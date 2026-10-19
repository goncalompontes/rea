import { randomUUID } from "node:crypto";

import type { AnalysisProfileCommitment } from "../../domain/analysisProfile.js";
import type { AnalysisSnapshot } from "../../domain/analysisSnapshot.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisInProgressError,
  AnalysisResourceConstraintError,
  AnalysisTargetNotOpenError,
} from "../../domain/analysisErrorCore.js";
import type { BinaryTarget } from "../../domain/binaryTargetTypes.js";
import type { Evidence } from "../../domain/evidence.js";
import type { EvidenceBundle } from "../../domain/evidenceBundle.js";
import type { EvidenceIntegrityError } from "../../domain/evidenceErrors.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { err, ok, type Result } from "../../domain/result.js";
import type {
  ResolvedSessionOpen,
} from "./BinarySessionOpen.js";
import { BinarySession } from "./BinarySession.js";
import { parseBinaryTarget } from "../BinaryTargetResolver.js";
import type {
  BinarySessionPort,
  SavedAnalysisSnapshot,
} from "./BinarySessionPort.js";
import { binaryTargetSummary } from "./BinaryTargetSummary.js";
import type { SessionProviderRouter } from "./SessionProviderRouter.js";
import { InvestigationRecords } from "../investigation/InvestigationRecords.js";
import type {
  AnalysisExecution,
  AnalysisOperation,
  AnalysisOperationPort,
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type {
  UnknownPage,
  UnknownQuery,
} from "../investigation/InvestigationRecordPort.js";
import type {
  RecordUnknownInput,
  ResidualUnknown,
  UnknownStatus,
  UpdateUnknownInput,
} from "../../domain/residualUnknown.js";
import type { UnknownRegistryError } from "../../domain/unknownRegistryError.js";
import type { WorkflowSnapshotRecordInput } from "./BinarySessionRecords.js";

/** Bounded target and analysis concurrency supplied by the composition root. */
export interface BinaryTargetLimits {
  readonly maxOpenTargets: number;
  readonly maxConcurrentAnalyses: number;
  readonly autoBackgroundAfterMs: number;
}

const DEFAULT_LIMITS: BinaryTargetLimits = {
  maxOpenTargets: 4,
  maxConcurrentAnalyses: 2,
  autoBackgroundAfterMs: 120_000,
};

const DEFAULT_WAIT_MS = 180_000;
const MAX_WAIT_MS = 290_000;

interface TargetSlot {
  readonly id: string;
  readonly session: BinarySession;
}

type AnalysisJobState = "starting" | "ready" | "failed" | "cancelled";

type OpenOptions = NonNullable<Parameters<BinarySessionPort["open"]>[1]>;
type OpenResolvedOptions = NonNullable<
  Parameters<BinarySessionPort["openResolvedTarget"]>[1]
>;

interface AnalysisJob {
  readonly slot: TargetSlot;
  readonly target: BinaryTarget;
  readonly controller: AbortController;
  readonly startedAt: number;
  readonly mode: "background" | "auto";
  state: AnalysisJobState;
  error: AnalysisError | undefined;
  readonly promise: Promise<void>;
}

/**
 * Own several independent target sessions behind one `BinarySessionPort`.
 *
 * Each slot keeps the single-target lifecycle lock, provider client, snapshot
 * cache, and cancellation scope it had when `BinarySession` owned the whole
 * server. The registry routes each call to one slot and bounds how many slots
 * and simultaneous starts may exist. A call without `target_id` addresses the
 * current slot, so single-target clients keep the replacement behaviour.
 */
export class BinaryTargetRegistry implements BinarySessionPort {
  readonly #router: SessionProviderRouter;
  readonly #records: InvestigationRecords;
  readonly #limits: BinaryTargetLimits;
  readonly #slots = new Map<string, TargetSlot>();
  readonly #jobs = new Map<string, AnalysisJob>();
  readonly #availabilityListeners = new Set<() => void | Promise<void>>();
  readonly #snapshotListeners = new Set<() => void | Promise<void>>();
  #primary: TargetSlot;
  #currentId: string;
  #activeStarts = 0;
  readonly #startQueue: Array<() => void> = [];

  constructor(
    router: SessionProviderRouter,
    records: InvestigationRecords = new InvestigationRecords(),
    limits: Partial<BinaryTargetLimits> = {},
  ) {
    this.#router = router;
    this.#records = records;
    this.#limits = {
      maxOpenTargets: Math.max(
        1,
        limits.maxOpenTargets ?? DEFAULT_LIMITS.maxOpenTargets,
      ),
      maxConcurrentAnalyses: Math.max(
        1,
        limits.maxConcurrentAnalyses ?? DEFAULT_LIMITS.maxConcurrentAnalyses,
      ),
      autoBackgroundAfterMs: Math.max(
        1,
        limits.autoBackgroundAfterMs ?? DEFAULT_LIMITS.autoBackgroundAfterMs,
      ),
    };
    this.#primary = this.#createSlot();
    this.#currentId = this.#primary.id;
  }

  /** Currently open target handles in deterministic creation order. */
  targets(): readonly { readonly target_id: string; readonly target: BinaryTarget }[] {
    return [...this.#slots.values()].flatMap((slot) => {
      const target = slot.session.activeTarget() ?? this.#jobs.get(slot.id)?.target;
      return target === undefined
        ? []
        : [{ target_id: slot.id, target }];
    });
  }

  /** Identifier of the target addressed when a call omits target_id. */
  currentTargetId(): string | undefined {
    return this.#targetForSlot(this.#slotById(this.#currentId)) === undefined
      ? undefined
      : this.#currentId;
  }

  /** Current background-analysis state for one target, when tracked. */
  analysisState(targetId?: string): JsonValue | undefined {
    const slot = this.#resolveSlotResult(targetId);
    if (!slot.ok) return undefined;
    const job = this.#jobForSlot(slot.value);
    if (job === undefined) return undefined;
    return {
      state: job.state,
      mode: job.mode,
      started_at: new Date(job.startedAt).toISOString(),
      elapsed_ms: Date.now() - job.startedAt,
      ...(job.error === undefined
        ? {}
        : {
            error: {
              code: job.error._tag,
              message: job.error.message,
            },
          }),
    };
  }

  async open(
    path: string,
    options: Parameters<BinarySessionPort["open"]>[1] = {},
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    if ((options.analysisMode ?? "foreground") !== "foreground")
      return this.#openAsJob(path, options);
    if (options.keepOthersOpen !== true)
      return this.#openReplacing(path, options);
    const existing = this.#slotForPath(path);
    if (existing !== undefined) return this.#openInSlot(existing, path, options);
    return this.#openInNewSlot(path, options);
  }

  async openResolvedTarget(
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options: Parameters<BinarySessionPort["openResolvedTarget"]>[1] = {},
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    if ((options.analysisMode ?? "foreground") !== "foreground")
      return this.#openResolvedAsJob(resolved, options);
    if (options.keepOthersOpen !== true)
      return this.#openResolvedReplacing(resolved, options);
    const existing = this.#slotForPath(resolved.target.path);
    if (existing !== undefined)
      return this.#openResolvedInSlot(existing, resolved, options);
    return this.#openResolvedInNewSlot(resolved, options);
  }

  async #openReplacing(
    path: string,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    this.#cancelJob(this.#primary);
    const closed = await this.#closeSlotsExcept(this.#primary);
    if (!closed.ok) return closed;
    return this.#openInSlot(this.#primary, path, options);
  }

  async #openResolvedReplacing(
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options: OpenResolvedOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    this.#cancelJob(this.#primary);
    const closed = await this.#closeSlotsExcept(this.#primary);
    if (!closed.ok) return closed;
    return this.#openResolvedInSlot(this.#primary, resolved, options);
  }

  async #openAsJob(
    path: string,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const existing = this.#slotForPath(path);
    if (existing !== undefined) {
      const job = this.#jobs.get(existing.id);
      if (job !== undefined) return this.#jobOpenResult(job, options);
      const active = existing.session.activeTarget();
      if (active !== undefined) {
        this.#currentId = existing.id;
        return ok(active);
      }
    }
    if (isAborted(options.signal))
      return err(new AnalysisCancelledError("open_binary"));
    const parsed = await parseBinaryTarget(path, {
      ...(options.targetKind === undefined
        ? {}
        : { targetKind: options.targetKind }),
      ...(options.formatHint === undefined
        ? {}
        : { formatHint: options.formatHint }),
      ...(options.architecture === undefined
        ? {}
        : { architecture: options.architecture }),
      ...(options.entryPoint === undefined
        ? {}
        : { entryPoint: options.entryPoint }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (!parsed.ok) return parsed;
    const slot = await this.#slotForJob(options);
    if (!slot.ok) return slot;
    return this.#startJob(
      slot.value,
      parsed.value,
      "background",
      (signal) => slot.value.session.open(path, { ...options, signal }),
      options,
    );
  }

  async #openResolvedAsJob(
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options: OpenResolvedOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const existing = this.#slotForPath(resolved.target.path);
    if (existing !== undefined) {
      const job = this.#jobs.get(existing.id);
      if (job !== undefined) return this.#jobOpenResult(job, options);
      const active = existing.session.activeTarget();
      if (active !== undefined) {
        this.#currentId = existing.id;
        return ok(active);
      }
    }
    if (isAborted(options.signal))
      return err(new AnalysisCancelledError("open_binary"));
    const slot = await this.#slotForJob(options);
    if (!slot.ok) return slot;
    return this.#startJob(
      slot.value,
      resolved.target,
      "background",
      (signal) =>
        slot.value.session.openResolvedTarget(resolved, { ...options, signal }),
      options,
    );
  }

  async #slotForJob(
    options: OpenOptions,
  ): Promise<Result<TargetSlot, AnalysisError>> {
    if (options.keepOthersOpen === true) {
      const capacity = this.#checkOpenCapacity("open_binary");
      if (capacity !== undefined) return capacity;
      return ok(this.#createSlot());
    }
    const closed = await this.#closeSlotsExcept(this.#primary);
    if (!closed.ok) return closed;
    const previousJob = this.#jobs.get(this.#primary.id);
    previousJob?.controller.abort();
    this.#jobs.delete(this.#primary.id);
    return ok(this.#primary);
  }

  #startJob(
    slot: TargetSlot,
    target: BinaryTarget,
    requestedMode: "background" | "auto",
    start: (signal: AbortSignal) => Promise<Result<BinaryTarget, AnalysisError>>,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const mode =
      options.analysisMode === "auto" ? ("auto" as const) : requestedMode;
    const controller = new AbortController();
    const startedAt = Date.now();
    let job!: AnalysisJob;
    const promise = start(controller.signal).then(
      (result) => {
        if (controller.signal.aborted) {
          job.state = "cancelled";
          job.error = result.ok
            ? new AnalysisCancelledError("open_binary")
            : result.error;
          return;
        }
        if (result.ok) {
          job.state = "ready";
          return;
        }
        job.state = "failed";
        job.error = result.error;
      },
      (cause: unknown) => {
        job.state = controller.signal.aborted ? "cancelled" : "failed";
        job.error =
          cause instanceof AnalysisError
            ? cause
            : new AnalysisCancelledError("open_binary");
      },
    );
    job = {
      slot,
      target,
      controller,
      startedAt,
      mode,
      state: "starting",
      error: undefined,
      promise,
    };
    this.#slots.set(slot.id, slot);
    this.#jobs.set(slot.id, job);
    this.#currentId = slot.id;
    if (mode === "background") return Promise.resolve(ok(target));
    const threshold = Math.max(
      1,
      options.autoBackgroundAfterMs ?? this.#limits.autoBackgroundAfterMs,
    );
    return this.#waitForAutoJob(job, threshold, options.signal).then(
      (outcome) => {
        if (outcome === "ready") return ok(target);
        if (outcome === "failed")
          return err(job.error ?? new AnalysisCancelledError("open_binary"));
        if (outcome === "aborted")
          return err(new AnalysisCancelledError("open_binary"));
        return ok(target);
      },
    );
  }

  async #waitForAutoJob(
    job: AnalysisJob,
    thresholdMs: number,
    signal: AbortSignal | undefined,
  ): Promise<"ready" | "failed" | "aborted" | "timeout"> {
    if (isAborted(signal)) return "aborted";
    const outcome = await new Promise<
      "ready" | "failed" | "aborted" | "timeout"
    >((resolve) => {
      let settled = false;
      const finish = (
        value: "ready" | "failed" | "aborted" | "timeout",
      ): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        resolve(value);
      };
      const timer = setTimeout(() => finish("timeout"), thresholdMs);
      timer.unref?.();
      const onAbort = (): void => finish("aborted");
      signal?.addEventListener("abort", onAbort, { once: true });
      void job.promise.then(() =>
        finish(job.state === "ready" ? "ready" : "failed"),
      );
    });
    return outcome;
  }

  #jobOpenResult(
    job: AnalysisJob,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    if (job.state === "ready") return Promise.resolve(ok(job.target));
    if (job.state === "starting" && job.mode === "background")
      return Promise.resolve(ok(job.target));
    if (job.state === "failed")
      return Promise.resolve(
        err(job.error ?? new AnalysisCancelledError("open_binary")),
      );
    if (job.state === "cancelled")
      return Promise.resolve(err(new AnalysisCancelledError("open_binary")));
    return this.#waitForAutoJob(
      job,
      Math.max(1, options.autoBackgroundAfterMs ?? this.#limits.autoBackgroundAfterMs),
      options.signal,
    ).then((outcome) =>
      outcome === "failed"
        ? err(job.error ?? new AnalysisCancelledError("open_binary"))
        : ok(job.target),
    );
  }

  async #openInNewSlot(
    path: string,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const capacity = this.#checkOpenCapacity("open_binary");
    if (capacity !== undefined) return capacity;
    return this.#openInSlot(this.#createSlot(), path, options);
  }

  async #openResolvedInNewSlot(
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options: OpenResolvedOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const capacity = this.#checkOpenCapacity("open_binary");
    if (capacity !== undefined) return capacity;
    return this.#openResolvedInSlot(this.#createSlot(), resolved, options);
  }

  async #openInSlot(
    slot: TargetSlot,
    path: string,
    options: OpenOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const job = this.#jobs.get(slot.id);
    if (job !== undefined) {
      await job.promise;
      return job.state === "ready"
        ? ok(job.target)
        : err(job.error ?? new AnalysisCancelledError("open_binary"));
    }
    const permit = await this.#acquireStartPermit("open_binary", options?.signal);
    if (!permit.ok) return err(permit.error);
    try {
      const opened = await slot.session.open(path, options);
      return this.#finishOpen(slot, opened);
    } finally {
      this.#releaseStartPermit();
    }
  }

  async #openResolvedInSlot(
    slot: TargetSlot,
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options: OpenResolvedOptions,
  ): Promise<Result<BinaryTarget, AnalysisError>> {
    const job = this.#jobs.get(slot.id);
    if (job !== undefined) {
      await job.promise;
      return job.state === "ready"
        ? ok(job.target)
        : err(job.error ?? new AnalysisCancelledError("open_binary"));
    }
    const permit = await this.#acquireStartPermit("open_binary", options?.signal);
    if (!permit.ok) return err(permit.error);
    try {
      const opened = await slot.session.openResolvedTarget(resolved, options);
      return this.#finishOpen(slot, opened);
    } finally {
      this.#releaseStartPermit();
    }
  }

  #finishOpen(
    slot: TargetSlot,
    opened: Result<BinaryTarget, AnalysisError>,
  ): Result<BinaryTarget, AnalysisError> {
    if (!opened.ok) {
      if (slot !== this.#primary && slot.session.activeTarget() === undefined)
        this.#removeSlot(slot);
      return opened;
    }
    this.#slots.set(slot.id, slot);
    this.#currentId = slot.id;
    return opened;
  }

  previewTarget(
    target: BinaryTarget,
    options: Parameters<BinarySessionPort["previewTarget"]>[1] = {},
  ): Promise<Result<ResolvedSessionOpen, AnalysisError>> {
    return this.#currentSlot().session.previewTarget(target, options);
  }

  close(
    options: Parameters<BinarySessionPort["close"]>[0] = {},
  ): Promise<Result<null, AnalysisError>> {
    return this.#closeSlotFor(options, (slot, behavior) =>
      slot.session.closeAsSlot(options, behavior),
    );
  }

  /** Close every slot; incomplete cleanup stays visible on the first failure. */
  async closeAll(
    options: Parameters<NonNullable<BinarySessionPort["closeAll"]>>[0] = {},
  ): Promise<Result<null, AnalysisError>> {
    let failure: AnalysisError | undefined;
    for (const slot of [...this.#slots.values()]) {
      const closed = await (async () => {
        this.#jobs.get(slot.id)?.controller.abort();
        return slot.session.closeAsSlot(options, {
          clearRecords: false,
          closeOwnedProviderResources: false,
        });
      })();
      if (!closed.ok) failure ??= closed.error;
      this.#retireSlot(slot);
    }
    const final = await this.#primary.session.closeAsSlot(options, {
      clearRecords: true,
      closeOwnedProviderResources: true,
    });
    if (!final.ok) failure ??= final.error;
    return failure === undefined ? ok(null) : err(failure);
  }

  closeWithSnapshot(
    path: string,
    overwrite: boolean,
    options: Parameters<BinarySessionPort["closeWithSnapshot"]>[2] = {},
  ): Promise<Result<SavedAnalysisSnapshot, AnalysisError>> {
    return this.#closeSlotFor(options, (slot, behavior) =>
      slot.session.closeWithSnapshotAsSlot(path, overwrite, options, behavior),
    );
  }

  async #closeSlotFor<Value>(
    options: { readonly targetId?: string; readonly signal?: AbortSignal },
    close: (
      slot: TargetSlot,
      behavior: {
        readonly clearRecords: boolean;
        readonly closeOwnedProviderResources: boolean;
      },
    ) => Promise<Result<Value, AnalysisError>>,
  ): Promise<Result<Value, AnalysisError>> {
    const slot = this.#resolveSlot(options.targetId, "close_binary");
    if (!slot.ok) return slot;
    const last = this.#openSlotCount() <= 1;
    this.#jobs.get(slot.value.id)?.controller.abort();
    const closed = await close(slot.value, {
      clearRecords: last,
      closeOwnedProviderResources: last,
    });
    if (closed.ok) this.#retireSlot(slot.value);
    return closed;
  }

  async status(
    options: Parameters<BinarySessionPort["status"]>[0] = {},
  ): Promise<JsonValue> {
    const slot = this.#resolveSlot(options?.targetId, "binary_session");
    if (!slot.ok) throw slot.error;
    const job = this.#jobForSlot(slot.value);
    if (job?.state === "starting")
      await this.#waitForAnalysis(slot.value, "binary_session", {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        ...(options.waitMs === undefined ? {} : { waitMs: options.waitMs }),
      });
    const base = await slot.value.session.status(options);
    if (typeof base !== "object" || base === null || Array.isArray(base))
      return base;
    const analysis =
      job === undefined
        ? undefined
        : {
            state: job.state,
            mode: job.mode,
            started_at: new Date(job.startedAt).toISOString(),
            elapsed_ms: Date.now() - job.startedAt,
            ...(job.error === undefined
              ? {}
              : {
                  error: {
                    code: job.error._tag,
                    message: job.error.message,
                  },
                }),
          };
    const targetFields =
      job === undefined || base.open === true || job.state === "failed" || job.state === "cancelled"
        ? {}
        : {
            open: true as const,
            ...binaryTargetSummary(job.target),
          };
    return {
      ...base,
      ...targetFields,
      target_id: slot.value.id,
      open_target_ids: this.targets().map(({ target_id }) => target_id),
      ...(analysis === undefined ? {} : { analysis }),
    };
  }

  execute(
    name: Parameters<AnalysisOperationPort["execute"]>[0],
    arguments_: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const slot = this.#resolveSlot(options?.targetId, name);
    if (!slot.ok) return Promise.resolve(slot);
    return this.#waitForAnalysis(slot.value, name, options).then((ready) =>
      ready.ok
        ? slot.value.session.execute(name, arguments_, options)
        : ready,
    );
  }

  executeIfProviderReady(
    name: Parameters<BinarySessionPort["executeIfProviderReady"]>[0],
    arguments_: Readonly<Record<string, JsonValue>>,
    options?: Pick<ExecutionOptions, "signal" | "selectorOrigin" | "targetId">,
  ): Promise<Result<AnalysisExecution, AnalysisError> | undefined> {
    const slot = this.#resolveSlot(options?.targetId, name);
    if (!slot.ok) return Promise.resolve(slot);
    const job = this.#jobForSlot(slot.value);
    if (job !== undefined && job.state !== "ready") return Promise.resolve(undefined);
    return slot.value.session.executeIfProviderReady(name, arguments_, options);
  }

  withAdmittedAnalysis<Value>(
    operationName: string,
    signal: AbortSignal | undefined,
    operation: (analysis: AnalysisOperationPort) => Promise<Value>,
    targetId?: string,
    waitMs?: number,
  ): Promise<Result<Value, AnalysisError>> {
    const slot = this.#resolveSlot(targetId, operationName);
    if (!slot.ok) return Promise.resolve(slot);
    return this.#waitForAnalysis(slot.value, operationName, {
      ...(signal === undefined ? {} : { signal }),
      ...(waitMs === undefined ? {} : { waitMs }),
    }).then((ready) =>
      ready.ok
        ? slot.value.session.withAdmittedAnalysis(
            operationName,
            signal,
            operation,
          )
        : ready,
    );
  }

  withAdmittedExternalMutation<Value>(
    path: string | undefined,
    signal: AbortSignal | undefined,
    operation: () => Promise<Result<Value, AnalysisError>>,
    retirementFailure: (
      value: Result<Value, AnalysisError>,
      error: AnalysisError,
    ) => AnalysisError,
    operationName = "execute_rizin_command",
    cleanupRecovery?: (
      failure: AnalysisError | undefined,
    ) => Promise<Result<null, AnalysisError>>,
  ): Promise<Result<Result<Value, AnalysisError>, AnalysisError>> {
    const slot = this.#currentSlot();
    return slot.session.withAdmittedExternalMutation(
      path,
      signal,
      operation,
      retirementFailure,
      operationName,
      cleanupRecovery,
    );
  }

  activeTarget(targetId?: string): BinaryTarget | undefined {
    const slot = this.#resolveSlotResult(targetId);
    return slot.ok ? this.#targetForSlot(slot.value) : undefined;
  }

  providerIdentity(
    operation?: AnalysisOperation,
    targetId?: string,
  ): ProviderIdentity {
    return this.#currentSlot(targetId).session.providerIdentity(operation);
  }

  analysisProfile(
    operation?: AnalysisOperation,
    targetId?: string,
  ): AnalysisProfileCommitment | undefined {
    return this.#currentSlot(targetId).session.analysisProfile(operation);
  }

  allowsSnapshotReplay(
    operation: AnalysisOperation,
    targetId?: string,
  ): boolean {
    return this.#currentSlot(targetId).session.allowsSnapshotReplay(operation);
  }

  invalidateSnapshotForExternalMutation(targetId?: string): void {
    this.#currentSlot(targetId).session.invalidateSnapshotForExternalMutation();
  }

  exportAnalysisSnapshot(
    targetId?: string,
  ): Result<AnalysisSnapshot, AnalysisError> {
    return this.#currentSlot(targetId).session.exportAnalysisSnapshot();
  }

  importAnalysisSnapshot(
    snapshot: AnalysisSnapshot,
    targetId?: string,
  ): Result<number, AnalysisError> {
    return this.#currentSlot(targetId).session.importAnalysisSnapshot(snapshot);
  }

  recordWorkflowSnapshot(
    input: WorkflowSnapshotRecordInput,
    targetId?: string,
  ): Result<null, EvidenceIntegrityError> {
    return this.#currentSlot(targetId).session.recordWorkflowSnapshot(input);
  }

  onAvailabilityChanged(listener: () => void | Promise<void>): () => void {
    this.#availabilityListeners.add(listener);
    return () => this.#availabilityListeners.delete(listener);
  }

  onAnalysisSnapshotChanged(listener: () => void | Promise<void>): () => void {
    this.#snapshotListeners.add(listener);
    return () => this.#snapshotListeners.delete(listener);
  }

  // Investigation records stay session-wide. The current slot owns the target
  // binding used to attach new unknowns and the only active snapshot cache.
  recordEvidence(
    evidence: Evidence,
  ): ReturnType<BinarySessionPort["recordEvidence"]> {
    return this.#currentSlot().session.recordEvidence(evidence);
  }

  hasEvidence(evidenceId: string): boolean {
    return this.#currentSlot().session.hasEvidence(evidenceId);
  }

  evidenceById(evidenceId: string): Evidence | undefined {
    return this.#currentSlot().session.evidenceById(evidenceId);
  }

  evidenceForAnalysis(evidenceId: string): Evidence | undefined {
    return this.#currentSlot().session.evidenceForAnalysis(evidenceId);
  }

  exportEvidenceBundle(): EvidenceBundle {
    return this.#currentSlot().session.exportEvidenceBundle();
  }

  evidenceBundleForSerialization(): EvidenceBundle {
    return this.#currentSlot().session.evidenceBundleForSerialization();
  }

  writeAnalysisSnapshot(
    snapshot: AnalysisSnapshot,
    path: string,
    overwrite: boolean,
  ): ReturnType<BinarySession["writeAnalysisSnapshot"]> {
    return this.#currentSlot().session.writeAnalysisSnapshot(
      snapshot,
      path,
      overwrite,
    );
  }

  closeWriteResources(): Promise<Result<null, AnalysisError>> {
    return this.#currentSlot().session.closeWriteResources();
  }

  importEvidenceBundle(
    bundle: unknown,
  ): ReturnType<BinarySession["importEvidenceBundle"]> {
    return this.#currentSlot().session.importEvidenceBundle(bundle);
  }

  recordUnknown(
    input: RecordUnknownInput,
  ): Result<ResidualUnknown, AnalysisError> {
    return this.#currentSlot().session.recordUnknown(input);
  }

  recordEvidenceWithUnknown(
    evidence: Evidence,
    input: RecordUnknownInput,
  ): Result<ResidualUnknown | null, AnalysisError> {
    return this.#currentSlot().session.recordEvidenceWithUnknown(
      evidence,
      input,
    );
  }

  updateUnknown(
    input: UpdateUnknownInput,
  ): Result<ResidualUnknown, AnalysisError> {
    return this.#currentSlot().session.updateUnknown(input);
  }

  listUnknowns(
    filters: {
      readonly status?: UnknownStatus;
      readonly severity?: ResidualUnknown["severity"];
      readonly domain?: string;
    } = {},
  ): ResidualUnknown[] {
    return this.#currentSlot().session.listUnknowns(filters);
  }

  listUnknownsPage(query: UnknownQuery = {}): UnknownPage {
    return this.#currentSlot().session.listUnknownsPage(query);
  }

  verifyUnknownResolution(
    unknownId: string,
  ): Result<
    {
      readonly valid: boolean;
      readonly truthVerified: boolean;
      readonly unknown: ResidualUnknown;
    },
    UnknownRegistryError
  > {
    return this.#currentSlot().session.verifyUnknownResolution(unknownId);
  }

  #createSlot(): TargetSlot {
    const session = new BinarySession(this.#router, this.#records);
    const slot: TargetSlot = { id: randomUUID(), session };
    session.onAvailabilityChanged(() => this.#emitAvailabilityChanged());
    session.onAnalysisSnapshotChanged(() => this.#emitSnapshotChanged());
    return slot;
  }

  #removeSlot(slot: TargetSlot): void {
    this.#jobs.get(slot.id)?.controller.abort();
    this.#jobs.delete(slot.id);
    this.#slots.delete(slot.id);
    if (this.#currentId === slot.id) this.#currentId = this.#primary.id;
  }

  #retireSlot(slot: TargetSlot): void {
    this.#jobs.get(slot.id)?.controller.abort();
    this.#jobs.delete(slot.id);
    if (slot === this.#primary) {
      this.#slots.delete(slot.id);
      const replacement = this.#firstOpenSlot();
      if (replacement !== undefined) {
        this.#currentId = replacement.id;
        return;
      }
      this.#currentId = this.#primary.id;
      return;
    }
    this.#slots.delete(slot.id);
    if (this.#currentId === slot.id) {
      const replacement = this.#firstOpenSlot();
      this.#currentId = replacement?.id ?? this.#primary.id;
    }
  }

  #firstOpenSlot(): TargetSlot | undefined {
    return [...this.#slots.values()].find(
      (slot) => this.#targetForSlot(slot) !== undefined,
    );
  }

  #openSlotCount(): number {
    let count = 0;
    for (const slot of this.#slots.values())
      if (this.#targetForSlot(slot) !== undefined) count += 1;
    return count;
  }

  #slotById(targetId: string): TargetSlot | undefined {
    if (this.#primary.id === targetId) return this.#primary;
    return this.#slots.get(targetId);
  }

  #targetForSlot(slot: TargetSlot | undefined): BinaryTarget | undefined {
    if (slot === undefined) return undefined;
    return slot.session.activeTarget() ?? this.#jobs.get(slot.id)?.target;
  }

  #jobForSlot(slot: TargetSlot): AnalysisJob | undefined {
    return this.#jobs.get(slot.id);
  }

  #cancelJob(slot: TargetSlot): void {
    const job = this.#jobs.get(slot.id);
    if (job === undefined) return;
    job.controller.abort();
    this.#jobs.delete(slot.id);
  }

  async #waitForAnalysis(
    slot: TargetSlot,
    operation: string,
    options: Pick<ExecutionOptions, "signal" | "waitMs"> | undefined,
  ): Promise<Result<undefined, AnalysisError>> {
    const job = this.#jobForSlot(slot);
    if (job === undefined || job.state === "ready") return ok(undefined);
    if (job.state === "failed")
      return err(job.error ?? new AnalysisCancelledError(operation));
    if (job.state === "cancelled")
      return err(new AnalysisCancelledError(operation));
    if (isAborted(options?.signal))
      return err(new AnalysisCancelledError(operation));
    const waitMs = Math.min(
      MAX_WAIT_MS,
      Math.max(1, options?.waitMs ?? DEFAULT_WAIT_MS),
    );
    const outcome = await new Promise<"ready" | "failed" | "aborted" | "timeout">(
      (resolve) => {
        let settled = false;
        const finish = (
          value: "ready" | "failed" | "aborted" | "timeout",
        ): void => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          options?.signal?.removeEventListener("abort", onAbort);
          resolve(value);
        };
        const timer = setTimeout(() => finish("timeout"), waitMs);
        timer.unref?.();
        const onAbort = (): void => finish("aborted");
        options?.signal?.addEventListener("abort", onAbort, { once: true });
        void job.promise.then(() =>
          finish(job.state === "ready" ? "ready" : "failed"),
        );
      },
    );
    if (outcome === "ready") return ok(undefined);
    if (outcome === "aborted")
      return err(new AnalysisCancelledError(operation));
    if (outcome === "failed")
      return err(job.error ?? new AnalysisCancelledError(operation));
    return err(
      new AnalysisInProgressError(
        operation,
        slot.id,
        Date.now() - job.startedAt,
        undefined,
      ),
    );
  }

  #slotForPath(path: string): TargetSlot | undefined {
    return [...this.#slots.values()].find((slot) => {
      const target = this.#targetForSlot(slot);
      return target?.path === path || target?.sourcePath === path;
    });
  }

  #currentSlot(targetId?: string): TargetSlot {
    if (targetId !== undefined) {
      const slot = this.#slotById(targetId);
      if (slot !== undefined && this.#targetForSlot(slot) !== undefined)
        return slot;
      return this.#primary;
    }
    return this.#slotById(this.#currentId) ?? this.#primary;
  }

  #resolveSlot(
    targetId: string | undefined,
    operation: string,
  ): Result<TargetSlot, AnalysisError> {
    if (targetId === undefined) return ok(this.#slotById(this.#currentId) ?? this.#primary);
    const slot = this.#slotById(targetId);
    if (slot !== undefined && this.#targetForSlot(slot) !== undefined)
      return ok(slot);
    return err(
      new AnalysisTargetNotOpenError(
        operation,
        targetId,
        [...this.#slots.values()]
          .filter((candidate) => this.#targetForSlot(candidate) !== undefined)
          .map(({ id }) => id),
      ),
    );
  }

  #resolveSlotResult(
    targetId: string | undefined,
  ): Result<TargetSlot, AnalysisError> {
    return this.#resolveSlot(targetId, "target lookup");
  }

  #checkOpenCapacity(
    operation: string,
  ): Result<never, AnalysisError> | undefined {
    if (this.#openSlotCount() < this.#limits.maxOpenTargets) return undefined;
    return err(
      new AnalysisResourceConstraintError(
        operation,
        "capacity",
        `Opening another target would exceed REA_MAX_OPEN_TARGETS=${this.#limits.maxOpenTargets}. Close an open target or raise the limit.`,
        { max_open_targets: this.#limits.maxOpenTargets },
        {
          remediationAction:
            "Close an open target with close_binary or raise REA_MAX_OPEN_TARGETS.",
        },
      ),
    );
  }

  async #closeSlotsExcept(
    keep: TargetSlot,
  ): Promise<Result<null, AnalysisError>> {
    for (const slot of [...this.#slots.values()]) {
      if (slot === keep) continue;
      this.#jobs.get(slot.id)?.controller.abort();
      const closed = await slot.session.closeAsSlot(
        {},
        { clearRecords: false, closeOwnedProviderResources: false },
      );
      if (!closed.ok) return closed;
      this.#retireSlot(slot);
    }
    return ok(null);
  }

  async #acquireStartPermit(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<undefined, AnalysisError>> {
    if (signal?.aborted === true)
      return err(new AnalysisCancelledError(operation));
    if (this.#activeStarts < this.#limits.maxConcurrentAnalyses) {
      this.#activeStarts += 1;
      return ok(undefined);
    }
    return new Promise((resolve) => {
      const grant = (): void => {
        this.#activeStarts += 1;
        resolve(ok(undefined));
      };
      if (signal === undefined) {
        this.#startQueue.push(grant);
        return;
      }
      const queued = (): void => {
        const index = this.#startQueue.indexOf(onGrant);
        if (index >= 0) this.#startQueue.splice(index, 1);
        resolve(err(new AnalysisCancelledError(operation)));
      };
      const onGrant = (): void => {
        signal.removeEventListener("abort", queued);
        grant();
      };
      signal.addEventListener("abort", queued, { once: true });
      this.#startQueue.push(onGrant);
    });
  }

  #releaseStartPermit(): void {
    this.#activeStarts = Math.max(0, this.#activeStarts - 1);
    const next = this.#startQueue.shift();
    next?.();
  }

  #emitAvailabilityChanged(): void {
    for (const listener of this.#availabilityListeners) {
      try {
        const notification = listener();
        if (notification !== undefined) void notification.catch(() => undefined);
      } catch (cause: unknown) {
        void cause;
      }
    }
  }

  #emitSnapshotChanged(): void {
    for (const listener of this.#snapshotListeners) {
      try {
        const notification = listener();
        if (notification !== undefined) void notification.catch(() => undefined);
      } catch (cause: unknown) {
        void cause;
      }
    }
  }
}


const isAborted = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;
