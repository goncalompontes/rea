import type { InvestigationRecordPort } from "../investigation/InvestigationRecordPort.js";
import type { ExecutableFormatHint } from "../../domain/dosCom.js";
import type {
  BinaryArchitecture,
  BinaryTarget,
} from "../../domain/binaryTargetTypes.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { AnalysisSnapshot } from "../../domain/analysisSnapshot.js";
import type { AnalysisProfileCommitment } from "../../domain/analysisProfile.js";
import type { AnalysisProviderSelector } from "../../contracts/providerSelection.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";
import type { EvidenceIntegrityError } from "../../domain/evidenceErrors.js";
import type { AnalysisSnapshotLoader } from "./BinarySessionOpen.js";
import type { ResolvedSessionOpen } from "./BinarySessionOpen.js";
import type { WorkflowSnapshotRecordInput } from "./BinarySessionRecords.js";

import type {
  AnalysisExecution,
  AnalysisOperation,
  AnalysisOperationPort,
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";

/** Receipt for an atomically saved snapshot followed by provider cleanup. */
export interface SavedAnalysisSnapshot {
  readonly path: string;
  readonly bytes: number;
  /** Eligible primitive query bindings. */
  readonly primitive_entries: number;
  /** Eligible composed workflow bindings, separate from primitive queries. */
  readonly workflow_entries: number;
  /** All retained Evidence records, including observations without a replay binding. */
  readonly evidence_records: number;
}

/** Target lifecycle used by CLI and MCP without exposing a concrete provider. */
export interface BinarySessionPort
  extends AnalysisOperationPort, InvestigationRecordPort {
  /** Execute only against a positively ready, already-created provider client. */
  executeIfProviderReady(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: Pick<ExecutionOptions, "signal" | "selectorOrigin" | "targetId">,
  ): Promise<Result<AnalysisExecution, AnalysisError> | undefined>;
  /** Hold one target binding through a complete composed operation. */
  withAdmittedAnalysis<Value>(
    operationName: string,
    signal: AbortSignal | undefined,
    operation: (analysis: AnalysisOperationPort) => Promise<Value>,
    targetId?: string,
    waitMs?: number,
  ): Promise<Result<Value, AnalysisError>>;
  /** Serialize an external mutation and retire any active target afterward. */
  withAdmittedExternalMutation<Value>(
    _path: string | undefined,
    signal: AbortSignal | undefined,
    operation: () => Promise<Result<Value, AnalysisError>>,
    retirementFailure: (
      value: Result<Value, AnalysisError>,
      error: AnalysisError,
    ) => AnalysisError,
    operationName?: string,
    cleanupRecovery?: (
      failure: AnalysisError | undefined,
    ) => Promise<Result<null, AnalysisError>>,
  ): Promise<Result<Result<Value, AnalysisError>, AnalysisError>>;
  /** Resolve a target and provider profile without creating a provider client. */
  previewTarget(
    target: BinaryTarget,
    options?: {
      readonly signal?: AbortSignal;
      readonly targetKind?: BinaryTarget["kind"];
      readonly formatHint?: ExecutableFormatHint;
      readonly architecture?: BinaryArchitecture;
      readonly entryPoint?: string;
      readonly snapshot?: AnalysisSnapshot;
      readonly providerId?: AnalysisProviderSelector;
    },
  ): Promise<Result<ResolvedSessionOpen, AnalysisError>>;
  /** Open a previewed target without repeating parsing or profile discovery. */
  openResolvedTarget(
    resolved: Pick<ResolvedSessionOpen, "target" | "route">,
    options?: {
      readonly signal?: AbortSignal;
      readonly snapshot?: AnalysisSnapshot;
      readonly keepOthersOpen?: boolean;
      readonly analysisMode?: "foreground" | "background" | "auto";
      readonly autoBackgroundAfterMs?: number;
    },
  ): Promise<Result<BinaryTarget, AnalysisError>>;
  open(
    path: string,
    options?: {
      readonly signal?: AbortSignal;
      readonly targetKind?: BinaryTarget["kind"];
      readonly formatHint?: ExecutableFormatHint;
      readonly architecture?: BinaryArchitecture;
      readonly entryPoint?: string;
      readonly snapshot?: AnalysisSnapshot;
      readonly loadSnapshot?: AnalysisSnapshotLoader;
      readonly providerId?: AnalysisProviderSelector;
      /** Keep other open targets instead of replacing them (default false). */
      readonly keepOthersOpen?: boolean;
      /** Foreground (default), background, or experimental auto promotion. */
      readonly analysisMode?: "foreground" | "background" | "auto";
      /** Auto mode promotion threshold; defaults to the registry setting. */
      readonly autoBackgroundAfterMs?: number;
    },
  ): Promise<Result<BinaryTarget, AnalysisError>>;
  close(
    options?: Pick<ExecutionOptions, "progress"> & {
      readonly retainProviderDocuments?: boolean;
      readonly targetId?: string;
    },
  ): Promise<Result<null, AnalysisError>>;
  /** Close every open target; used by server shutdown rather than a tool call. */
  closeAll?(
    options?: Pick<ExecutionOptions, "progress"> & {
      readonly retainProviderDocuments?: boolean;
    },
  ): Promise<Result<null, AnalysisError>>;
  /** Save a snapshot and close while excluding later provider requests. */
  closeWithSnapshot(
    path: string,
    overwrite: boolean,
    options?: Pick<ExecutionOptions, "progress"> & {
      readonly targetId?: string;
    },
  ): Promise<Result<SavedAnalysisSnapshot, AnalysisError>>;
  status(options?: {
    readonly signal?: AbortSignal;
    readonly targetId?: string;
    readonly waitMs?: number;
  }): Promise<JsonValue>;
  /** Opaque handle of the current target when the adapter exposes handles. */
  currentTargetId?(): string | undefined;
  /** Every open target handle, when the adapter supports concurrent targets. */
  targets?(): readonly {
    readonly target_id: string;
    readonly target: BinaryTarget;
  }[];
  /** Current background-analysis state for one target, when tracked. */
  analysisState?(targetId?: string): JsonValue | undefined;
  activeTarget(targetId?: string): BinaryTarget | undefined;
  exportAnalysisSnapshot(): Result<AnalysisSnapshot, AnalysisError>;
  writeAnalysisSnapshot(
    snapshot: AnalysisSnapshot,
    path: string,
    overwrite: boolean,
  ): Promise<
    Result<{ readonly path: string; readonly bytes: number }, AnalysisError>
  >;
  closeWriteResources(): Promise<Result<null, AnalysisError>>;
  importAnalysisSnapshot(
    snapshot: AnalysisSnapshot,
  ): Result<number, AnalysisError>;
  providerIdentity(
    operation?: AnalysisOperation,
    targetId?: string,
  ): ProviderIdentity;
  analysisProfile(
    operation?: AnalysisOperation,
    targetId?: string,
  ): AnalysisProfileCommitment | undefined;
  allowsSnapshotReplay(
    operation: AnalysisOperation,
    targetId?: string,
  ): boolean;
  /** Invalidate cached Evidence before an external command may mutate the target. */
  invalidateSnapshotForExternalMutation(targetId?: string): void;
  recordWorkflowSnapshot(
    input: WorkflowSnapshotRecordInput,
  ): Result<null, EvidenceIntegrityError>;
  onAvailabilityChanged?(listener: () => void | Promise<void>): () => void;
  onAnalysisSnapshotChanged?(listener: () => void | Promise<void>): () => void;
}
