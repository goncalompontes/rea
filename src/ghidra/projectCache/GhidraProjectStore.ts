import { randomUUID } from "node:crypto";
import {
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

import { err, ok, type Result } from "../../domain/result.js";
import type { GhidraProjectCacheMode } from "../../config/ghidraProjectCache.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  GHIDRA_PROJECT_LOCK_DIRECTORY,
  GHIDRA_PROJECT_MANIFEST_FILE,
  GHIDRA_PROJECT_STAGING_DIRECTORY,
  GhidraProjectCacheError,
  type GhidraProjectCacheIdentity,
} from "./GhidraProjectCacheTypes.js";
import { ghidraProjectCacheKey } from "./GhidraProjectCacheKey.js";
import {
  admitGhidraProjectDirectory,
  copyGhidraProjectDirectory,
  digestGhidraProjectDirectory,
} from "./GhidraProjectLayout.js";
import {
  parseGhidraProjectManifest,
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
  type GhidraProjectManifestTarget,
} from "./GhidraProjectManifest.js";

const KEY_PATTERN = /^[a-f0-9]{64}$/u;
// A publisher that died mid-analysis can leave a lock behind. Steal one only
// after this age, and only once; a live publisher is not preempted.
const LOCK_STALE_MS = 10 * 60 * 1000;

/** A resolved cache lookup or a reserved staging slot for a fresh import. */
export interface GhidraProjectReservation {
  readonly key: string;
  readonly hit: boolean;
  readonly entryPath: string;
  /** Present only when the caller may populate the cache. */
  readonly stagingPath?: string;
  /** Present on a hit: the stored program name and its recorded digest. */
  readonly programName?: string;
  readonly programSha256?: string;
  /** An existing entry was present but rejected; a miss was served instead. */
  readonly invalidEntry?: GhidraProjectCacheError;
}

export interface GhidraProjectPublishInput {
  readonly reservation: GhidraProjectReservation;
  readonly identity: GhidraProjectCacheIdentity;
  readonly target: GhidraProjectManifestTarget;
  /** The runtime project directory holding `rea-project.gpr` and `.rep`. */
  readonly sourceProjectDirectory: string;
  readonly programName: string;
  readonly programSha256: string;
  readonly producer: { readonly reaVersion: string; readonly runId: string };
  /** Injectable clock for deterministic tests. */
  readonly now?: string;
  readonly signal?: AbortSignal;
}

export interface GhidraProjectStoreOptions {
  readonly root: string;
  readonly maxBytes: number;
  /** Discard entries older than this many days; unset applies no age limit. */
  readonly maxAgeDays?: number;
}

/** Owns the on-disk store of previously analyzed Ghidra projects. */
export class GhidraProjectStore {
  readonly #root: string;
  readonly #maxBytes: number;
  readonly #maxAgeDays: number | undefined;

  constructor(options: GhidraProjectStoreOptions) {
    this.#root = options.root;
    this.#maxBytes = options.maxBytes;
    this.#maxAgeDays = options.maxAgeDays;
  }

  get root(): string {
    return this.#root;
  }

  /**
   * Resolve a hit, or reserve a staging slot for a miss. Returns `null` when
   * the mode is `off`, so the caller keeps its ephemeral behaviour.
   */
  async prepare(input: {
    readonly identity: GhidraProjectCacheIdentity;
    readonly mode: GhidraProjectCacheMode;
    readonly signal?: AbortSignal;
  }): Promise<
    Result<GhidraProjectReservation | null, GhidraProjectCacheError>
  > {
    if (input.mode === "off") return ok(null);
    const key = ghidraProjectCacheKey(input.identity);
    const entryPath = this.#entryPath(key);
    try {
      await mkdir(this.#root, { recursive: true, mode: 0o700 });
      input.signal?.throwIfAborted();
      const existing = await lstat(entryPath).catch(() => undefined);
      if (existing === undefined)
        return ok(this.#miss(key, entryPath, input.mode));
      const admitted = await admitGhidraProjectDirectory(entryPath);
      if (!admitted.ok) {
        await this.#discard(entryPath);
        return ok({
          ...this.#miss(key, entryPath, input.mode),
          invalidEntry: admitted.error,
        });
      }
      const manifest = await this.#readManifest(entryPath);
      if (!manifest.ok || manifest.value.key !== key) {
        await this.#discard(entryPath);
        return ok({
          ...this.#miss(key, entryPath, input.mode),
          invalidEntry: manifest.ok
            ? new GhidraProjectCacheError(
                "identity",
                "Stored Ghidra project manifest key does not match its directory",
                entryPath,
              )
            : manifest.error,
        });
      }
      return ok({
        key,
        hit: true,
        entryPath,
        programName: manifest.value.program_name,
        programSha256: manifest.value.program_sha256,
      });
    } catch (cause: unknown) {
      if (input.signal?.aborted === true) throw cause;
      return err(
        this.#io("Ghidra project cache lookup failed", entryPath, cause),
      );
    }
  }

  /** Publish a freshly analyzed project after a clean, complete session. */
  async publish(
    input: GhidraProjectPublishInput,
  ): Promise<Result<{ readonly published: boolean }, GhidraProjectCacheError>> {
    const stagingPath = input.reservation.stagingPath;
    if (stagingPath === undefined)
      return err(
        new GhidraProjectCacheError(
          "disabled",
          "Ghidra project cache publish requires a reserved staging slot",
          input.reservation.entryPath,
        ),
      );
    try {
      return await this.#withLock(
        input.reservation.key,
        input.signal,
        async () => {
          const existing = await lstat(input.reservation.entryPath).catch(
            () => undefined,
          );
          if (existing !== undefined) {
            // A concurrent publisher won; discard this copy rather than overwrite.
            await this.#discard(stagingPath);
            return ok({ published: false });
          }
          await copyGhidraProjectDirectory(
            input.sourceProjectDirectory,
            stagingPath,
            input.signal,
          );
          const admitted = await admitGhidraProjectDirectory(stagingPath);
          if (!admitted.ok) {
            await this.#discard(stagingPath);
            return admitted;
          }
          const digest = await digestGhidraProjectDirectory(
            stagingPath,
            input.signal,
          );
          const now = input.now ?? new Date().toISOString();
          const manifest: GhidraProjectManifest = {
            schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
            key: input.reservation.key,
            provider: {
              id: input.identity.providerId,
              version: input.identity.providerVersion,
            },
            jvm: { vm_name: input.identity.jvmVmName },
            platform: input.identity.platform,
            target: input.target,
            import_profile_digest: input.identity.importProfileDigest,
            program_name: input.programName,
            program_sha256: input.programSha256,
            project_files: [...digest.files],
            project_digest: digest.projectDigest,
            created_at: now,
            last_used_at: now,
            size_bytes: digest.sizeBytes,
            producer: {
              rea_version: input.producer.reaVersion,
              run_id: input.producer.runId,
            },
          };
          await writeFile(
            join(stagingPath, GHIDRA_PROJECT_MANIFEST_FILE),
            serializeGhidraProjectManifest(manifest),
            { flag: "wx", mode: 0o600 },
          );
          await rename(stagingPath, input.reservation.entryPath);
          await this.prune(input.signal);
          return ok({ published: true });
        },
      );
    } catch (cause: unknown) {
      await this.#discard(stagingPath);
      if (input.signal?.aborted === true) throw cause;
      if (cause instanceof GhidraProjectCacheError) return err(cause);
      return err(
        this.#io(
          "Ghidra project cache publish failed",
          input.reservation.entryPath,
          cause,
        ),
      );
    }
  }

  /** Discard a reserved staging slot without publishing (failure/cancel). */
  async abandon(reservation: GhidraProjectReservation): Promise<void> {
    if (reservation.stagingPath !== undefined)
      await this.#discard(reservation.stagingPath);
  }

  /** Remove one stored entry by key. Returns whether an entry was removed. */
  async remove(key: string): Promise<Result<boolean, GhidraProjectCacheError>> {
    if (!KEY_PATTERN.test(key))
      return err(
        new GhidraProjectCacheError(
          "identity",
          "A Ghidra project cache key is a lowercase sha256 digest",
          key,
        ),
      );
    const entryPath = this.#entryPath(key);
    try {
      const existing = await lstat(entryPath).catch(() => undefined);
      if (existing === undefined) return ok(false);
      await this.#discard(entryPath);
      return ok(true);
    } catch (cause: unknown) {
      return err(
        this.#io("Ghidra project cache removal failed", entryPath, cause),
      );
    }
  }

  /**
   * Re-validate every stored entry: layout admission, manifest identity, and the
   * full per-file digest recorded at publish. Returns one row per entry; a row
   * with issues is corrupt and may be removed with {@link remove}.
   */
  async verify(signal?: AbortSignal): Promise<
    readonly {
      readonly key: string;
      readonly ok: boolean;
      readonly issues: readonly string[];
    }[]
  > {
    const results: {
      readonly key: string;
      readonly ok: boolean;
      readonly issues: readonly string[];
    }[] = [];
    for (const key of await this.#entryKeys(signal))
      results.push(await this.#verifyEntry(key, signal));
    return results;
  }

  async #verifyEntry(
    key: string,
    signal?: AbortSignal,
  ): Promise<{
    readonly key: string;
    readonly ok: boolean;
    readonly issues: readonly string[];
  }> {
    const entryPath = this.#entryPath(key);
    const issues: string[] = [];
    const admitted = await admitGhidraProjectDirectory(entryPath);
    if (!admitted.ok) issues.push(admitted.error.message);
    const manifest = await this.#readManifest(entryPath);
    if (!manifest.ok) {
      issues.push(manifest.error.message);
    } else if (manifest.value.key !== key) {
      issues.push("Manifest key does not match its directory");
    } else if (admitted.ok) {
      issues.push(
        ...(await this.#digestIssues(entryPath, manifest.value, signal)),
      );
    }
    return { key, ok: issues.length === 0, issues };
  }

  async #digestIssues(
    entryPath: string,
    manifest: GhidraProjectManifest,
    signal?: AbortSignal,
  ): Promise<readonly string[]> {
    try {
      const digest = await digestGhidraProjectDirectory(entryPath, signal);
      const issues: string[] = [];
      if (digest.projectDigest !== manifest.project_digest)
        issues.push("Stored project digest does not match its manifest");
      if (digest.sizeBytes !== manifest.size_bytes)
        issues.push("Stored project size does not match its manifest");
      return issues;
    } catch (cause: unknown) {
      return [cause instanceof Error ? cause.message : String(cause)];
    }
  }

  /** Every valid stored manifest, for discovery and pruning. */
  async list(signal?: AbortSignal): Promise<readonly GhidraProjectManifest[]> {
    const manifests: GhidraProjectManifest[] = [];
    for (const key of await this.#entryKeys(signal)) {
      const manifest = await this.#readManifest(this.#entryPath(key));
      if (manifest.ok) manifests.push(manifest.value);
    }
    return manifests;
  }

  /** Remove stale entries, then the oldest until the store fits its ceiling. */
  async prune(
    signal?: AbortSignal,
  ): Promise<{ readonly removed: readonly string[]; readonly bytes: number }> {
    const manifests = [...(await this.list(signal))];
    const removed: string[] = [];
    let freed = 0;
    const drop = async (manifest: GhidraProjectManifest): Promise<void> => {
      await this.#discard(this.#entryPath(manifest.key));
      removed.push(manifest.key);
      freed += manifest.size_bytes;
    };
    const nowMs = Date.now();
    const fresh: GhidraProjectManifest[] = [];
    for (const manifest of manifests) {
      const ageMs = nowMs - Date.parse(manifest.last_used_at);
      if (
        this.#maxAgeDays !== undefined &&
        Number.isFinite(ageMs) &&
        ageMs > this.#maxAgeDays * 86_400_000
      )
        await drop(manifest);
      else fresh.push(manifest);
    }
    let total = fresh.reduce((sum, entry) => sum + entry.size_bytes, 0);
    if (total <= this.#maxBytes) return { removed, bytes: freed };
    fresh.sort((left, right) =>
      left.last_used_at < right.last_used_at
        ? -1
        : left.last_used_at > right.last_used_at
          ? 1
          : left.key < right.key
            ? -1
            : 1,
    );
    for (const manifest of fresh) {
      if (total <= this.#maxBytes) break;
      await drop(manifest);
      total -= manifest.size_bytes;
    }
    return { removed, bytes: freed };
  }

  #miss(
    key: string,
    entryPath: string,
    mode: GhidraProjectCacheMode,
  ): GhidraProjectReservation {
    return {
      key,
      hit: false,
      entryPath,
      ...(mode === "on" ? { stagingPath: this.#stagingPath() } : {}),
    };
  }

  #entryPath(key: string): string {
    return join(this.#root, key);
  }

  #stagingPath(): string {
    return join(this.#root, GHIDRA_PROJECT_STAGING_DIRECTORY, randomUUID());
  }

  #lockPath(key: string): string {
    return join(this.#root, GHIDRA_PROJECT_LOCK_DIRECTORY, `${key}.lock`);
  }

  async #readManifest(
    entryPath: string,
  ): Promise<Result<GhidraProjectManifest, GhidraProjectCacheError>> {
    let raw: string;
    try {
      raw = await readFile(
        join(entryPath, GHIDRA_PROJECT_MANIFEST_FILE),
        "utf8",
      );
    } catch (cause: unknown) {
      return err(
        this.#io(
          "Stored Ghidra project manifest is unreadable",
          entryPath,
          cause,
        ),
      );
    }
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch (cause: unknown) {
      return err(
        new GhidraProjectCacheError(
          "manifest",
          "Stored Ghidra project manifest is not valid JSON",
          entryPath,
          { cause },
        ),
      );
    }
    return parseGhidraProjectManifest(value, entryPath);
  }

  async #entryKeys(signal?: AbortSignal): Promise<readonly string[]> {
    const entries = await readdir(this.#root, { withFileTypes: true }).catch(
      () => [],
    );
    signal?.throwIfAborted();
    return entries
      .filter((entry) => entry.isDirectory() && KEY_PATTERN.test(entry.name))
      .map((entry) => entry.name)
      .sort();
  }

  async #withLock<Value>(
    key: string,
    signal: AbortSignal | undefined,
    body: () => Promise<Value>,
  ): Promise<Value> {
    const lockPath = this.#lockPath(key);
    await mkdir(join(this.#root, GHIDRA_PROJECT_LOCK_DIRECTORY), {
      recursive: true,
      mode: 0o700,
    });
    await this.#acquireLock(lockPath);
    try {
      signal?.throwIfAborted();
      return await body();
    } finally {
      await rm(lockPath, { recursive: true, force: true });
    }
  }

  async #acquireLock(lockPath: string): Promise<void> {
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        const handle = await open(lockPath, "wx", 0o600);
        await handle.close();
        return;
      } catch (cause: unknown) {
        if (!isAlreadyExists(cause)) throw cause;
        if (attempt === 1) throw cause;
        const age = await lstat(lockPath).then(
          (stats) => Date.now() - stats.mtimeMs,
          () => Number.POSITIVE_INFINITY,
        );
        if (age < LOCK_STALE_MS)
          throw new GhidraProjectCacheError(
            "busy",
            "Another session is publishing this Ghidra project",
            lockPath,
            { cause },
          );
        await rm(lockPath, { recursive: true, force: true });
      }
    }
  }

  async #discard(path: string): Promise<void> {
    await rm(path, { recursive: true, force: true });
  }

  #io(message: string, path: string, cause: unknown): GhidraProjectCacheError {
    return new GhidraProjectCacheError("io", message, path, { cause });
  }
}

const isAlreadyExists = (cause: unknown): boolean =>
  cause instanceof Error &&
  "code" in cause &&
  (cause as { readonly code?: string }).code === "EEXIST";
