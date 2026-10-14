import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { randomUUID } from "node:crypto";

import { ghidraProjectCacheKey } from "./GhidraProjectCacheKey.js";
import {
  GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  type GhidraProjectCacheIdentity,
} from "./GhidraProjectCacheTypes.js";
import {
  serializeGhidraProjectManifest,
  type GhidraProjectManifest,
} from "./GhidraProjectManifest.js";
import {
  GhidraProjectStore,
  type GhidraProjectPublishInput,
} from "./GhidraProjectStore.js";

const identity = (): GhidraProjectCacheIdentity => ({
  providerId: "ghidra",
  providerVersion: "12.1.4",
  jvmVmName: "OpenJDK 64-Bit Server VM",
  platform: "linux",
  targetSha256: "a".repeat(64),
  importProfileDigest: "b".repeat(64),
});

const target = {
  sha256: "a".repeat(64),
  kind: "executable",
  format: "pe",
  architecture: "x86_64",
  executable_role: "shared-library",
} as const;

let root: string;
let source: string;

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "rea-ghidra-cache-"));
  source = await mkdtemp(join(tmpdir(), "rea-ghidra-runtime-"));
  await mkdir(join(source, "rea-project.rep", "idata"), { recursive: true });
  await writeFile(join(source, "rea-project.gpr"), "");
  await writeFile(
    join(source, "rea-project.rep", "idata", "db.gbf"),
    Buffer.from("analyzed-program-bytes"),
  );
});

afterEach(async () => {
  await Promise.all([
    rm(root, { recursive: true, force: true }),
    rm(source, { recursive: true, force: true }),
  ]);
});

const publishable = (
  store: GhidraProjectStore,
  reservation: Awaited<ReturnType<GhidraProjectStore["prepare"]>>,
): GhidraProjectPublishInput => {
  if (
    !reservation.ok ||
    reservation.value === null ||
    !reservation.value.stagingPath
  )
    throw new Error("expected a populate-capable reservation");
  return {
    reservation: reservation.value,
    identity: identity(),
    target,
    sourceProjectDirectory: source,
    programName: "target-abc123.dll",
    programSha256: "c".repeat(64),
    producer: { reaVersion: "6.4.0", runId: "run-1" },
  };
};

describe("GhidraProjectStore", () => {
  it("is disabled when the mode is off", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    expect(await store.prepare({ identity: identity(), mode: "off" })).toEqual({
      ok: true,
      value: null,
    });
  });

  it("publishes a miss and serves a later hit with the stored program identity", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.hit === false).toBe(true);
    const published = await store.publish(publishable(store, miss));
    expect(published.ok && published.value.published).toBe(true);

    const key = ghidraProjectCacheKey(identity());
    const manifest = JSON.parse(
      await readFile(join(root, key, "manifest.json"), "utf8"),
    ) as GhidraProjectManifest;
    expect(manifest.program_name).toBe("target-abc123.dll");
    expect(manifest.program_sha256).toBe("c".repeat(64));
    expect(manifest.project_files).toHaveLength(2);
    expect(
      manifest.project_files.some((file) =>
        file.path.endsWith("rea-project.rep/idata/db.gbf"),
      ),
    ).toBe(true);
    expect(manifest.size_bytes).toBeGreaterThan(0);

    const hit = await store.prepare({ identity: identity(), mode: "on" });
    expect(hit.ok).toBe(true);
    if (!hit.ok || hit.value === null) throw new Error("expected a hit");
    expect(hit.value.hit).toBe(true);
    expect(hit.value.programName).toBe("target-abc123.dll");
    expect(hit.value.stagingPath).toBeUndefined();
  });

  it("reserves no staging slot in read mode", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const miss = await store.prepare({ identity: identity(), mode: "read" });
    expect(miss.ok).toBe(true);
    if (!miss.ok || miss.value === null)
      throw new Error("expected a reservation");
    expect(miss.value.hit).toBe(false);
    expect(miss.value.stagingPath).toBeUndefined();
  });

  it("discards an entry that is not an expanded project and reports it", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key), { recursive: true });
    await writeFile(join(root, key, "stray.txt"), "not a project");
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.invalidEntry?.reason).toBe("layout");
    expect(miss.ok && miss.value?.hit === false).toBe(true);
  });

  it("discards an entry whose manifest key does not match and reports it", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key, "rea-project.rep"), { recursive: true });
    await writeFile(join(root, key, "rea-project.gpr"), "");
    await writeFile(
      join(root, key, "manifest.json"),
      serializeGhidraProjectManifest(manifestWithKey("9".repeat(64))),
    );
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    expect(miss.ok && miss.value?.invalidEntry?.reason).toBe("identity");
  });

  it("does not overwrite an existing entry when another publisher won", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const key = ghidraProjectCacheKey(identity());
    await mkdir(join(root, key), { recursive: true });
    const stagingPath = join(root, "staging", randomUUID());
    await mkdir(stagingPath, { recursive: true });
    const result = await store.publish({
      reservation: { key, hit: false, entryPath: join(root, key), stagingPath },
      identity: identity(),
      target,
      sourceProjectDirectory: source,
      programName: "target-abc123.dll",
      programSha256: "c".repeat(64),
      producer: { reaVersion: "6.4.0", runId: "run-1" },
    });
    expect(result.ok && result.value.published).toBe(false);
    await expect(stat(stagingPath)).rejects.toThrow();
  });
});

describe("GhidraProjectStore maintenance", () => {
  it("removes a stored entry by key", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    const published = await store.publish(publishable(store, miss));
    expect(published.ok && published.value.published).toBe(true);
    const key = ghidraProjectCacheKey(identity());
    const removed = await store.remove(key);
    expect(removed.ok && removed.value).toBe(true);
    expect(await store.list()).toHaveLength(0);
    const again = await store.remove(key);
    expect(again.ok && again.value).toBe(false);
    expect((await store.remove("not-a-key")).ok).toBe(false);
  });

  it("verifies a clean entry and detects a tampered one", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    await store.publish(publishable(store, miss));
    const key = ghidraProjectCacheKey(identity());
    expect(await store.verify()).toEqual([{ key, ok: true, issues: [] }]);
    await writeFile(
      join(root, key, "rea-project.rep", "idata", "db.gbf"),
      "tampered",
    );
    const [row] = await store.verify();
    expect(row?.ok).toBe(false);
    expect(row?.issues.join(" ")).toMatch(/digest/u);
  });

  it("abandons a reserved staging slot", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const miss = await store.prepare({ identity: identity(), mode: "on" });
    if (!miss.ok || miss.value === null || !miss.value.stagingPath)
      throw new Error("expected a staging slot");
    const stagingPath = miss.value.stagingPath;
    await mkdir(stagingPath, { recursive: true });
    await store.abandon(miss.value);
    await expect(stat(stagingPath)).rejects.toThrow();
  });

  it("prunes the oldest entries to satisfy a smaller ceiling", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const older = { ...identity(), targetSha256: "1".repeat(64) };
    const newer = { ...identity(), targetSha256: "2".repeat(64) };
    for (const [id, now] of [
      [older, "2020-01-01T00:00:00.000Z"],
      [newer, "2021-01-01T00:00:00.000Z"],
    ] as const) {
      const reservation = await store.prepare({ identity: id, mode: "on" });
      if (!reservation.ok || reservation.value === null)
        throw new Error("expected a reservation");
      const published = await store.publish({
        ...publishable(store, reservation),
        identity: id,
        now,
      });
      expect(published.ok).toBe(true);
    }
    expect(await store.list()).toHaveLength(2);

    const [firstSize] = (await store.list()).map((entry) => entry.size_bytes);
    const smaller = new GhidraProjectStore({ root, maxBytes: firstSize ?? 1 });
    const pruned = await smaller.prune();
    expect(pruned.removed).toEqual([ghidraProjectCacheKey(older)]);
    const remaining = await smaller.list();
    expect(remaining.map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(newer),
    ]);
  });

  it("prunes entries older than the configured age", async () => {
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const dayMs = 86_400_000;
    const now = Date.now();
    const older = { ...identity(), targetSha256: "3".repeat(64) };
    const newer = { ...identity(), targetSha256: "4".repeat(64) };
    for (const [id, at] of [
      [older, new Date(now - 40 * dayMs).toISOString()],
      [newer, new Date(now - 1 * dayMs).toISOString()],
    ] as const) {
      const reservation = await store.prepare({ identity: id, mode: "on" });
      if (!reservation.ok || reservation.value === null)
        throw new Error("expected a reservation");
      const published = await store.publish({
        ...publishable(store, reservation),
        identity: id,
        now: at,
      });
      expect(published.ok).toBe(true);
    }
    const aged = new GhidraProjectStore({
      root,
      maxBytes: 1_000_000,
      maxAgeDays: 30,
    });
    const pruned = await aged.prune();
    expect(pruned.removed).toEqual([ghidraProjectCacheKey(older)]);
    expect((await aged.list()).map((entry) => entry.key)).toEqual([
      ghidraProjectCacheKey(newer),
    ]);
  });
});

const manifestWithKey = (key: string): GhidraProjectManifest => ({
  schema_version: GHIDRA_PROJECT_CACHE_SCHEMA_VERSION,
  key,
  provider: { id: "ghidra", version: "12.1.4" },
  jvm: { vm_name: "OpenJDK 64-Bit Server VM" },
  platform: "linux",
  target,
  import_profile_digest: "b".repeat(64),
  program_name: "target-abc123.dll",
  program_sha256: "c".repeat(64),
  project_files: [
    { path: "rea-project.rep/db.gbf", bytes: 1, sha256: "d".repeat(64) },
  ],
  project_digest: "e".repeat(64),
  created_at: "2026-01-01T00:00:00.000Z",
  last_used_at: "2026-01-01T00:00:00.000Z",
  size_bytes: 1,
  producer: { rea_version: "6.4.0", run_id: "run-1" },
});
