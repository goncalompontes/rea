import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, onTestFinished } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ok } from "../domain/result.js";
import { silentLogger } from "../logger.js";
import type { GhidraInstallationHost } from "./GhidraInstallation.js";
import { GhidraProvider } from "./GhidraProvider.js";
import type { GhidraProviderClientFactory } from "./GhidraProviderClient.js";
import type { GhidraHeadlessLauncher } from "./GhidraLauncher.js";
import { GHIDRA_SESSION_CAPABILITIES } from "./GhidraSessionValues.js";
import type { GhidraProjectCacheIdentity } from "./projectCache/GhidraProjectCacheTypes.js";
import { ghidraProjectCacheKey } from "./projectCache/GhidraProjectCacheKey.js";
import { GhidraProjectStore } from "./projectCache/GhidraProjectStore.js";

const INSTALL = "/opt/ghidra_12.1.4_PUBLIC";

const installationHost = (): GhidraInstallationHost => ({
  platform: "linux",
  architecture: "x64",
  readText: () => "application.version=12.1.4\napplication.java.min=21\n",
  executable: () => true,
  probeJava: () => ({
    osArch: "amd64",
    osName: "Linux",
    version: "21.0.11",
    major: 21,
    home: "/usr/lib/jvm/jdk-21",
    bits: 64,
    runtime: "jdk",
    vmName: "OpenJDK 64-Bit Server VM",
  }),
});

const target = (sha256 = "a".repeat(64)): BinaryTarget => ({
  path: "/tmp/fixture",
  sha256,
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
});

const sessionInfo = () => ({
  name: "REA Ghidra bridge" as const,
  run_id: "11111111-1111-4111-8111-111111111111",
  profile_digest: "a".repeat(64),
  provider: { id: "ghidra" as const, version: "12.1.4" },
  read_only: false as const,
  analysis_complete: true,
  analysis_timed_out: false,
  capabilities: [...GHIDRA_SESSION_CAPABILITIES],
  target: {
    name: "fixture",
    language_id: "x86:LE:64:default",
    compiler_spec_id: "gcc",
    image_base: "0x1000",
    default_address_space: "ram",
    sha256: "a".repeat(64),
  },
});

const provider = (
  environment: Record<string, string>,
  clientFactory?: GhidraProviderClientFactory,
): GhidraProvider => {
  const config = parseConfig({ GHIDRA_INSTALL_DIR: INSTALL, ...environment });
  if (!config.ok) throw config.error;
  return new GhidraProvider(
    config.value,
    silentLogger,
    {},
    installationHost(),
    clientFactory,
  );
};

/** A fake client that records the launcher the provider handed it. */
const capturingFactory = (launchers: GhidraHeadlessLauncher[]) => {
  const factory: GhidraProviderClientFactory = (options) => {
    launchers.push(options.launcher as GhidraHeadlessLauncher);
    return {
      start: () => Promise.resolve(ok(sessionInfo())),
      callTool: () => Promise.resolve(ok(null)),
      close: () => Promise.resolve(ok(null)),
    };
  };
  return factory;
};

const temporaryCacheRoot = async (): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), "rea-project-cache-"));
  onTestFinished(() => rm(root, { recursive: true, force: true }));
  return root;
};

const commitProfile = (
  resolved: Awaited<ReturnType<GhidraProvider["resolveAnalysisProfile"]>>,
) => {
  if (!resolved.ok || resolved.value.profile === null)
    throw new Error("expected a bound Ghidra profile");
  return resolved.value.profile;
};

const projectCacheOf = (
  profile: ReturnType<typeof commitProfile>,
): { key: string; import_profile_digest: string } => {
  const value = profile.parameters.project_cache;
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error("expected a project_cache commitment");
  const record = value as Record<string, unknown>;
  if (
    typeof record.key !== "string" ||
    typeof record.import_profile_digest !== "string"
  )
    throw new Error("invalid project_cache commitment");
  return {
    key: record.key,
    import_profile_digest: record.import_profile_digest,
  };
};

describe("Ghidra project cache integration", () => {
  it("keeps the ephemeral profile and launcher when the cache is off", async () => {
    const launchers: GhidraHeadlessLauncher[] = [];
    const ghidra = provider({}, capturingFactory(launchers));
    const profile = commitProfile(
      await ghidra.resolveAnalysisProfile(target()),
    );
    expect(profile.parameters.import_mode).toBe("ephemeral-source-immutable");
    expect(profile.parameters.project_cache).toBeUndefined();
    const client = ghidra.createClient(target(), profile);
    expect((await client.execute("health", {})).ok).toBe(true);
    expect(launchers[0]?.options.saveImportedProject).toBeUndefined();
    expect(launchers[0]?.options.existingProject).toBeUndefined();
    await client.close();
  });

  it("reserves a save on a miss and reuses the same identity on a hit", async () => {
    const root = await temporaryCacheRoot();
    const environment = {
      REA_GHIDRA_PROJECT_CACHE: "on",
      REA_GHIDRA_PROJECT_CACHE_DIR: root,
    };
    const launchers: GhidraHeadlessLauncher[] = [];
    const ghidra = provider(environment, capturingFactory(launchers));
    const subject = target();

    // Miss: managed identity, no import-mode provenance, launcher saves.
    const missResolved = await ghidra.resolveAnalysisProfile(subject);
    const missProfile = commitProfile(missResolved);
    const missCommitment = projectCacheOf(missProfile);
    expect(missProfile.parameters.import_mode).toBeUndefined();
    const missClient = ghidra.createClient(subject, missProfile);
    expect((await missClient.execute("health", {})).ok).toBe(true);
    expect(launchers[0]?.options.saveImportedProject).toBe(true);
    expect(launchers[0]?.options.existingProject).toBeUndefined();
    await missClient.close();

    // Populate the entry the miss reserved, as a completed import would.
    const identity: GhidraProjectCacheIdentity = {
      providerId: "ghidra",
      providerVersion: "12.1.4",
      jvmVmName: "OpenJDK 64-Bit Server VM",
      platform: "linux",
      targetSha256: subject.sha256,
      importProfileDigest: missCommitment.import_profile_digest,
    };
    expect(ghidraProjectCacheKey(identity)).toBe(missCommitment.key);
    const store = new GhidraProjectStore({ root, maxBytes: 1_000_000 });
    const source = await mkdtemp(join(tmpdir(), "rea-project-source-"));
    onTestFinished(() => rm(source, { recursive: true, force: true }));
    await mkdir(join(source, "rea-project.rep", "idata"), { recursive: true });
    await writeFile(join(source, "rea-project.gpr"), "");
    await writeFile(
      join(source, "rea-project.rep", "idata", "db.gbf"),
      "program",
    );
    const reservation = await store.prepare({ identity, mode: "on" });
    if (!reservation.ok || reservation.value === null)
      throw new Error("expected a reservation");
    const published = await store.publish({
      reservation: reservation.value,
      identity,
      target: {
        sha256: subject.sha256,
        kind: "executable",
        format: "elf",
        architecture: "x86_64",
        executable_role: null,
      },
      sourceProjectDirectory: source,
      programName: "fixture",
      programSha256: subject.sha256,
      producer: { reaVersion: "6.4.0", runId: "run-1" },
    });
    expect(published.ok && published.value.published).toBe(true);

    // Hit: the same identity, and the launcher opens the stored project.
    const hitLaunchers: GhidraHeadlessLauncher[] = [];
    const hitProvider = provider(environment, capturingFactory(hitLaunchers));
    const hitProfile = commitProfile(
      await hitProvider.resolveAnalysisProfile(subject),
    );
    expect(hitProfile.digest).toBe(missProfile.digest);
    expect(projectCacheOf(hitProfile)).toEqual(missCommitment);
    const hitClient = hitProvider.createClient(subject, hitProfile);
    expect((await hitClient.execute("health", {})).ok).toBe(true);
    expect(hitLaunchers[0]?.options.existingProject).toEqual({
      projectPath: join(root, missCommitment.key),
      programName: "fixture",
    });
    expect(hitLaunchers[0]?.options.saveImportedProject).toBeUndefined();
    await hitClient.close();
  });
});
