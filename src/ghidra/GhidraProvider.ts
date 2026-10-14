import { randomUUID } from "node:crypto";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import type {
  AnalysisClient,
  AnalysisClientContext,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  AnalysisProviderReadinessSnapshot,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderIdentity,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import type { AppConfig } from "../config/types.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import {
  isMachOFormat,
  type BinaryTarget,
} from "../domain/binaryTargetTypes.js";
import {
  jsonObjectSchema,
  jsonValueSchema,
  type JsonValue,
} from "../domain/jsonValue.js";
import { err, ok } from "../domain/result.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { Logger } from "pino";
import { GhidraClient } from "./GhidraClient.js";
import type { GhidraProjectPersistence } from "./GhidraClientTypes.js";
import { GhidraProjectStore } from "./projectCache/GhidraProjectStore.js";
import type { GhidraProjectCacheIdentity } from "./projectCache/GhidraProjectCacheTypes.js";
import { ghidraProjectCacheCommitmentSchema } from "./projectCache/GhidraProjectCacheCommitment.js";
import type { GhidraProjectReservation } from "./projectCache/GhidraProjectStore.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import {
  ghidraInstallationDiagnostics,
  inspectGhidraInstallation,
  type GhidraInstallationHost,
  type GhidraInstallationInspection,
} from "./GhidraInstallation.js";
import {
  ghidraExistingProjectUnsupportedReason,
  resolveGhidraAnalysisProfile,
} from "./GhidraAnalysisProfile.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { resolveGhidraAnalysisSeeds } from "./GhidraAnalysisSeeds.js";
import {
  admitGhidraLanguageOverride,
  GhidraLanguageCatalogCleanupError,
  readGhidraLanguageCatalog,
} from "./GhidraLanguageCatalog.js";
import {
  ghidraProcessorUnsupportedReason,
  isGhidraPspTarget,
} from "./GhidraPspProfile.js";
import { resolveGhidraExtensions } from "./extensions/GhidraExtensions.js";
import {
  CAPABILITIES,
  windowsP0Capabilities,
  GHIDRA_PROVIDER_IDENTITY,
} from "./GhidraProviderCapabilities.js";
import {
  createGhidraProviderClient,
  type GhidraProviderClientFactory,
} from "./GhidraProviderClient.js";
import {
  inspectWindowsNativeReadiness,
  type WindowsNativeReadiness,
  windowsNativeCapabilities,
} from "../process/WindowsAuthority.js";

const SUPPORTED_ARCHITECTURES = new Set([
  "x86",
  "x86_64",
  "arm",
  "arm64",
  "mips",
  "6502",
  "riscv",
  "powerpc",
]);

/** Managed project-cache coordinates retained between profile and client creation. */
interface ManagedGhidraProject {
  readonly store: GhidraProjectStore;
  readonly identity: GhidraProjectCacheIdentity;
  readonly reservation: GhidraProjectReservation;
}

/** Ghidra candidate backed by an isolated ephemeral headless import. */
export class GhidraProvider implements AnalysisProviderCandidate {
  #installation: GhidraInstallationInspection | undefined;
  #store: GhidraProjectStore | undefined;
  /** Cache wiring keyed by the committed profile digest a client will receive. */
  readonly #managedProjects = new Map<string, ManagedGhidraProject>();
  private readonly environment: NodeJS.ProcessEnv;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv>,
    private readonly installationHost?: GhidraInstallationHost,
    private readonly clientFactory: GhidraProviderClientFactory = (options) =>
      new GhidraClient(options),
  ) {
    this.environment = snapshotEnvironment(
      environment,
      installationHost?.platform,
    );
  }

  identity(): ProviderIdentity {
    return GHIDRA_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return (this.installationHost?.platform ?? process.platform) === "win32"
      ? windowsP0Capabilities()
      : CAPABILITIES;
  }

  inspectAvailability(): ProviderAvailability {
    return this.inspectReadinessSnapshot().availability;
  }

  inspectReadinessSnapshot(): AnalysisProviderReadinessSnapshot {
    const installation = this.#inspectInstallation();
    const readiness =
      installation.platform === "win32"
        ? inspectWindowsNativeReadiness(installation.platform)
        : undefined;
    return {
      availability: this.#availability(installation, readiness),
      capabilities:
        readiness === undefined
          ? CAPABILITIES
          : windowsP0Capabilities(readiness),
    };
  }

  #availability(
    installation: GhidraInstallationInspection,
    readiness: WindowsNativeReadiness | undefined,
  ): ProviderAvailability {
    const diagnostics = ghidraInstallationDiagnostics(installation);
    if (installation.status === "available" && readiness?.available === false)
      return {
        status: "unavailable",
        code: readiness.code,
        reason: readiness.reason,
        diagnostics: {
          ...diagnostics,
          windows_security: jsonObjectSchema.parse(
            windowsNativeCapabilities(installation.platform, readiness),
          ),
          windows_native_failure: {
            stage: readiness.failureStage,
            remediation: readiness.remediation,
          },
        },
      };
    return installation.status === "available"
      ? {
          status: "available",
          code: null,
          reason: null,
          diagnostics,
        }
      : {
          status: "unavailable",
          code: installation.rejection.code,
          reason: installation.rejection.reason,
          diagnostics,
        };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const hostPlatform = this.installationHost?.platform ?? process.platform;
    const diagnostics = {
      host_platform: hostPlatform,
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.architecture ?? null,
      available_architectures:
        target.kind === "executable"
          ? [...target.availableArchitectures]
          : null,
      executable_role: target.executableRole ?? null,
      managed: target.managed ?? null,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Ghidra v1 imports executable targets, not ${target.kind} targets.`,
        diagnostics,
      };
    if (hostPlatform === "win32")
      return inspectWindowsP0TargetSupport(target, diagnostics);
    const mipsReason =
      isGhidraPspTarget(target) &&
      (hostPlatform !== "linux" ||
        (this.installationHost?.architecture ?? process.arch) !== "x64")
        ? "The initial PSP Allegrex profile is verified on Linux x64 only."
        : ghidraProcessorUnsupportedReason(target);
    if (mipsReason !== null)
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: mipsReason,
        diagnostics,
      };
    if (
      isMachOFormat(target.format) &&
      target.availableArchitectures.length > 1
    )
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 cannot enforce the selected architecture when importing a universal Mach-O; analyze a thinned Mach-O slice instead.",
        diagnostics,
      };
    if (!SUPPORTED_ARCHITECTURES.has(target.architecture))
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Ghidra v1 requires a supported x86, x86_64, arm, arm64, MIPS, RISC-V, or raw 6502 target profile.",
        diagnostics,
      };
    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics,
    };
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    const installation = this.#inspectInstallation();
    const resolved = await resolveGhidraAnalysisProfile(
      target,
      GHIDRA_PROVIDER_IDENTITY,
      installation,
      options?.signal,
      this.config.ghidraLanguageOverride,
      this.config.ghidraDisabledAnalyzers,
      this.config.ghidraExistingProject !== undefined,
    );
    if (!resolved.ok || resolved.value.profile === null) return resolved;
    const override = this.config.ghidraLanguageOverride;
    if (override !== undefined && installation.status === "available") {
      let catalog: Awaited<ReturnType<typeof readGhidraLanguageCatalog>>;
      try {
        catalog = await readGhidraLanguageCatalog(installation.installDir);
      } catch (cause: unknown) {
        if (cause instanceof GhidraLanguageCatalogCleanupError)
          return err(
            new ProviderCleanupError(
              "ghidra",
              cause.paths,
              {
                reason: cause.message,
                paths: [...cause.paths],
                close_failures: cause.causes.map(providerFailureText),
                ...(cause.readFailure === undefined
                  ? {}
                  : { read_failure: providerFailureText(cause.readFailure) }),
              },
              { operation: "resolve_analysis_profile", cause },
            ),
          );
        return err(
          new ProviderAdapterError("ghidra", "resolve_analysis_profile", {
            cause,
            diagnostics: {
              reason:
                "Could not read the installed Ghidra language definitions.",
            },
          }),
        );
      }
      const refused = admitGhidraLanguageOverride(
        override,
        catalog,
        installation.providerVersion,
      );
      if (refused !== null) return err(refused);
    }
    const extensions = await resolveGhidraExtensions(
      this.config,
      target,
      installation.platform,
      options?.signal,
    );
    if (!extensions.ok) return extensions;
    if (options?.signal?.aborted === true)
      return err(new AnalysisCancelledError("open_binary"));
    const seeds = await resolveGhidraAnalysisSeeds(this.config.ghidraSeedFile);
    if (!seeds.ok) return seeds;
    const existingProject = this.config.ghidraExistingProject;
    const intentProfile = createAnalysisProfile(
      resolved.value.profile.provider,
      {
        ...resolved.value.profile.parameters,
        ...(extensions.value.length === 0
          ? {}
          : { analysis_extensions: jsonValueSchema.parse(extensions.value) }),
        ...(seeds.value === undefined
          ? {}
          : { analysis_seeds: jsonValueSchema.parse(seeds.value) }),
      },
    );
    if (existingProject !== undefined)
      return ok({
        ...resolved.value,
        profile: createAnalysisProfile(resolved.value.profile.provider, {
          ...intentProfile.parameters,
          // A caller-selected project is not manifest-verified, so its state is
          // never treated as a reusable identity: each resolution gets its own
          // session id and snapshots stay session-local.
          existing_project: {
            program_name: existingProject.programName,
            session_id: randomUUID(),
          },
        }),
      });
    const managed = await this.#prepareManagedProject(
      target,
      installation,
      intentProfile,
      options?.signal,
    );
    if (managed !== undefined) {
      this.#managedProjects.set(managed.profile.digest, managed.persistence);
      return ok({ ...resolved.value, profile: managed.profile });
    }
    return ok({ ...resolved.value, profile: intentProfile });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    context?: AnalysisClientContext,
  ): AnalysisClient {
    const managed =
      profile === undefined
        ? undefined
        : this.#managedProjects.get(profile.digest);
    return createGhidraProviderClient({
      config: this.config,
      environment: this.environment,
      logger: this.logger,
      clientFactory: this.clientFactory,
      target,
      ...(profile === undefined ? {} : { profile }),
      ...(context === undefined ? {} : { context }),
      installation: this.#inspectInstallation(),
      ...(managed === undefined
        ? {}
        : {
            projectPersistence: this.#persistenceFor(target, managed, context),
          }),
    });
  }

  #inspectInstallation(): GhidraInstallationInspection {
    const options = {
      environment: this.environment,
      ...(this.config.ghidraInstallDir === undefined
        ? {}
        : { installDir: this.config.ghidraInstallDir }),
      ...(this.config.ghidraJavaHome === undefined
        ? {}
        : { javaHome: this.config.ghidraJavaHome }),
      ...(this.installationHost?.platform === undefined
        ? {}
        : { platform: this.installationHost.platform }),
      ...(this.installationHost?.architecture === undefined
        ? {}
        : { architecture: this.installationHost.architecture }),
    };
    this.#installation ??=
      this.installationHost === undefined
        ? inspectGhidraInstallation(options)
        : inspectGhidraInstallation(options, this.installationHost);
    return this.#installation;
  }

  #projectStore(): GhidraProjectStore | undefined {
    if (this.config.ghidraProjectCache.mode === "off") return undefined;
    this.#store ??= new GhidraProjectStore({
      root: this.config.ghidraProjectCache.directory,
      maxBytes: this.config.ghidraProjectCache.maxBytes,
      ...(this.config.ghidraProjectCache.maxAgeDays === undefined
        ? {}
        : { maxAgeDays: this.config.ghidraProjectCache.maxAgeDays }),
    });
    return this.#store;
  }

  /**
   * Resolve a managed stored project for this target, or reserve a staging slot
   * on a miss. Returns undefined (keeping the ephemeral profile) when the cache
   * is disabled, unsupported for the target, or unreadable.
   */
  async #prepareManagedProject(
    target: BinaryTarget,
    installation: GhidraInstallationInspection,
    intentProfile: AnalysisProfileCommitment,
    signal?: AbortSignal,
  ): Promise<
    | {
        readonly profile: AnalysisProfileCommitment;
        readonly persistence: ManagedGhidraProject;
      }
    | undefined
  > {
    const store = this.#projectStore();
    if (store === undefined || installation.status !== "available")
      return undefined;
    // A stored project opens with -process, which DOS, raw-binary and PSP
    // targets cannot select, so those lanes are never cached.
    if (ghidraExistingProjectUnsupportedReason(target) !== null)
      return undefined;
    const identity: GhidraProjectCacheIdentity = {
      providerId: GHIDRA_PROVIDER_IDENTITY.id,
      providerVersion: installation.providerVersion,
      jvmVmName: installation.javaVmName ?? "unknown",
      platform: installation.platform,
      targetSha256: target.sha256,
      importProfileDigest: intentProfile.digest,
    };
    let prepared;
    try {
      prepared = await store.prepare({
        identity,
        mode: this.config.ghidraProjectCache.mode,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch {
      return undefined;
    }
    if (!prepared.ok || prepared.value === null) return undefined;
    const parameters: Record<string, JsonValue> = {
      ...intentProfile.parameters,
    };
    // Identity is open-mode independent: import-mode provenance is dropped so a
    // miss and a hit commit the same profile for one target, which lets a
    // stored analysis snapshot replay in a later session.
    delete parameters.import_mode;
    const profile = createAnalysisProfile(intentProfile.provider, {
      ...parameters,
      project_cache: ghidraProjectCacheCommitmentSchema.parse({
        key: prepared.value.key,
        import_profile_digest: identity.importProfileDigest,
      }),
    });
    return {
      profile,
      persistence: { store, identity, reservation: prepared.value },
    };
  }

  #persistenceFor(
    target: BinaryTarget,
    managed: ManagedGhidraProject,
    context: AnalysisClientContext | undefined,
  ): GhidraProjectPersistence {
    const reuse = managed.reservation.hit;
    return {
      store: managed.store,
      reservation: managed.reservation,
      identity: managed.identity,
      target: {
        sha256: target.sha256,
        kind: target.kind,
        format: target.format,
        architecture: target.architecture ?? null,
        executable_role: target.executableRole ?? null,
      },
      producer: {
        reaVersion: PRODUCT_IDENTITY.packageVersion,
        runId: context?.runId ?? randomUUID(),
      },
      publishable: !reuse && managed.reservation.stagingPath !== undefined,
      reuse,
    };
  }
}

const providerFailureText = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

const inspectWindowsP0TargetSupport = (
  target: BinaryTarget,
  diagnostics: Readonly<Record<string, JsonValue>>,
): ProviderTargetSupport => {
  // The raw 6502 lane uses the same immutable snapshot and native ownership boundary.
  if (target.format === "raw-binary" && target.architecture === "6502")
    return { status: "supported", code: null, reason: null, diagnostics };
  if (target.format !== "pe")
    return {
      status: "unsupported",
      code: "target_format_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE and explicitly selected raw 6502 targets only.",
      diagnostics,
    };
  if (target.architecture !== "x86" && target.architecture !== "x86_64")
    return {
      status: "unsupported",
      code: "architecture_unsupported",
      reason: "Windows Ghidra P0 accepts x86 and x86-64 PE targets only.",
      diagnostics,
    };
  if (
    target.executableRole !== "application" &&
    target.executableRole !== "shared-library"
  )
    return {
      status: "unsupported",
      code: "target_role_unsupported",
      reason:
        "Windows Ghidra P0 accepts PE applications and DLLs, not non-executable or unclassified images.",
      diagnostics,
    };
  if (target.managed !== false)
    return {
      status: "unsupported",
      code: "managed_target_unsupported",
      reason:
        "Windows Ghidra P0 accepts native PE applications and DLLs; managed or unclassified PE targets are unsupported.",
      diagnostics,
    };
  return {
    status: "supported",
    code: null,
    reason: null,
    diagnostics,
  };
};
