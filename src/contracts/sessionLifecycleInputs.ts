import { isAbsolute } from "node:path";
import { executableFormatHintSchema } from "../domain/dosCom.js";
import { localPathStringSchema } from "../domain/localPath.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
  rawBinarySelectionError,
} from "../domain/rawBinary.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "./providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "snapshot_path must be an absolute local filesystem path (for example /tmp/rea/analysis.json or C:\\rea\\analysis.json)",
  })
  .describe(
    "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
  );

/** Opaque handle for one open target; never a path or digest. */
const binaryTargetIdSchema = z
  .string()
  .min(1)
  .describe(
    "Opaque target handle returned by open_binary. Omit to address the current target.",
  );

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
  })
  .describe(
    "Absolute local filesystem path for the analysis target; relative paths are rejected.",
  );

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z
  .strictObject({
    path: binaryTargetPathSchema,
    format: executableFormatHintSchema
      .optional()
      .describe(
        "Explicit headerless interpretation: dos-com or raw-binary. Omission preserves header-based detection.",
      ),
    architecture: binaryArchitectureSchema
      .optional()
      .describe(
        "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise.",
      ),
    entry_point: rawBinaryEntryPointSchema
      .optional()
      .describe(
        "Caller-supplied load and entry address (0xhex). File offset 0 is mapped here. Required with format=raw-binary; rejected otherwise.",
      ),
    provider_id: analysisProviderSelectorSchema.optional(),
    snapshot_path: snapshotPathSchema.optional(),
    keep_others_open: z
      .boolean()
      .default(false)
      .describe(
        "Keep existing open targets and add this one instead of replacing the current target. Default false preserves single-target replacement.",
      ),
    analysis_mode: z
      .enum(["foreground", "background", "auto"])
      .default("foreground")
      .describe(
        "foreground blocks until ready (default). background starts a server-owned job and returns analysis_started. auto waits up to auto_background_after_ms, then continues in background.",
      ),
    auto_background_after_ms: z
      .number()
      .int()
      .min(1)
      .max(2_147_483_647)
      .optional()
      .describe(
        "Auto-mode promotion threshold in milliseconds; defaults to REA_GHIDRA_AUTO_BACKGROUND_AFTER_MS or 120000.",
      ),
  })
  .superRefine((value, context) => {
    const pairing = rawBinarySelectionError({
      ...(value.format === undefined ? {} : { format: value.format }),
      ...(value.architecture === undefined
        ? {}
        : { architecture: value.architecture }),
      ...(value.entry_point === undefined
        ? {}
        : { entryPoint: value.entry_point }),
    });
    if (pairing === undefined) return;
    context.addIssue({
      code: "custom",
      path:
        value.format === "raw-binary"
          ? value.architecture === undefined
            ? ["architecture"]
            : ["entry_point"]
          : value.architecture === undefined
            ? ["entry_point"]
            : ["architecture"],
      message: pairing,
    });
  });

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
  target_id: binaryTargetIdSchema.optional(),
});
