import { z } from "zod";
import { isAbsolute } from "node:path";

import { localPathStringSchema } from "../domain/localPath.js";

/** Optional expectations used to compare the live session with its caller. */
export const binarySessionInputSchema = z.strictObject({
  target_id: z
    .string()
    .min(1)
    .describe(
      "Opaque target handle returned by open_binary. Omit to report the current target.",
    )
    .optional(),
  wait_ms: z
    .number()
    .int()
    .min(1)
    .max(290_000)
    .optional()
    .describe(
      "Maximum milliseconds to wait for a starting target before reporting its current analysis state. Default 180000; maximum 290000.",
    ),
  expected_package_version: z.string().min(1).optional(),
  expected_catalog_digest: z
    .string()
    .regex(/^[a-f0-9]{64}$/u)
    .optional(),
  expected_server_path: localPathStringSchema
    .refine(isAbsolute, {
      message:
        "expected_server_path must be an absolute local filesystem path (for example /opt/rea/dist/main.js)",
    })
    .describe(
      "Absolute local filesystem path expected for the running server; relative paths are rejected.",
    )
    .optional(),
});
