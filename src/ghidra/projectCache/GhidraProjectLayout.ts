import { createHash } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { lstat, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";

import canonicalize from "canonicalize";

import { err, ok, type Result } from "../../domain/result.js";
import {
  GhidraProjectCacheError,
  GHIDRA_PROJECT_DATA_DIRECTORY,
  GHIDRA_PROJECT_MANIFEST_FILE,
  GHIDRA_PROJECT_MARKER_FILE,
} from "./GhidraProjectCacheTypes.js";
import type { GhidraProjectFileRecord } from "./GhidraProjectManifest.js";

/**
 * Admit a stored project directory: an expanded Ghidra project (regular
 * `rea-project.gpr` marker plus a `rea-project.rep` directory), with no
 * symlink/reparse at either entry. Mirrors the existing-project admission so a
 * stored entry cannot smuggle a foreign path into a later launch.
 */
export const admitGhidraProjectDirectory = async (
  directory: string,
): Promise<Result<void, GhidraProjectCacheError>> => {
  let root;
  try {
    root = await lstat(directory);
  } catch (cause: unknown) {
    return err(
      new GhidraProjectCacheError(
        "io",
        "Stored Ghidra project directory is unreadable",
        directory,
        { cause },
      ),
    );
  }
  if (!root.isDirectory() || root.isSymbolicLink())
    return err(
      new GhidraProjectCacheError(
        "layout",
        "Stored Ghidra project must be a regular directory",
        directory,
      ),
    );
  const [marker, data] = await Promise.all(
    [GHIDRA_PROJECT_MARKER_FILE, GHIDRA_PROJECT_DATA_DIRECTORY].map((name) =>
      lstat(join(directory, name)).catch(() => undefined),
    ),
  );
  if (
    marker === undefined ||
    !marker.isFile() ||
    marker.isSymbolicLink() ||
    data === undefined ||
    !data.isDirectory() ||
    data.isSymbolicLink()
  )
    return err(
      new GhidraProjectCacheError(
        "layout",
        `Stored Ghidra project requires a regular ${GHIDRA_PROJECT_MARKER_FILE} and a ${GHIDRA_PROJECT_DATA_DIRECTORY} directory`,
        directory,
      ),
    );
  return ok(undefined);
};

/** Copy the marker and data entries of a project into an empty destination. */
export const copyGhidraProjectDirectory = async (
  source: string,
  destination: string,
  signal?: AbortSignal,
): Promise<void> => {
  signal?.throwIfAborted();
  await mkdir(destination, { recursive: true, mode: 0o700 });
  const copyEntry = async (from: string, to: string): Promise<void> => {
    signal?.throwIfAborted();
    const entry = await lstat(from);
    if (entry.isSymbolicLink())
      throw new GhidraProjectCacheError(
        "layout",
        "Stored Ghidra project contains a symbolic link",
        from,
      );
    if (entry.isDirectory()) {
      await mkdir(to, { recursive: true, mode: 0o700 });
      for (const name of await readdir(from))
        await copyEntry(join(from, name), join(to, name));
      return;
    }
    if (!entry.isFile())
      throw new GhidraProjectCacheError(
        "layout",
        "Stored Ghidra project contains a non-regular entry",
        from,
      );
    if (signal === undefined)
      await pipeline(
        createReadStream(from),
        createWriteStream(to, { flags: "wx", mode: 0o600 }),
      );
    else
      await pipeline(
        createReadStream(from),
        createWriteStream(to, { flags: "wx", mode: 0o600 }),
        { signal },
      );
  };
  await copyEntry(
    join(source, GHIDRA_PROJECT_MARKER_FILE),
    join(destination, GHIDRA_PROJECT_MARKER_FILE),
  );
  await copyEntry(
    join(source, GHIDRA_PROJECT_DATA_DIRECTORY),
    join(destination, GHIDRA_PROJECT_DATA_DIRECTORY),
  );
};

export interface GhidraProjectDigest {
  readonly files: readonly GhidraProjectFileRecord[];
  readonly projectDigest: string;
  readonly sizeBytes: number;
}

/** Digest every file in a stored project for integrity verification. */
export const digestGhidraProjectDirectory = async (
  directory: string,
  signal?: AbortSignal,
): Promise<GhidraProjectDigest> => {
  const files: GhidraProjectFileRecord[] = [];
  const walk = async (from: string, relative: string): Promise<void> => {
    signal?.throwIfAborted();
    for (const name of (await readdir(from)).sort()) {
      // The store's own manifest is written after the project is digested, so it
      // is not part of the project content identity.
      if (relative.length === 0 && name === GHIDRA_PROJECT_MANIFEST_FILE)
        continue;
      const absolute = join(from, name);
      const path = relative.length === 0 ? name : `${relative}/${name}`;
      const entry = await lstat(absolute);
      if (entry.isSymbolicLink())
        throw new GhidraProjectCacheError(
          "layout",
          "Stored Ghidra project contains a symbolic link",
          absolute,
        );
      if (entry.isDirectory()) {
        await walk(absolute, path);
        continue;
      }
      if (!entry.isFile())
        throw new GhidraProjectCacheError(
          "layout",
          "Stored Ghidra project contains a non-regular entry",
          absolute,
        );
      const hash = createHash("sha256");
      for await (const chunk of createReadStream(absolute)) {
        signal?.throwIfAborted();
        hash.update(chunk as Buffer);
      }
      files.push({ path, bytes: entry.size, sha256: hash.digest("hex") });
    }
  };
  await walk(directory, "");
  const sorted = [...files].sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  const encoded = canonicalize(sorted);
  if (encoded === undefined)
    throw new TypeError("Ghidra project file records are not canonicalizable");
  return {
    files: sorted,
    projectDigest: createHash("sha256").update(encoded).digest("hex"),
    sizeBytes: sorted.reduce((total, file) => total + file.bytes, 0),
  };
};
