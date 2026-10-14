# Ghidra project cache

A fresh Ghidra import plus auto-analysis is paid on every `open_binary`. Large
targets can need many minutes, and an MCP restart re-pays it. The project cache
stores a previously analyzed program under REA's managed data directory and
reuses it in a later session for the same target and analysis inputs.

The fresh-import path runs `analyzeHeadless` with `-readOnly -deleteProject`, so
Ghidra never saves the program and nothing is reused. The cache instead imports
once **without** `-readOnly`, keeps the saved project, and opens it later with
`-process -noanalysis -readOnly` — the same read-only open the manual
pre-imported-project workflow uses (see
[installation](installation.md#opening-a-pre-imported-ghidra-project)).

## Enabling

| Variable                                | Meaning                                                  | Default                             |
| --------------------------------------- | -------------------------------------------------------- | ----------------------------------- |
| `REA_GHIDRA_PROJECT_CACHE`              | `off`, `read` (reuse only), or `on` (reuse and populate) | `off`                               |
| `REA_GHIDRA_PROJECT_CACHE_DIR`          | absolute cache root                                      | `<home>/.rea/cache/ghidra-projects` |
| `REA_GHIDRA_PROJECT_CACHE_MAX_BYTES`    | size ceiling; oldest entries are pruned first            | 10 GiB                              |
| `REA_GHIDRA_PROJECT_CACHE_MAX_AGE_DAYS` | discard entries older than this many days                | unset (no age limit)                |

The cache and `REA_GHIDRA_EXISTING_PROJECT` are mutually exclusive: both select
saved project state, and combining them is a configuration error.

```powershell
$env:REA_GHIDRA_PROJECT_CACHE = "on"
```

`rea uninstall --purge-data` removes the cache, because it lives under
`<home>/.rea/cache`.

## Identity

A stored project is selected by a key derived from the target SHA-256, the
Ghidra provider version, the JVM, the platform, and the final import profile
digest (language, loader, seeds, disabled analyzers, extensions, and the
provider-pinned lanes). A change to any result-affecting input selects a
different key, so a rebuilt Ghidra or a different import profile never reuses a
stale project.

For a REA-managed session the committed analysis profile is **open-mode
independent**: how the program was obtained (fresh import or cache hit) is
provenance, not analysis identity. A cache miss and a later cache hit therefore
commit the same profile digest for one target, so a retained analysis snapshot
([Save and reuse analysis snapshots](cli.md#save-and-reuse-analysis-snapshots))
replays in the later session.

## Lifecycle and safety

- **Miss** imports writable into a private runtime project; when the session
  closes after a clean, complete, mutation-free analysis the saved project is
  copied into the cache and published by an atomic rename under a per-key lock.
  A concurrent publisher that loses the race discards its copy.
- **Hit** copies the stored project into the private runtime and opens it
  read-only; the stored entry is never modified.
- A session that issued a database mutation (`annotate_native_function`, name
  writes) does not publish, so client annotations are never served to a later
  session as engine analysis.
- Entries are admitted only as an expanded Ghidra project (a regular
  `rea-project.gpr` marker and a `rea-project.rep` directory) with no
  symlink/reparse; an unreadable or mismatched entry is discarded and reported,
  and the session rebuilds instead.
- On a hit REA verifies the manifest and the cheap identity fields; the full
  per-file digest is recorded at publish for integrity checks rather than
  re-hashed on every open.

## Managing the cache

```sh
rea cache-list            # stored projects, sizes, and keys
rea cache-verify          # re-check manifests and digests
rea cache-verify --repair # also remove corrupt entries
rea cache-prune           # enforce the size ceiling now
rea cache-remove <key>    # drop one stored project
```

`cache-list` reports the cache directory, mode, ceiling, and each entry's key,
stored program name, target digest, provider version, size, and creation time.
`cache-verify` re-admits each entry and re-hashes its files against the recorded
project digest, reporting any mismatch. Add `--format json` for machine-readable
output. Listing and verification are read-only; prune, remove, and
`--repair` are the only cache mutations, and none of them opens a target.

## Limitations

The stored project is bound to the target bytes, provider, JVM, and import
profile it was built from. Saved project analysis can differ for identical
executable bytes, so the cache reuses a specific saved program rather than
claiming equivalence to a hypothetical fresh run. A cache hit reports that the
provider did not import or re-analyze the target in that session.

## Measured reuse

Windows Ghidra P0, Ghidra 12.1.4, JDK 21, alternating
`rea analyze <target> --provider ghidra` with `REA_GHIDRA_PROJECT_CACHE=on`:

| Target                 | First open (import + analysis) | Second open (cache hit) |
| ---------------------- | ------------------------------ | ----------------------- |
| `engine2.dll` (6.8 MB) | 256.8 s                        | 13.1 s                  |
| minimal PE fixture     | 17.4 s                         | 11.1 s                  |

The hit is confirmed by the session limitation "Ghidra analysis was reused from
a local project cache…" on the returned Evidence, and by an analysis profile
that records `project_cache` and no `import_mode`. Elapsed wall-clock includes
Node and JVM startup, a fixed cost that dominates a small target; the saving
scales with analysis size.
