# Tasks

Sequencing is shared with [analysis-jobs](../analysis-jobs/tasks.md). Each slice
is reviewable on its own and keeps `main` behaviour unchanged until its
contract step lands.

## Slice MT-1: registry refactor (no behaviour change)

1. Extract the single-target logic from `BinarySession` into a slot
   implementation with its own transition lock.
2. Add `BinaryTargetRegistry` that wraps one slot. Keep the public
   `BinarySessionPort` identical.
3. Gate: existing `BinarySession*` tests pass unchanged.

## Slice MT-2: target routing and caps

4. Add `target_id` generation, reopen-returns-same-id, and `keep_others_open`
   (default `false`).
5. Add optional `target_id` to every target-bound official tool contract. Route
   once in `withAdmittedAnalysis`. Add `target_not_open`.
6. Add `REA_MAX_OPEN_TARGETS` (default 4) and `capacity` refusal.
7. Gate: unit tests for caps, unknown id, and per-slot transition isolation.
   Boundary test with two `fakeGhidra` targets over MCP stdio.
8. Regenerate the tool catalog. Update `docs/mcp-contracts.md` and
   `docs/tool-design.md`.

## Slice AJ-1: background jobs in slots

9. Add the analysis state to each slot. Start the provider client with a
   job-owned signal (see analysis-jobs spec, "Ownership and lifetime").
10. Add `analysis_mode` (`foreground` default, `background`) to `open_binary`.
    Add `wait_ms` to `binary_session` and to analysis tools. Add
    `analysis_in_progress`.
11. Make `close_binary` cancel a running job through the forced-stop path, with
    no publish.
12. Move the cache publish into the job completion path, keeping its gate.
13. CLI rejects `background` with `capability_unavailable`.
14. Gate: unit tests (request abort does not stop job; wait budget; cancel
    publishes nothing). Boundary test: open in background, poll, reach ready.

## Slice AJ-2: experimental auto heuristic

15. Add `auto` mode, `auto_background_after_ms`, and
    `REA_GHIDRA_AUTO_BACKGROUND_AFTER_MS`.
16. Gate: unit tests for threshold choice; a cache hit returns in `auto` as in
    foreground.

## Slice MT-3: concurrency queue and batch CLI

17. Add `REA_MAX_CONCURRENT_ANALYSES` (default 2) and FIFO `queued` state shared
    by foreground and background starts.
18. Add `rea analyze <path>... --concurrency N` on the registry in one process,
    using the project cache.
19. Gate: queue ordering tests; CLI JSON output test.

## Real-provider verification (required before any claim)

20. Linux x64, Ghidra 12.1.4:
    - foreground versus background wall time on a small PE, with a lowered
      startup deadline;
    - a client abort mid-wait leaves the job running;
    - server exit mid-job publishes nothing and orphans no JVM;
    - two real PEs analysed concurrently versus serially, with peak
      process-family RSS.
21. Record every number as observed in the PR body. State the coverage that was
    not run, such as Windows and macOS.

## Maintainer decisions needed first

- Scope approval for the target-bound contract change (MT-2).
- O1 (shared-server retirement rule) and O2 (slot ownership).
- O3 (detached supervisor) before any v2 lifetime work.
