# Tasks

The job model lives in the per-target slots from
[multi-target-sessions](../multi-target-sessions/tasks.md). Slice numbers below
refer to that file.

## Prerequisites

- MT-1 (registry refactor) and MT-2 (target routing) land first, so each job
  has a slot to live in.
- The project cache (#3531) is on the branch the jobs publish to.

## Slice AJ-1: background jobs (tasks 9-14 in the multi-target file)

- Job-owned `AbortSignal` for provider start; request signal only aborts the
  wait.
- `analysis_mode` on `open_binary`; `wait_ms` on `binary_session` and analysis
  tools; `analysis_in_progress` error with progress.
- `close_binary` cancels through the forced-stop path, with no publish.
- Cache publish moved into the completion path, keeping the existing gate.
- CLI refuses `background` with `capability_unavailable`.
- Docs: `docs/mcp-contracts.md`, `docs/installation.md` startup-timeout guidance,
  the packaged skill's polling guidance.

## Slice AJ-2: auto heuristic (tasks 15-16)

- Time-based promotion only. Phase 2 (recorded history) is a separate, later
  slice and stays off by default.

## Real-provider verification (task 20)

- Foreground versus background on a small PE with a lowered deadline.
- Client abort mid-wait keeps the job alive.
- Server exit mid-job publishes nothing and orphans no JVM.
- Acceptance: the user's large DLL, recording elapsed time, the cache publish,
  and a second open as a cache hit.

## Explicitly deferred

- Detached supervisor surviving server restart (O3). Needs a maintainer decision
  and its own spec.
- Phase 2 history heuristic (D2 of the analysis-jobs spec).
