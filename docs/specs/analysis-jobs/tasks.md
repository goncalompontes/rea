# Tasks

The job model runs inside the per-target slots from the
[multi-target draft](https://github.com/morluto/rea/issues/5272). Slice numbers
below refer to that file.

## Prerequisites

- MT-1 (registry refactor) and MT-2 (target routing) are on the stacked branch.
- The project cache (#3531) remains the publish owner on close.

## Slice AJ-1: background jobs

- [x] Job-owned `AbortSignal` for provider start; the request signal only
  aborts the caller's wait.
- [x] `analysis_mode` (`foreground` default, `background`, `auto`) on
  `open_binary`.
- [x] `wait_ms` on official analysis tools and `binary_session`.
- [x] `analysis_in_progress` error with elapsed time.
- [x] `close_binary` aborts the job through the existing close path.
- [x] `analysis` state (`starting`, `ready`, `failed`, `cancelled`) in
  `open_binary` and `binary_session`.
- [ ] Move the cache publish into the job completion path. In this draft, the
  existing close gate still owns the publish; a completed background job keeps
  the provider alive until close, and a cancelled close publishes nothing.
- [ ] CLI refusal for `background`. The CLI does not expose `analysis_mode` yet,
  so there is nothing to refuse. The one-shot CLI continues to run foreground.

## Slice AJ-2: auto heuristic

- [x] Time-based promotion with `auto_background_after_ms` and
  `REA_GHIDRA_AUTO_BACKGROUND_AFTER_MS` (default 120 000 ms).
- [x] Gate: threshold choice and request-abort tests; a cache hit is not
  distinguishable in the fixture provider yet.

## Real-provider verification (task 20)

- [ ] Foreground versus background on a small PE with a lowered deadline.
- [ ] Client abort mid-wait keeps the job alive.
- [ ] Server exit mid-job publishes nothing and orphans no JVM.
- [ ] Acceptance: the user's large DLL, recording elapsed time, the cache
  publish, and a second open as a cache hit.

## Explicitly deferred

- Detached supervisor surviving server restart (O3). Needs a maintainer decision
  and its own spec.
- Recorded-history auto promotion (phase 2).
- Provider-side progress percentages until #4439 or a bridge progress channel
  exists.
