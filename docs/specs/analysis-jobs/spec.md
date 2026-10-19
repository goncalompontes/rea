# Background Ghidra analysis jobs with bounded waits

Status: **draft implementation** (stacked on the multi-target drafts; no
integration without a maintainer scope decision). This changes the
`open_binary` and `binary_session` contracts and the lifetime of provider
processes. Tracking issue:
[#5271](https://github.com/morluto/rea/issues/5271). Related: #3509, #3751,
#1048; PRs #3531 (project cache), #4161 (progress notifications), #4439
(streamed progress and an analysis cache).

Companion: [multiple concurrent targets](https://github.com/morluto/rea/issues/5272),
which provides the per-target slot these jobs run in.

## Problem

1. `open_binary` is one blocking MCP call. The Ghidra startup deadline
   (`REA_GHIDRA_STARTUP_TIMEOUT_MS`, default 330 000 ms) covers import, auto
   analysis, bridge start, and readiness. Raising it to an hour keeps the agent
   inside one call for an hour (`src/config/providerStartupTimeout.ts`,
   `docs/mcp-contracts.md` 516).
2. A client idle timeout or abort cancels the request. Cancelling an active
   Ghidra request calls the forced-stop path
   (`GhidraRequestQueue` ÔåÆ `#stopAfterActiveCancellation` ÔåÆ `#requestClose(true)`
   in `src/ghidra/GhidraClient.ts`). A forced stop skips
   `#publishManagedProject`, so the partial analysis is discarded and the next
   open starts over. This is the mechanism behind #3509.
3. Coding agents run inside LLM prompt caches with reported TTLs of 5 to 30
   minutes. A tool call that blocks for tens of minutes leaves the model idle;
   its next turn is then likely to re-read the whole context uncached. This is
   reasoning from the reported TTLs, not a measurement.

## Outcome

- Analysis can run as a **background job** owned by the MCP server. The request
  that starts a job and any later request only control their own wait. A
  cancelled or timed-out wait never stops the job.
- Every wait returns within a bounded budget. While a target is still starting,
  the response reports `analysis_in_progress` with elapsed time, so each agent
  turn stays short.
- Foreground behaviour remains the default and is unchanged.
- An **experimental** heuristic can promote a foreground open to a background
  job after a configured run time.

## Implementation status

This draft implements background and auto modes at the target registry. The job
owns the provider start signal, `binary_session` and official analysis tools
accept `wait_ms`, and `close_binary` aborts the job. The existing close-time
cache publish gate is unchanged. The CLI does not expose `analysis_mode`, so no
one-shot background mode exists to refuse. No real-provider measurement has been
run.

## Non-goals (v1)

- Surviving the MCP server process exiting or restarting. A job ends with its
  server. Completed analyses are published to the cache; incomplete ones are
  not. A detached supervisor is the v2 answer (D4).
- Background analysis in the one-shot CLI (D3).
- Providers other than Ghidra. The job model is provider-neutral; other providers
  opt in later through a capability flag.
- Concurrency across targets. That is owned by the multi-target spec.

## Decisions

D1. **Default is foreground.** `analysis_mode` defaults to `foreground`. Errors,
cache behaviour, and output are unchanged unless a caller opts in.

D2. **`auto` is experimental and opt-in.** `open_binary` accepts
`analysis_mode: "auto"` and `auto_background_after_ms` (default 120 000). The
environment variable `REA_GHIDRA_AUTO_BACKGROUND_AFTER_MS` sets the default
threshold. In `auto`, the open waits up to the threshold. If the target is ready,
the result is the same as foreground, which covers cache hits. Otherwise the
open returns `analysis_started` and the job continues.

D3. **Background is MCP-server only.** The CLI process exits when the command
does, so a CLI background job would die with it. The one-shot CLI has no
`analysis_mode` input and remains foreground; a future CLI flag must fail with
`capability_unavailable` rather than start a short-lived job.

D4. **Job lifetime equals server lifetime in v1.** Server exit cancels the job
without publishing. Open question O3 covers a REA-owned detached supervisor,
which is the change that would make a one-hour analysis survive a client
restart.

D5. **Wait budget.** `binary_session` and analysis tools accept `wait_ms`.
Default 180 000, maximum 290 000, so a single call stays under the shortest
reported cache TTL (5 minutes). A tool call that finds the target still starting
waits up to the budget, then fails with `analysis_in_progress`, which is
retryable and includes progress.

D6. **Cancellation.** `close_binary` cancels a running job. It uses the existing
forced stop, so cleanup is owned and no cache entry is written. v1 adds no new
cancel tool, following the tool-design rule to reuse existing contracts.

D7. **Progress is honest.** Progress comes from launcher output and, once merged,
from #4439's streamed progress. Until then the state reports elapsed time and
any phase line Ghidra prints. No percentage is invented. The bridge serves
nothing before analysis completes, so progress cannot come from bridge requests.

D8. **Caching is unchanged in rule; the close gate still owns the publish.**
A background job keeps the provider alive after analysis, so a later explicit
close can publish under the existing gate: a confirmed shutdown, a natural
process exit, complete non-timed-out analysis, and no client mutation. A
cancelled close still publishes nothing. Moving publication onto the completion
path remains a provider-side follow-up.

## Design

### State

Each target slot (see the multi-target spec) has an analysis state:

```
idle -> starting(mode) -> ready
starting -> failed(error)
starting -> cancelled            (close_binary)
ready -> closing -> idle
```

`binary_session` reports it:

```
analysis: { state, mode, started_at, elapsed_ms, progress?, error? }
```

### Ownership and lifetime

- A job starts the provider client with a job-owned `AbortSignal`, not the
  request's signal. Today `GhidraClient.start(signal)` binds the request signal
  to startup, and an abort there reaches `#startupInterrupted`. In background
  mode the request signal only aborts the wait. The wait is built on the same
  abortable-promise primitive used elsewhere (`src/process/AbortablePromise.ts`).
- Stopping uses the existing `GhidraClient.close` path and `src/process/`
  supervision. No new process-cleanup logic is added, per AGENTS.md.
- A job whose cleanup fails keeps ownership of the retained resource and reports
  `cleanup_incomplete`, as foreground sessions already do.

### Wait semantics

| Call | Behaviour |
|---|---|
| `open_binary` foreground | Unchanged. Blocks until ready or failure. |
| `open_binary` background | Registers the job and returns `analysis_started` at once. |
| `open_binary` auto | Waits up to `auto_background_after_ms`, then returns `analysis_started` if still starting. |
| `binary_session` with `wait_ms` | Waits up to the budget for ready or failure, then returns the current state. |
| Analysis tool while starting | Waits up to `wait_ms`, then returns `analysis_in_progress`. |

Phase 2, optional and off by default: when the cache manifest or the Activity
Journal (#4161) has a recorded foreground duration for the same cache key that
exceeded the threshold, start in background immediately. Record this as a
heuristic in the Evidence limitations.

### Errors

New codes and states:

- `analysis_in_progress`: retryable; includes elapsed time. Implemented.
- `analysis_failed`: not a separate code in this draft. A failed job exposes the
  original provider error and records it in the `analysis` state.
- `analysis_cancelled`: `close_binary` aborts the job through the existing close
  path; callers see the existing cancellation outcome.
- `capability_unavailable`: reserved for a future CLI `background` request; the
  CLI has no such input today.

### Contracts and docs

- `sessionToolContracts.ts`: `open_binary` gains `analysis_mode`,
  `auto_background_after_ms`; `binary_session` gains `wait_ms` and `analysis`.
- Analysis tool contracts: only the new `analysis_in_progress` error and optional
  `wait_ms`. Target routing is in the multi-target spec.
- `toolEffects.ts`: background opens are long-lived process owners.
- Regenerate the catalog. Update `docs/mcp-contracts.md`,
  `docs/installation.md` (startup timeout guidance), and the packaged
  `reverse-engineer-anything` skill so agents open in background and poll with
  bounded waits.

## Verification plan

- **Unit** (fake client seam, `GhidraProviderClientFactory`): a request abort
  during a wait does not stop the job; `close_binary` stops it with no publish;
  the wait budget is honoured; the auto threshold chooses the mode.
- **Boundary** (MCP stdio, `fakeGhidra`): open in background, poll until ready,
  and check that an analysis call while starting returns `analysis_in_progress`
  inside the budget.
- **Real provider** (Linux x64, Ghidra 12.1.4, required before any claim):
  1. A small PE with a lowered startup deadline, to compare foreground and
     background wall time and to check that a client abort mid-wait leaves the
     job running.
  2. Server exit mid-job: no cache entry is published and no JVM is orphaned.
  3. Acceptance: the user's large DLL, recording elapsed time, the cache publish,
     and a second open as a cache hit.
- Record every measurement as observed. Do not claim numbers that were not run.

## Risks

- **Orphan processes** if a server crashes. Mitigated by reusing `src/process/`
  ownership.
- **Idle memory**: a background job keeps its JVM heap while waiting. The
  multi-target caps bound this.
- **Client expectations**: clients that assume a blocking `open_binary` change
  behaviour only when they opt in. Foreground stays the default.
- **Progress quality** is limited until #4439 or a bridge-side progress channel
  exists.

## Open questions

- **O3.** Should v2 add a detached REA-owned supervisor that outlives the MCP
  server? It is the only option that lets a one-hour analysis survive a client
  restart. It needs a maintainer scope decision.
- **O4.** Should `auto` use recorded history (phase 2) on by default once it has
  real-provider data?
