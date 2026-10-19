# Multiple concurrent targets per MCP server

Status: **draft design** (uncommitted). Requires a maintainer scope decision
before implementation: every target-bound tool gains an optional selector, and
the server can hold several provider processes at once. Related: #1048, #3751,
#2358, #2150, #3817, #3531.

Companion: [analysis-jobs](../analysis-jobs/spec.md), whose background jobs run
inside the per-target slots defined here.

## Problem

1. `BinarySession` holds one `#active` binding and one `#transition` promise
   chain (`src/application/binary/BinarySession.ts`, 81 and 89). Opening another
   target drains calls on the current one and replaces it
   (`#openWithinTransition`, `#drainCalls`). Two DLLs cannot be analysed in one
   server.
2. Official analysis tools accept no target selector. They are admitted through
   `withAdmittedAnalysis` against the single active binding
   (`src/server/analysisAdmission.ts`, `ServerAnalysisSource`).
3. Rizin, GDB, Cutter, and the Rizin debugger each state that in a shared server
   they close any active binary-analysis session. That is the one-session model
   leaking into their contracts.
4. The provider layer already serialises work per Program
   (`GhidraRequestQueue`), and each Ghidra analysis is its own JVM. So the
   parallelism exists below the application layer. The single lock is above it.

## Outcome

- A server holds a registry of open targets. Each target has its own provider
  session and its own lifecycle lock. Work on different targets runs
  concurrently. Work on one target stays serial, as it is today.
- Existing single-target use is unchanged. A tool call without `target_id` acts
  on the current target.

## Non-goals (v1)

- Cross-target queries such as xrefs across DLLs or cross-module call graphs.
  Every result stays bound to one target digest.
- Import-table dependency resolution between DLLs. A possible follow-up.
- Cross-client isolation. v1 assumes one trusted client per server (O2).
- Changing the Rizin, GDB, Cutter, and debugger rule that they retire binary
  sessions (O1).

## Decisions

D1. **Registry in the application layer.** Add `BinaryTargetRegistry`
(`src/application/binary/`). It owns N slots. Each slot runs the single-target
logic currently in `BinarySession`, with its own transition lock. The single
`#transition` becomes per-slot. The registry lock covers only map changes.
Land this as a refactor with no behaviour change first. The existing
`BinarySession` tests are the guard.

D2. **`target_id` is an opaque routing handle.** It is a random identifier per
slot, returned by `open_binary`. Reopening the same target digest and profile
while its slot is live returns the same id, which keeps today's "reopening
retains" rule. It is never a path or a digest. Lookup identity and display stay
separate, as AGENTS.md requires. Evidence identity stays the target digest; the
handle does not replace it.

D3. **Opening.** `open_binary` gains `keep_others_open` (boolean, default
`false`). `false` keeps today's replace semantics, which avoids surprise memory
growth for existing clients. `true` adds a slot and makes it current.

D4. **Routing once.** Every target-bound official tool gains an optional
`target_id`. Absent means the current target. An unknown or closed id returns
`target_not_open`, listing the open ids but no paths. Routing happens once, in
`withAdmittedAnalysis` / `ServerAnalysisSource`, not in each tool. JSON Schemas
are validated after SDK conversion, per AGENTS.md.

D5. **Capacity is explicit.** `REA_MAX_OPEN_TARGETS` (default 4) bounds open
slots. `REA_MAX_CONCURRENT_ANALYSES` (default 2) bounds analyses in flight.
Opening beyond the open cap is refused with `capacity`. Nothing is evicted
silently. Starts beyond the concurrency cap are `queued` and run FIFO. Both caps
are needed because each Ghidra target is one JVM with its own heap. #3751
measured a 12 GB heap for one 191 MiB binary.

D6. **Background jobs are slot states.** The analysis-jobs spec's `starting`
state, including background mode, lives in a slot. The concurrency queue applies
to both foreground and background starts.

D7. **Evidence stays bound to the digest.** Each Evidence record already carries
the target identity. The response also names `target_id` for routing, so an
agent can tell which DLL it is reading.

D8. **Batch CLI as a later slice.** `rea analyze a.dll b.dll ... --concurrency N`
runs on the registry inside one CLI process, which avoids the lifetime problem
in analysis-jobs D3. Re-runs are cheap with the project cache (#3531).

## Design

### Components

- `BinaryTargetRegistry` (new): slots, ids, caps, queue.
- `BinarySession` / `BinarySessionPort`: `activeTarget(targetId?)` and
  `withAdmittedAnalysis(targetId?, …)`. The current single-target code becomes
  the slot implementation.
- `src/server/analysisAdmission.ts`: target resolution.
- `src/server/createServer.ts` and `registerOfficialTools.ts`: pass the registry
  and the selector to admission.
- `src/contracts/officialToolContracts.ts` and the Rizin, GDB, and Cutter
  contracts: optional `target_id` where the tool is target-bound.
- `docs/mcp-contracts.md`, `docs/tool-design.md`, and the skill: document the
  selector, the caps, and the errors.

### Lifecycle rules

- `close_binary` with `target_id` closes that slot. Without an id it closes the
  current slot, as today.
- Rizin, GDB, Cutter, and debugger tools keep their rule: they retire all binary
  slots in a shared server (O1). Their remediation text does not change.
- Server shutdown cancels every slot. Incomplete analyses are not published.

## Verification plan

- **Refactor guard**: existing `BinarySession` and `BinarySessionLiveness` tests
  pass unchanged after D1.
- **Unit**: registry caps, FIFO queue, unknown id, reopen returns the same id,
  and a transition on one slot does not block another.
- **Boundary** (MCP stdio, `fakeGhidra`): open two fixture targets; an analysis
  call on A completes while B is still analysing.
- **Real provider** (Linux x64, Ghidra 12.1.4): two real PEs, including the
  user's DLLs, analysed concurrently versus serially. Record wall time and peak
  process-family RSS. These are measurements to take, not claims to make now.
- **Compatibility**: a recorded single-target transcript matches before and after.

## Risks

- **Largest contract change so far**: every target-bound tool gains a field. It
  needs a maintainer decision first.
- **Memory**: N JVMs. The conservative default caps limit the exposure.
- **Wrong-target analysis**: an agent may act on the current DLL by accident.
  Mitigation: every response names the target's id, name, and digest.
- **Shared server**: a second client could close or query a slot it did not
  open (O2).

## Open questions

- **O1.** Should Rizin, GDB, Cutter, and the debugger keep retiring all binary
  slots, or only the slots that conflict with them? The current rule predates
  multiple targets, and the reason is not written down in these contracts.
- **O2.** Should slots be owned by the client that opened them? Ownership
  affects HTTP transport, where several clients can share one server.
- **O5.** Should cross-target queries (for example, DLL A calling into DLL B)
  come in a later spec? They need a defined result shape before any design.
