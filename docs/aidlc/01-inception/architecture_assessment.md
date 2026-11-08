# Architecture Assessment — Sentinel v1 (AI-DLC Inception)

| | |
|---|---|
| Phase | Inception |
| Date | 2026-10-28 |
| Inputs | Architecture PDF (13 pp.), `SENTINEL_BUILD_BRIEF.md`, the 11 diagrams in `docs/architecture/` |
| Status | Draft rev. 10 (D-24a and D-15 Approved: default deny through explicit grants; policy receives `tool_spec` explicitly; no Tool-Abuse detector in v1). Rev. 9 (D-24b Approved: tool-level grants; identity produces `SecurityContext` facts, never decisions). Rev. 8 (D-05, D-18, D-21 Approved: filesystem contract C2 and the Windows restriction for path-constrained tools). Rev. 7 (operational refusals are not policy decisions; C-03 was then blocked on the Pydantic dependency, since approved and implemented). Rev. 6: Q-03c, internal errors are not denials. Rev. 5: owner answers recorded; C-03a implemented. Rev. 4: final contract gate (D-07, D-29, D-30, D-31 approved). Rev. 3 was after C-02/C-02b (owner approvals D-12, D-25–D-28 and the D-14 amendment). Rev. 3 amends §2 (adapter notes), §4 (claim, guard, interruption, async path), §5, §6 and §8; earlier text is kept and marked. Changes marked **[APPROVAL]** need owner sign-off. Rev. 2 replaces §4 and §8 with the reconciled contracts in [`decision_record.md`](decision_record.md); §1–3 and §5–7 are unchanged from rev. 1 except where noted. CF/OD references map to D-IDs through the table at the top of `open_decisions.md` |

## 1. Summary verdict

The brief's architecture is a good fit for v1: a linear, synchronous pipeline with one decision point (the policy engine) and one execution point (the tool proxy). It is cohesive, and it already resolves most of the PDF's contradictions. **No new architectural components are recommended.** The assessment found six contract gaps that would otherwise let the actual execution path diverge from what the policy decided, or leave a failure mode undefined:

1. The policy engine needs tool metadata (`destructive`, `path_args`) but its interface does not receive it (CF-07).
2. Decisions are not bound to requests, and the proxy accepts any decision object (CF-08).
3. Argument coercion can make the executed arguments differ from the evaluated arguments (OD-09).
4. Path checking is underspecified: string-prefix matching, uncanonicalised allowed prefixes, the original rather than the canonical path passed to the tool, and `None` meaning unrestricted (CF-13).
5. Failures **after** execution are reported as DENY, and post-execution audit failure is undefined (CF-05, CF-09).
6. The framework integration promise (`protect(graph)` covers "every invocation") exceeds what interception can enforce (CF-18).

The owner's diagrams of 2026-10-26 differ from the brief on three structural points: who orchestrates, when audit is written, and the persistence model. These are recorded as decisions OD-02, CF-09 and OD-01, not settled here.

## 2. Component responsibilities

| Component (module) | Responsibility | In → Out | Security check it **owns** | Assessment |
|---|---|---|---|---|
| Gateway (`gateway.py`) | Validate and normalise raw input; confirm the tool is registered; validate arguments against the schema (OD-09) | `dict` → `SecurityRequest` (frozen) | Input well-formedness (FR-001, FR-003, FR-004); reserved-key rejection (SEC-013) | Cohesive. **Change:** the pipeline assigns `request_id` before calling the gateway, so invalid requests are auditable (FR-002). Session store: the brief records history in M1 but nothing uses it until M4. Recommend introducing it in M4 (YAGNI). |
| Identity (`identity.py`) | Resolve the agent, verify the credential, load the envelope | `SecurityRequest` → `SecurityContext` | Authentication facts (`authorized`), not decisions | Cohesive. It never decides ALLOW/DENY; policy row 1 does. Good. |
| Detector (`detector.py`) | Heuristic findings over request content | `(SecurityRequest, SecurityContext)` → `list[SecurityFinding]` | None authoritative. Advisory input to policy | Cohesive once the Tool-Abuse detector is removed, since it duplicates policy (CF-07). |
| Policy engine (`policy.py`) | **Sole** ALLOW / DENY / REQUIRE_APPROVAL authority | `(request, context, findings, tool_spec)` → `SecurityDecision` | Grants, path constraints, severity threshold, rate limits (M4), destructive approval | Cohesive. **Gap:** missing `tool_spec` input [APPROVAL CF-07]. Must be pure (SEC-019). |
| Path guard (pure function; recommended home `policy.py` or a small `paths.py`) | Canonicalise and check containment | `(path, allowed_prefixes)` → allowed / denied plus canonical path | Filesystem boundary (SEC-007) | Not a new component: a shared pure helper so that policy and the proxy re-check cannot drift apart. |
| Tool registry (`registry.py`) | Map name → (`ToolSpec` metadata, callable); unique names | Registration → lookup | Registry integrity (SEC-014) | Cohesive. **Recommend:** `ToolSpec` holds metadata only, and the registry keeps the callable beside it. That matches the persisted `Tool` entity (metadata only) and lets metadata go to policy without handing over the callable. |
| Tool proxy (`proxy.py`) | Execute only a bound ALLOW; re-check paths; invoke with canonical arguments; run the output-filter stage; contain tool errors | `(request, decision)` → `ToolResult{executed\|blocked\|error}` | Decision binding (SEC-010); last-line path re-check; tool-error containment (SEC-017); filter fail-closed (SEC-011) | Cohesive. **Gaps:** decision binding [APPROVAL CF-08]; `error` status [APPROVAL CF-05]. |
| Output filter (inside `proxy.py`) | Redact or withhold sensitive output | output → filtered output | SEC-011, FR-015 | M1 pass-through stage; M3 redaction. |
| Audit logger + store (`audit.py`, `store.py`) | Append-only event recording, masking, read API | Event → committed row | SEC-005, SEC-008, SEC-018 | **Recommend:** only `Pipeline` writes audit events. Each stage returns values; the pipeline records them. That gives one place that defines and tests ordering, instead of every stage calling the logger ("Audit Logger observes every stage" still holds functionally). |
| Pipeline (`pipeline.py`) | Orchestrate stages; enforce audit ordering; fail closed before execution; report the outcome truthfully after | `dict` → `PipelineResult` | Overall enforcement sequence; SEC-005, SEC-009 | Cohesive. It is the single owner of the enforcement path (OD-02: diagrams give this role to the Gateway). |
| Client (`client.py`) | Thin public facade: registration, `evaluate_request`, `audit_events`, later `protect` | — | None of its own | Cohesive. |
| Config (`config.py`) | Explicit configuration object; no env reads | — | Fail closed on invalid config (CF-01) | Cohesive. `db_url` default [APPROVAL OD-07]. |
| Integrations (`integrations/`) | Route framework tool calls into the pipeline; bind identity | Framework tool call → `evaluate_request` → result or exception | Identity binding (SEC-013); async fail-closed (SEC-016) | **Highest uncertainty.** Validate early (C-02 spike) [APPROVAL CF-18]. |
| Alert manager (`audit.py`) | Warn on repeated high-severity denials | Audit stream → `logging` warning | None (observability) | Fine as SHOULD; not on the enforcement path. |

**Rev. 2 notes on the table above:**
- The gateway also canonicalises path arguments and builds the `AuthorizedAction` candidate (C2.4, C1.4). That I/O moves out of policy, so policy stays pure.
- The path guard is two functions: `canonicalise` (I/O; used by the gateway and the proxy re-resolution) and `is_contained` (pure; used by policy and the proxy).
- The proxy's `ToolResult{executed|blocked|error}` is superseded by the C1.6 fields.
- The `AuditEvent` model is specified in C4.2.

**Rev. 3 notes (decision record C3.5):**
- **Proxy:** holds the atomic single-use claim (C1.4 rule 5, D-25) and the `tool_call_id` guard (D-27). It has sync and async execution paths sharing one claim implementation, and the state machine `claimed → entered → completed | failed | interrupted`. It is still the only caller of original functions.
- **Pipeline:** adds the **internal** async entry (FR-026; D-30 Approved in rev. 4: not a public API in v1) that runs blocking stages in a worker thread, and the interruption handling (C1.6: best-effort `unknown`, re-raise).
- **Framework adapter** (`integrations/`): builds replacement `StructuredTool`s (Design B, D-12); refuses unsupported patterns; forwards `InjectedToolCallId` outside the evaluated action; converts non-ALLOW and post-execution failures into fixed-text in-tool `ToolException`s (D-26); offers a best-effort coverage report (FR-025). It **owns no authorization logic**: it only translates between the framework and the pipeline.

## 3. Dependency direction (no cycles)

```text
exceptions, models          (no internal imports)
      ↑
config, path guard          (models)
      ↑
registry                    (models, exceptions)
      ↑
gateway, identity, detector, policy     (models, registry metadata, path guard)
      ↑
store → audit               (models, SQLAlchemy)
      ↑
proxy                       (registry, path guard, models)       ← no audit import
      ↑
pipeline                    (all stages + audit)
      ↑
client                      (pipeline, registry, config)
      ↑
integrations/*              (client only; framework imports guarded inside)
```

With pipeline-owned audit writes and metadata-only `ToolSpec`, every arrow points one way. **INFERRED:** the brief's layout has no inherent cycle. The risk lies in the proxy calling audit directly, as the PDF suggests ("Feeds into: Calls the Audit Logger"), while the pipeline also does. That would scatter ordering logic, which the recommendation above avoids. NFR-015 tests this.

## 4. The enforcement sequence (recommended contract)

Numbers in brackets are audit events. **Bold** marks the failure behaviour.

**Rev. 2** (reconciled with `decision_record.md` C1, C2, C4). Every audit write up to and including step 7 is **committed** before the next step. The pipeline is the only audit writer (D-16).

| Step | Stage | Action | On exception / failure |
|---|---|---|---|
| 0 | Pipeline | Assign `request_id`, UTC `received_at` | — |
| 1 | Audit | [REQUEST_RECEIVED], masked | **Not invoked; `decision=None`, `AUDIT_UNAVAILABLE`** *(rev. 7; was DENY)*, `audit_complete=False` |
| 2 | Gateway | Shape; tool registered; reserved keys; strict `arg_schema` (extra forbidden); path arguments absolute → `realpath` canonicalised → `AuthorizedAction` candidate with digest | Invalid → refused: `decision=None`, `INVALID_REQUEST` → REQUEST_COMPLETED, no DECISION event *(rev. 7; was DENY → step 6)*. Unexpected → **Internal error: `decision=None`, `INTERNAL_ERROR`, not executed** *(rev. 6, Q-03c; was DENY `INTERNAL_ERROR`)* |
| 3 | Identity | → `SecurityContext`; [IDENTITY_RESOLVED] | **Internal error: `decision=None`, `INTERNAL_ERROR`, not executed** *(rev. 6, Q-03c; was DENY `INTERNAL_ERROR`)*; audit failure → **`decision=None`, `AUDIT_UNAVAILABLE`** *(rev. 7; was DENY)* |
| 4 | Detector | → findings; [FINDING]×n | Same as step 3 |
| 5 | Policy (pure, no I/O) | `evaluate(request, context, findings, tool_spec)`: rows 1–7 of C1.5; containment by component on canonical paths; embeds the action in the decision | **Internal error: `decision=None`, `INTERNAL_ERROR`, not executed** *(rev. 6, Q-03c; was DENY `INTERNAL_ERROR`)* |
| 6 | Audit | [DECISION] (with `action_digest` for allow) | **Not invoked; the policy decision is preserved (`allow`/`deny`), `AUDIT_UNAVAILABLE`** *(rev. 7; was DENY)* |
| 6a | Branch | deny / require_approval → [REQUEST_COMPLETED(not_started)] → return | Audit failure: still not executed; `audit_complete=False` |
| 6b | Proxy (rev. 3; rev. 4) | **Atomic claim** of the decision (D-25); if a `tool_call_id` is present, purge expired guard entries, then claim `(agent_id, session_id, tool_call_id)` (D-27, D-31) | Already claimed → **not invoked**; `decision=None`, `DECISION_ALREADY_USED` / `DUPLICATE_TOOL_CALL` *(rev. 7; was effective DENY)*. **Rev. 4:** guard full after purging → **not invoked**, `decision=None`, `GUARD_CAPACITY_EXHAUSTED` (no eviction of unexpired entries); REQUEST_COMPLETED(not_started). A `tool_call_id` without a `session_id` was already rejected at step 2 (`INVALID_REQUEST`) |
| 7 | Audit | [EXECUTION_STARTED] (ALLOW only) | **Not invoked; `allow` preserved, `AUDIT_UNAVAILABLE`** *(rev. 7; was DENY)* |
| 8 | Proxy | ALLOW and `request_id`s match and digest verifies → re-resolve paths (must be unchanged and contained) → set `entered` → `fn(**deepcopy(action.arguments), **injected)` (sync) or `await coro(...)` (async, on the caller's loop) | Check fails → **not invoked**; `decision=None`, `ACTION_MISMATCH` / `RESTRICTED_PATH` (path changed) *(rev. 7; was effective DENY)*; an unexpected internal error (e.g. registry lookup) → `decision=None`, `INTERNAL_ERROR`, not executed (rev. 6, Q-03c). Tool raises `Exception` → `execution="failed"`, `TOOL_FAILED`, structured diagnostics per D-29 (type, module, function, line, stage; no message text, no absolute paths). **Rev. 3:** `BaseException` after `entered` → state `interrupted`, best-effort REQUEST_COMPLETED(`unknown`), re-raise (never DENY, never retried) |
| 9 | Output filter | Pass-through (M1) / redact (M3); [OUTPUT_FILTERED] or [OUTPUT_WITHHELD] | Filter raises → **output withheld**, `OUTPUT_FILTER_FAILED` |
| 10 | Audit | [REQUEST_COMPLETED(execution, effective decision)] | Decision stays as enforced; `execution` truthful; output withheld; `audit_complete=False`; masked `logging` fallback (D-03) |
| 11 | Pipeline | Return `PipelineResult{request_id, decision, reason, execution, output_released, output, audit_complete, error_code}`; never raises for request outcomes | — |

The precedence follows brief R4, which merges the PDF's two conflicting orders so that DENY always beats REQUIRE_APPROVAL. Audit readers apply the reconstruction rules in `decision_record.md` C4.4. A request with EXECUTION_STARTED but no REQUEST_COMPLETED has **unknown** execution status.

**Rev. 3 additions:**
- The async entry (FR-026) runs steps 0–7 and 9–11 in a worker thread and awaits step 8's coroutine on the caller's event loop.
- No step re-invokes the tool for a claimed request (C1.7, D-26).
- The framework adapter maps the result to the framework:
  - ALLOW + released output → the original return value, unchanged (`str`, `ToolMessage`, `Command`);
  - non-ALLOW → `ToolException("blocked: <REASON>")`;
  - executed but failed, or output withheld → `ToolException("tool failed (execution may have occurred)")`;
  - interruption → the exception propagates.

*Rev. 1 of this table placed canonicalisation in policy, wrote TOOL_EXECUTED/TOOL_BLOCKED terminal events, and raised `AuditUnavailable`. Those positions are superseded by D-18, D-09 and D-03 respectively.*

## 5. Trust boundaries and the security boundary

```text
 ┌──────────────────────── single Python process (TRUSTED CODE) ───────────────────────┐
 │  Developer application code ── constructs ──► SentinelClient / Pipeline / Registry   │
 │        │                                         ▲                                    │
 │        │ binds agent identity (trusted)          │ only path to registered tools      │
 │        ▼                                         │                                    │
 │  Framework (LangGraph/LangChain) ── tool call ──►┘  (via Sentinel-wrapped tools)      │
 │        ▲                                                                              │
 └────────┼──────────────────────────────────────────────────────────────────────────────┘
          │ UNTRUSTED DATA crossing in:
          │  • LLM output: tool name, arguments (attacker-influenceable via prompt injection)
          │  • Tool outputs and retrieved content (may carry injected instructions)
          │  • User input
          ▼
   External tools / filesystem / APIs  ◄── side effects only through the proxy
```

**What Sentinel is designed to enforce (deterministic controls; planned, not yet implemented):** for every tool call **routed through Sentinel**, the call executes only if the bound agent is authorized, holds a grant for that tool, satisfies the grant's path constraints, triggers no finding at or above the deny threshold, is not destructive-with-approval-required, and the decision event is committed to the audit store first.

**What Sentinel will not and cannot enforce in v1:**

| Limitation | Why |
|---|---|
| Code in the same process calling tool functions directly, monkey-patching Sentinel, or editing the audit DB | In-process library; Python has no memory isolation (CF-11) |
| Tool calls that do not go through a Sentinel-wrapped tool or node | Interception only covers what is wrapped (CF-18) |
| What the model reads (LLM context, retrieved documents) | Not visible to Sentinel unless it appears in arguments or output |
| Prompt injection in general | Detection is heuristic; the capability envelope limits the *consequences* (CF-15) |
| Side effects of an allowed tool beyond its declared path arguments | Sentinel checks declared arguments, not tool internals |
| Runaway tool execution | No timeouts or resource caps |
| Symlink swaps between resolution and `open()` | TOCTOU residual (CF-13) |
| Tamper-proof audit | Append-only through the API only (CF-10) |
| **Rev. 3:** unwrapped, middleware-supplied and provider built-in tools; trusted code substituting an original tool | Outside the adapter boundary (C3.3, C3.6; observed C-02b A5, A6, A8) |
| **Rev. 3:** downstream effects of an allowed tool's `Command` (`goto`, state updates) | Applied by the framework after Sentinel's decision (C-02b C2) |
| **Rev. 3:** a new call with a new `tool_call_id`, including model-driven repeats | A new request, evaluated independently; the D-27 guard only stops repeats of the same id |
| **Rev. 3:** whether an interrupted tool completed its side effect | Inherently unknown; recorded as `unknown` (C1.6) |
| **Rev. 3:** retry mechanisms other than `RetryPolicy` and `ToolRetryMiddleware` | Untested (C3.6) |

**Trust assumptions (ASSUMPTION, to be stated in the README):** the developer's application code, the Sentinel configuration, and registered tool implementations are trusted. Agent identity is trusted only if it is bound by application code (CF-12).

## 6. Bypass analysis of the execution path

| # | Potential bypass | In the brief's design? | Mitigation | Residual |
|---|---|---|---|---|
| B1 | Calling `ToolProxy.execute` with a hand-built ALLOW decision | Possible | Bind decision to `request_id`; proxy internal and not exported (CF-08) | Deliberate in-process misuse remains possible |
| B2 | Calling the registered tool function directly | Possible | Adapters move the original into the registry and expose only the wrapped tool; docs warn | Cannot be prevented in-process |
| B3 | Policy evaluates arguments X; the proxy executes coerced or mutated arguments X′ | Possible (lax re-validation, mutable dict) | Validate once, strictly; freeze; execute the same values (OD-09) | None known |
| B4 | Path string re-interpreted by the tool (`~`, relative path, symlink resolved later) | Possible | Execute with the canonical path; reject relative paths (CF-13) | TOCTOU swap window |
| B5 | Exception after ALLOW reported as DENY → caller assumes no side effect | Yes (§4.2 "any exception → DENY") | `outcome` field (CF-05) | — |
| B6 | Audit failure leaves an executed call unrecorded | Possible after execution | CF-09 option B | The side effect itself is not undone |
| B7 | Async framework path calls the original tool unguarded | Possible at M5 | *Rev. 2:* async entry fails closed (SEC-016). **Rev. 3:** superseded by D-12. Async-native tools are gated through the async proxy path; a sync entry into an async-only tool is rejected by the framework (C-02b B4) | Untested async patterns |
| B8 | Model supplies `agent_id` to impersonate another agent | Possible if the adapter reads it from model data | Bind identity at wrap time; reserved keys (CF-12) | Misconfigured integration code |
| B9 | Tool registered twice; the second registration silently replaces a vetted function | Unspecified | Reject duplicates (SEC-014) | — |
| B10 | Destructive tool registered without the flag | Default `False` fails open | Required argument (CF-16) | Developer mislabels it |
| B11 | Grant without path prefixes gives unrestricted filesystem access | `None` default | `None` ⇒ deny for path tools (CF-13) | — |
| B12 | Nested path in a list or dict argument escapes `path_args` | Possible | v1: only top-level path arguments; documented | Tool authors must comply |
| B13 (rev. 3) | Framework retry re-runs a tool after a post-execution failure | Observed with a naive adapter (3 executions) | In-tool `ToolException` conversion (D-26); `tool_call_id` guard (D-27); no Sentinel re-invocation (C1.7) | Untested retry mechanisms; new ids |
| B14 (rev. 3) | Two threads/tasks consume one decision | Possible without an atomic claim (observed with the racy control) | Atomic single-use claim (D-25) | Cross-process (out of scope) |
| B15 (rev. 3) | Interruption reported as not executed, or as a denial | Possible in a naive design | C1.6 interruption handling; re-raise | Outcome itself unknown |
| B16 (rev. 3) | Denied `Command` tool still routes or updates state | Not observed with Design B | Never return a `Command` on non-ALLOW (SEC-028) | — |
| B17 (rev. 3) | Middleware swaps in an original tool, or supplies an unwrapped one | Observed (C-02b A6, A8) | Documented as outside the boundary; coverage report (FR-025) | **Inherent** (trusted code) |
| B18 (rev. 3) | Framework-injected parameters reach the function unevaluated | Observed for `InjectedState` (C-02 B4) | Refuse all injected parameters except `InjectedToolCallId` (SEC-029) | Untested injection kinds refused by rule, not by test |

## 7. Duplicated responsibilities, missing contracts, unclear interfaces

**Duplicated:**
- Capability checks in the Tool-Abuse detector and in the policy engine. Resolution: remove the detector (CF-07).
- Path checks in the detector (PDF §3), policy and proxy. Resolution: one pure helper, used by policy (authoritative) and the proxy (re-check).
- Audit calls from several stages (PDF). Resolution: the pipeline is the only writer.
- `RESTRICTED_PATH` as both a finding code and a reason code. Acceptable; documented (CF-17).

**Missing contracts:**
- Tool metadata into policy (CF-07); `request_id` on `SecurityDecision` (CF-08); `outcome` on `PipelineResult` and `error` on `ToolResult` (CF-05).
- Post-execution audit failure (CF-09); output-filter failure (CF-14).
- Meaning of `allowed_path_prefixes=None` (CF-13); rules for relative paths.
- Audit read API (OD-04).
- Adapter identity binding (CF-12); async behaviour (CF-18); thread-safety guarantee (OD-08).
- Interaction between the policy's `Severity` threshold and multiple findings (tie-break, CF-03).

**Unclear interfaces:**
- `protect(workflow)`: what exactly is wrapped (CF-18).
- `register_agent` exists for "test/config seeding" (brief §6.7) but is part of the public API. Clarify whether it is a production API or a test helper. Recommendation: keep it public as the v1 way to configure agents, with the credential passed as `SecretStr` and stored only as a hash.

## 8. Proposed changes needing approval (no new components)

Rev. 2. The Inception IDs are kept in brackets for traceability.

| Change | Decision ID |
|---|---|
| `evaluate(request, context, findings, tool_spec)`; `ToolSpec` without callable; Tool-Abuse detector dropped | D-15 (CF-07) |
| `AuthorizedAction` + digest in `SecurityDecision`; the proxy executes only `decision.action`; internal proxy | D-07 (CF-08) |
| `PipelineResult` fields `execution` / `output_released` / `audit_complete` / `error_code` | D-14 (CF-05) |
| Post-execution audit failure returned truthfully, not raised | D-03 (CF-09) |
| Strict single validation; `arg_schema` required for all tools | D-08 (OD-09) |
| Filesystem contract C2: gateway canonicalisation, pure containment, proxy re-resolution, empty ⇒ deny, existing prefixes; path-constrained tools refused on Windows | D-05, D-18 (CF-13), D-21 — Approved (rev. 8) |
| `destructive` required; approval never executes | D-06 (CF-04, CF-16) |
| Identity from trusted application code; reserved keys | D-04 (CF-12) |
| `wrap_tools()` instead of `protect(graph)`; async fails closed *(rev. 2; async part superseded in rev. 3, see below)* | D-12 (CF-18) |
| Pipeline is sole orchestrator and audit writer | D-16 (OD-02) |
| `audit_events` table only; EXECUTION_STARTED / REQUEST_COMPLETED lifecycle | D-09 (OD-01) |
| Durable SQLite default | D-11 (OD-07) |
| `audit_events()` read API | D-17 (OD-04) |
| **Rev. 3, Approved:** Design B adapter scope and refusals | D-12 |
| **Rev. 3, Approved:** in-process `unknown` on interruption | D-14 amendment |
| **Rev. 3, Approved:** atomic single-use claim | D-25 |
| **Rev. 3, Approved:** post-execution failure handling in the adapter | D-26 |
| **Rev. 3, Approved:** at-most-once per `tool_call_id` | D-27 |
| *Rev. 3, Proposed:* diagnostics content; async entry; guard parameters. **Rev. 4: Approved** (D-31 default values still Proposed) | D-29, D-30, D-31 |
| **Rev. 4, Approved:** exact-action binding, canonical digest | D-07 |
| *Rev. 4, open (C-03 blockers):* result model, post-execution audit failure, return vs raise, credentials and reserved keys, destructive declaration, validation and schemas, policy authority, precedence, decision value casing (D-03, D-04, D-06, D-08, D-14 remainder, D-15, D-24c, D-24d, D-24i). **Rev. 5:** owner answers recorded. **Approved:** D-03, D-04 (`require_credentials=True`), D-06, D-08, D-14, D-24c, D-24d. **Partly approved:** D-15 (metadata authority), D-24i (lowercase values). **New open item:** Q-03c (pre-invocation unexpected-error representation) | decision record §12, §14.R4 |
| **Rev. 5:** C-03a implemented: `sentinel/action.py` (internal, not exported) | D-07 |
| **Rev. 6, Approved:** internal errors represented as `decision=None` + `INTERNAL_ERROR`, never `"deny"`; no `"error"` decision value | Q-03c |
| **Rev. 7, Approved:** operational refusals (invalid request, mismatch, path changed, already used, duplicate id, guard full) → `decision=None`; pre-execution audit failure keeps a reached policy decision; `deny` only for policy rows 1–5 | owner (§12 rev. 6) |
| **Rev. 7:** C-03 approved with `ToolGrant`, `RateLimit`, `CapabilityEnvelope`, `SecurityContext` moved to C-07; **blocked** by the unapproved, uninstalled Pydantic dependency | §8.6 rev. 6 |
