# Decision Record and Reconciled Contracts — Sentinel v1 (AI-DLC Phase 1.5)

| | |
|---|---|
| Phase | 1.5 — Decision lock and contract reconciliation |
| Date | 2026-10-28 |
| Decision owner | Soham Pasalkar |
| Status | **Approval is recorded per entry.** Approved so far (owner, 2026-10-28; verbatim words in §12): D-01, D-02 (provisional), D-13, D-22 (partial), D-23 for C-01, after the C-02/C-02b review, **D-12 (expanded), D-25, D-26, D-27, D-28 and the C1.6 amendment of D-14**; and at the final contract gate (rev. 3), **D-07, D-29, D-30, D-31**, plus requirement **FR-022** and the **C-17 → C-16 consolidation** (conditional, satisfied in `implementation_plan.md`); and in rev. 4, the owner's answers to §14: **D-03, D-04, D-06, D-08, D-14 (complete), D-24c, D-24d Approved; D-15 and D-24i partly approved**; interpretations for D-07, D-29, D-30, D-31 confirmed; **C-03a authorized** (full C-03 remains unauthorized); and in rev. 5, **Q-03c Approved (Option B, without an `"error"` decision value)**; and in rev. 6, **operational refusals are not policy decisions** and the **C-03 increment is approved with `ToolGrant` out of scope**, but **implementation is blocked** by an unapproved runtime dependency (Pydantic; §8.6 rev. 6); and in rev. 7, **NFR-002 (Pydantic part)** (C-03 then implemented and committed); and in rev. 8 (2026-11-08), **D-05, D-18 and D-21** (C-04 unblocked); and in rev. 9 (2026-11-08), **D-24b** (C-07 unblocked). Every other entry is *Proposed* (a recommendation ready for owner review) or *Pending* (needs information first). |
| Revision | Rev. 2 (2026-10-28): C-02 / C-02b findings reconciled. New contracts C3.5–C3.7, decisions D-25–D-31, §13. **Rev. 3 (2026-10-28): final contract gate before C-03.** D-07, D-29, D-30, D-31 approved; D-03, D-04, D-06, D-08, D-14 (remainder), D-15, D-24c, D-24d reviewed (§14); C-03 entry gate (§8.6). Earlier text is kept; superseded positions are marked, not deleted. **Rev. 4 (2026-10-28): owner answers to §14 recorded (§12, §14.R4); C-03a authorized; new open question Q-03c.** **Rev. 5 (2026-10-28): Q-03c resolved: internal errors are represented separately from policy decisions (C1.6, C1.8).** **Rev. 6 (2026-10-28): owner decision on operational refusals (C1.6 table); C-03 approved (ToolGrant excluded); blocker found: Pydantic not an approved or installed dependency.** **Rev. 7 (2026-10-28): NFR-002 Pydantic part approved (§12); C-03 implemented.** **Rev. 8 (2026-11-08): D-05, D-18, D-21 approved (§7 entries, §12); C-04 unblocked; D-21 clarified: the Windows restriction applies to path-constrained tools only.** **Rev. 9 (2026-11-08): D-24b approved (tool-level grants); C-07 interpretations recorded under D-24 (owner confirmation requested); C-07 unblocked.** |
| Supersedes | The active-register role of `open_decisions.md`. That file is kept unchanged as the Inception history, with a mapping to this record added at its top. |

## 0. How this record works

### 0.1 Source and status vocabulary

| Tag | Meaning |
|---|---|
| **EXISTING** | Stated in an original reference: the architecture PDF (`PDF §x`) or a diagram (`DIAG:<name>`) |
| **BRIEF** | A `[REC]` or `[ASSUMPTION]` in `SENTINEL_BUILD_BRIEF.md` (`Brief §x / Rn`). The brief says its RECs apply "unless the user rejects" them; this record still lists them for explicit confirmation |
| **INCEPTION** | A recommendation introduced in the Phase 1 documents (`CF-xx`, `OD-xx` in `open_decisions.md`) |
| **PHASE-1.5** | A refinement introduced in this record |
| **ASSUMPTION** | Believed true but not verified |

Decision status values: **Proposed**, **Pending**, **Approved**, **Rejected**. Only the owner moves an entry to Approved or Rejected. Rejected alternatives stay in the record with their reasoning.

### 0.2 Evidence read for this phase

- All seven Inception documents. Their contents were verified unchanged since they were written: modification times 20:30–20:40 match when they were written, and `git status` shows no other new files.
- `SENTINEL_BUILD_BRIEF.md`, the 13-page architecture PDF, and all 11 diagrams. All were read in full earlier in this session. Their modification times (2026-09-08 to 2026-10-28 20:15) predate that reading, so they have not changed since.
- No commands beyond read-only file inspection were run (§11).
- **Added in rev. 2 (C-02/C-02b finalization):** the two experiment reports, [`spike_framework_interception.md`](../02-construction/spike_framework_interception.md) (C-02, 97 checks) and [`spike_langchain_compatibility.md`](../02-construction/spike_langchain_compatibility.md) (C-02b, 120 checks), the spike READMEs, and the saved results and transcripts under `spikes/`. **Observed evidence** is cited as "C-02 …" or "C-02b …" and is always distinguished from **decisions**. The evidence comes from toy stand-ins for the gate and proxy, a scripted chat model, one framework version set (`langchain` 1.4.7, `langgraph` 1.2.18, `langchain-core` 1.7.1) and Python 3.11.14. It is evidence for that configuration, not a general guarantee.

### 0.3 Changes from Inception, at a glance

| Inception position | Phase 1.5 refinement | Why |
|---|---|---|
| `outcome` enum mixed execution and output delivery (CF-05) | Separate fields: `execution`, `output_released`, `audit_complete` (C1.6) | One enum could not say "executed, output withheld, audit incomplete" without ambiguity |
| Decision bound by `request_id` only (CF-08) | Bound to an `AuthorizedAction` **and** its SHA-256 digest (C1.4) | `request_id` alone does not prove the *action* is unchanged; nested argument dicts stay mutable inside frozen models |
| Paths canonicalised in policy and re-checked in the proxy (CF-13) | Canonicalised in the **gateway** (before policy), proxy **re-resolves and compares** (C2) | Keeps `evaluate` free of I/O (determinism, SEC-019), and the proxy detects symlink changes between check and use |
| Post-execution audit failure: raise `AuditUnavailable` (CF-09 option B) | `evaluate_request` **returns** a result marked `audit_complete=False`, output withheld; adapters raise (C1.7) | One rule: the pipeline never raises for request outcomes. Raising would also hide the `execution` status from the caller |
| Audit events TOOL_EXECUTED / TOOL_BLOCKED / ERROR as terminal events | Add a mandatory pre-invocation **EXECUTION_STARTED**; single terminal **REQUEST_COMPLETED** (C4.3) | Lets anyone reading the audit log tell "never invoked" from "invoked, outcome unknown" after a crash |
| `arg_schema` required only for path tools (OD-09 item 4 open) | Recommend `arg_schema` **required for every tool** (D-08) | Strict validation, the action digest and audit serialisation all need a schema |
| Default `db_url`: no default, explicit required (OD-07) | Recommend a **durable SQLite file by default** (D-11) | Matches the owner's stated preference. The in-memory alternative is kept as Rejected history |
| `protect(graph)` narrowed (CF-18) | Recommend replacing it with `wrap_tools(...)` (D-12) | The name `protect(graph)` itself overpromises |

### 0.4 Changes from the C-02 / C-02b review (rev. 2, owner-approved 2026-10-28)

| Earlier position (kept in this file as history where marked) | Rev. 2 position | Observed evidence | Decision |
|---|---|---|---|
| D-12 pending: `wrap_tools` for LangGraph, sync only; async path "fails closed" (C3.2, SEC-016) | `wrap_tools` returns replacement tools (Design B) for **sync function tools, async-native tools through async entry points, and `Command`-returning tools** whose only injected parameter is `InjectedToolCallId`; unsupported patterns are refused; unwrapped, middleware-supplied and provider built-in tools are explicitly **not** protected (C3.2, C3.3) | C-02 B1–B8 (52/52); C-02b A, B, C (120/120) | **D-12 Approved** |
| C1.6: `unknown` is "not produced by the in-process pipeline in v1" | `unknown` **is** produced in-process when a `BaseException` (e.g. cancellation) escapes after execution begins; it is recorded best-effort and the exception is re-raised, never converted to a denial (C1.6, C1.7) | C-02b B6: cancelled async tool, state `interrupted`, counter stayed 1 | **D-14 amended (Approved)** |
| C1.4 rule: a decision is bound to one action (single use implied) | Claiming is **atomic and single-use across threads and asyncio tasks** (C1.4 rule 5) | C-02b B5/D3: 100/100 trials × 8 contenders executed once, per mode; racy control duplicated in 50/50 | **D-25 Approved** |
| C1.8 / D-24d: adapters raise `ActionDenied`, `ApprovalRequired`, `ToolExecutionError` into the framework | The framework adapter surfaces non-ALLOW and post-execution failures as **fixed-text in-tool `ToolException`s**; internal diagnostics go to the audit (C1.8, C3.5) | C-02 E6, C-02b matrix: a naive adapter that lets the exception escape was **re-executed 3 times** by `RetryPolicy` and by `ToolRetryMiddleware`; conversion gave 1 execution in every row | **D-26 Approved** |
| (none) | **At-most-once per `tool_call_id`** as defense in depth, with the explicit statement that it does **not** stop a new call with a new id (C3.5 rule 8) | C-02b: 1 execution in every guarded row | **D-27 Approved** |
| Ruff excluded only the brief and `docs` (C-01) | Ruff also excludes `spikes/` via configuration; file-wide `# ruff: noqa` headers removed | C-02, C-02b: 200 lint errors appeared when the spike files entered the tree | **D-28 Approved** |

Observed evidence supports each rule. It does not make a guarantee wider than the tested configuration. See C3.6 for the explicit limits.

---

## 1. Core execution contract (C1)

### C1.1 Request identity

- The pipeline assigns `request_id` (UUID4, string form) and `received_at` (timezone-aware UTC) **before** any validation. Every audit event and result for that call carries this `request_id`. [EXISTING PDF §4.1; INCEPTION FR-002]
- `session_id` is supplied by trusted application code and is used **only for correlation** in v1. It has no security role, and rate limits (M4) are keyed by `agent_id`. [PHASE-1.5; INCEPTION T-14]

### C1.2 Trusted agent identity and capability grants

- `agent_id` is **trusted input from application code**. Both public entry points take it from trusted code, never from model output:
  - `SentinelClient.evaluate_request(raw)`: the documented contract is that `raw` is constructed by application code. The model's tool-call payload maps only to `raw["tool"]` and `raw["arguments"]`.
  - Framework adapters: `agent_id` is a required parameter at wrap time (C3.2).
- `raw["arguments"]` must not contain the reserved keys `agent_id`, `session_id`, `auth_token`, `request_id`, `tool_call_id` → refused: `decision=None`, `error_code="INVALID_REQUEST"` *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*. (`tool_call_id` added in rev. 2.)
- **Rev. 2:** `raw` may carry an optional top-level `tool_call_id` (str), supplied by a framework adapter from the framework's tool call, never from model-controlled `arguments`. It is used **only** by the at-most-once guard (C3.5 rule 8). It is not part of the evaluated action or its digest (D-07), and it has no authorization meaning. Without it, the guard does not apply. **Rev. 3 (D-31 Approved):** a guard entry binds the trusted `agent_id`, the trusted `session_id` and the `tool_call_id`. A request that carries a `tool_call_id` **without** a `session_id` is refused with `decision=None`, `error_code="INVALID_REQUEST"` *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")* (fail closed: the guard cannot bind it). This is a derived rule; see §14.
- Credentials are optional per agent (PDF "if used"). If an agent has a stored credential hash, the request must present a matching `auth_token` (compared as SHA-256 digests with `hmac.compare_digest`). `SecurityPolicy.require_credentials: bool = False` lets a deployment require credentials for all agents. [BRIEF §6.2; INCEPTION CF-12]
- **Rev. 4 (D-04 Approved; owner choice Q-04a = B):** credentials are configured **per agent**, and `require_credentials` defaults to **`True`**. An agent without a configured credential is therefore not authorized unless the deployment explicitly sets `require_credentials=False`. Mandatory signed tokens are **not** a v1 requirement. Reserved identity-related keys in `arguments` are **rejected**, never stripped (Q-04b = A). *(The rev. 1–3 default `False` is superseded.)*
- Grants: `CapabilityEnvelope{agent_id, grants: tuple[ToolGrant, ...]}`; `ToolGrant{tool, allowed_path_prefixes: tuple[str, ...] = (), rate_limit: RateLimit | None}`. ALLOW is reachable only for a tool with a grant (default deny). [BRIEF R5]
- **Rev. 9 (D-24b Approved):** a `ToolGrant` covers the **whole registered tool, by its registered name**. It establishes that the agent may use that tool; it is **not** an ALLOW. Every invocation is still evaluated by policy (C1.5), and the exact action stays bound by `AuthorizedAction` and its digest (C1.4). There are no sub-action, operation-level or argument-level grants in v1.

### C1.3 Tool metadata required by policy

`ToolSpec` (metadata only; the registry holds the callable beside it, never inside it):

| Field | Type | Rule |
|---|---|---|
| `name` | `str` | Unique in the registry; re-registration is rejected |
| `arg_schema` | Pydantic model class | **Required** (D-08). Must forbid extra fields; validated in strict mode |
| `destructive` | `bool` | **Required keyword**, no default (D-06) |
| `path_args` | `tuple[str, ...]` | Default `()`. Each name must be a top-level `str` field of `arg_schema` |

Policy receives the `ToolSpec` explicitly: `PolicyEngine.evaluate(request, context, findings, tool_spec) -> SecurityDecision`. [INCEPTION CF-07]

**Rev. 4:**
- `destructive` required, no default (D-06 Approved).
- `arg_schema` required for every tool; validation is strict with no type coercion; unexpected argument keys are rejected (D-08 Approved).
- **The registry is the authoritative source of security-relevant tool metadata; policy evaluates it; no detector is an allow/deny authority** (D-15, partly approved).
- *Still open (D-15 remainder, not a C-03 or C-03a blocker):* whether the metadata reaches policy as the explicit `tool_spec` parameter shown above or by a registry lookup inside policy; and whether an informational-only Tool-Abuse detector exists in v1.

### C1.4 The exact action a decision authorizes

```text
AuthorizedAction (frozen)
  request_id : str
  agent_id   : str
  tool       : str
  arguments  : validated values, path arguments replaced by canonical absolute paths
  digest     : sha256 hex of the canonical JSON encoding of
               {"request_id","agent_id","tool","arguments"}  (sorted keys, no whitespace, UTF-8)

SecurityDecision (frozen)
  request_id, decision, reason, policy_version, finding_codes, risk_score?
  action     : AuthorizedAction      # the one action this decision covers
```

Rules:

1. The gateway builds the `AuthorizedAction` candidate (validated and canonicalised arguments) **before** policy. Policy evaluates exactly that object and embeds it in the decision.
2. The proxy executes **only** `decision.action`, and only if all of the following hold:
   - `decision.decision is Decision.ALLOW`,
   - `decision.request_id == decision.action.request_id == request.request_id`,
   - the digest recomputed from `decision.action` equals `decision.action.digest`,
   - every path argument passes the proxy re-resolution check (C2.5).

   Otherwise it does not invoke the tool. **Rev. 6:** the refused attempt has `decision=None` with `error_code="ACTION_MISMATCH"` (binding or digest) or `error_code="RESTRICTED_PATH"` (path changed after authorization), and `execution="not_started"`. *(Rev. 2–5: "The **effective** decision becomes DENY with reason …", superseded: these are operational refusals, not policy decisions.)* *(Rev. 1–4 also listed "`INTERNAL_ERROR` (registry lookup)" here.)* **Rev. 5 (Q-03c):** an unexpected internal error in the proxy's pre-invocation steps, such as a registry lookup failure, is **not** a denial. It is represented per C1.8: `decision=None`, `error_code="INTERNAL_ERROR"`, `execution="not_started"`. The DECISION audit event still shows policy's `allow`; *(rev. 2–5: "REQUEST_COMPLETED shows the enforced `deny`")* **rev. 6:** REQUEST_COMPLETED records `decision` NULL with the refusal's error code and `execution="not_started"`.
3. The tool is called as `fn(**deepcopy(action.arguments))`. A tool that mutates its arguments therefore cannot change what was audited.
4. **Limit, stated plainly:** the digest is an integrity check against accidental divergence and mutation inside the process. It is **not** a cryptographic authorization token. Code in the same process can forge a decision (C6).
5. **Atomic single-use claim (rev. 2, D-25 Approved).** A decision authorizes **at most one** invocation.
   - Before setting `entered`, the proxy *claims* the decision. The claim checks that the decision is unclaimed and records it as claimed, as **one atomic operation**: under a lock that is safe across threads, with **no `await` and no I/O** between the check and the mark.
   - The same claim implementation serves the sync and async execution paths.
   - Any second claim of the same decision (sequential replay, concurrent thread or concurrent task) does not invoke the tool. The refused attempt has `decision=None`, `error_code="DECISION_ALREADY_USED"`, `execution="not_started"` *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*.
   - Claimed decisions are tracked per process, for the life of the pipeline. A decision is never claimable by another process. Persistence of claims is out of scope.
   - *Observed (C-02b B5/D3):* 8 contenders × 100 trials, threads and asyncio separately, executed exactly once per trial with 700 refusals. A deliberately non-atomic control duplicated execution in 50/50 trials.
   - *Rev. 2 note (superseded in rev. 3):* "D-07 (the digest binding in rules 1–4) is still **Proposed**." **Rev. 3:** D-07 is **Approved** (see rule 6).

6. **Exact-action binding and canonical encoding (rev. 3, D-07 Approved).** A decision authorizes **one exact, validated action**.
   - **Bound fields:** request identity (`request_id`, `agent_id`), tool identity (the registered tool name, which the registry keeps unique and non-replaceable for the pipeline's lifetime: C1.3, SEC-014), and canonical arguments, including **resolved path information**. Every argument named in `path_args` carries its canonical absolute path (C2.4); the digest therefore covers the resolved paths, and the proxy's re-resolution (C2.7) compares against them.
   - **Excluded:** `tool_call_id`. It is used only by the duplicate-execution guard (C3.5 rule 8, D-31). Two requests that differ only in `tool_call_id` have the same action content (and differ in `request_id`).
   - **Canonical encoding:** `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)`, encoded as UTF-8, over `{"request_id", "agent_id", "tool", "arguments"}`; digest = SHA-256 hex. Validated argument values must be **JSON-native**: `str`, `int`, finite `float`, `bool`, `None`, `list`, and `dict` with `str` keys. Any other value type is rejected (`INVALID_REQUEST`) and is never encoded with `repr` or a fallback serializer. No Unicode normalization is applied, so different code-point sequences are different actions.
   - **Properties required by D-07:** the digest is **deterministic across processes and runs** (no dependence on hash randomization, dict insertion order or object identity), and it **changes when any nested argument value changes**. All argument values are covered, so "security-relevant" is never decided case by case.
   - **Mismatch:** an attempt to execute an action whose recomputed digest, tool or `request_id` differs from the approved action is rejected (rule 2: `decision=None`, `error_code="ACTION_MISMATCH"`, not executed *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*).
   - Production tests: AT-23, AT-28–AT-31.

[PHASE-1.5, refining INCEPTION CF-08 and OD-09; rule 5 added in rev. 2; rule 6 added in rev. 3]

### C1.5 Policy outcomes

| Decision | Meaning in v1 | Execution |
|---|---|---|
| `ALLOW` | Every check passed for this exact action | Proxy may execute after the C1.4 checks |
| `DENY` | Any failed check, or any failure before execution | **Never executed** |
| `REQUIRE_APPROVAL` | Granted destructive tool while `require_approval_for_destructive=True` | **Never executed in v1.** There is no approval or replay mechanism; a retry is a new request with a new decision |

Evaluation order: first matching row wins. [BRIEF R4; INCEPTION CF-03]

1. Not authorized → DENY `UNAUTHORIZED_AGENT`
2. Tool not granted → DENY `UNAUTHORIZED_TOOL`
3. Path constraint fails (including an empty prefix list for a path tool) → DENY `RESTRICTED_PATH`; any other grant constraint → DENY `CAPABILITY_EXCEEDED`
4. Highest finding severity ≥ `deny_at_severity` → DENY with that finding's code (ties broken by code order; exact rule below)
5. Rate limit exceeded (M4) → DENY `RATE_LIMIT_EXCEEDED`
6. Destructive and approval required → REQUIRE_APPROVAL
7. Otherwise → ALLOW

Enum values: `Decision.ALLOW = "allow"`, `DENY = "deny"`, `REQUIRE_APPROVAL = "require_approval"`. No `RESTRICT` in v1. [BRIEF R9]

**Rev. 4 (D-24c, D-24i Approved): exact order and tie-break.**
- **Order:** the brief's §6.4 order, rows 1–7 above. Evaluation stops at the first matching row.
- **Inputs that never affect the outcome:** the risk score has no row (informational only, brief R7).
- **Row 3 tie-break:** if both a path constraint and another grant constraint fail, the reason is `RESTRICTED_PATH`, because path is checked first.
- **Row 4 tie-break:** let F = the findings with `severity ≥ deny_at_severity`, where `deny_at_severity = HIGH` by default.
  - If F is non-empty, the reason is the `code` of the finding in F with the **highest severity**.
  - Among equal severities, the reason is the **lexicographically smallest `code`**, comparing Unicode code points (Python `str` ordering).
  - The input order of findings never matters.
  - `finding_codes` on the decision lists every finding's code, sorted the same way: by descending severity, then ascending code.
- **Serialization:** decision values serialize as lowercase strings (`"allow"`, `"deny"`, `"require_approval"`); Q-24i.

### C1.6 Execution outcomes (result model)

```text
PipelineResult (frozen)
  request_id      : str
  decision        : Decision | None # the EFFECTIVE policy/enforcement decision; None = no decision because of an internal error (rev. 5, Q-03c)
  reason          : str             # stable reason code, never free text from exceptions
  execution       : "not_started" | "succeeded" | "failed" | "unknown"
  output_released : bool            # True only if the filtered output is returned to the caller
  output          : Any | None      # None unless output_released
  audit_complete  : bool            # True only if every required audit event was committed
  error_code      : str | None      # e.g. AUDIT_UNAVAILABLE, TOOL_FAILED, OUTPUT_FILTER_FAILED, ACTION_MISMATCH
```

| `execution` | Definition | When the pipeline reports it |
|---|---|---|
| `not_started` | The tool function was **not entered**. This is guaranteed: the proxy sets an `entered` flag immediately before the call | DENY, REQUIRE_APPROVAL, any failure before invocation, binding or path re-check failure |
| `succeeded` | The function returned normally | Normal ALLOW path, **including** when the output was later withheld or the post-execution audit failed |
| `failed` | The function was entered and raised an `Exception`. Side effects may have happened partially | Tool error |
| `unknown` | The function was entered, and whether or how it completed cannot be established | **Rev. 2 (D-14 amendment, Approved):** produced **in-process** when a `BaseException` that is not an `Exception` (e.g. `asyncio.CancelledError`, `KeyboardInterrupt`, `SystemExit`) escapes **after** `entered` is set. Also the state an audit reader must assign to a request with `EXECUTION_STARTED` but no `REQUEST_COMPLETED` (crash, kill, post-execution audit loss; C4.4) |

*Superseded rev. 1 text (kept as history):* "`unknown` … **Not produced by the in-process pipeline in v1** … Reserved for future timeouts or cancellation." C-02b B6 showed cancellation reaches this state in-process.

**Interruption handling (rev. 2):**
1. The proxy records the request as `interrupted`.
2. The pipeline makes **one best-effort** attempt to commit `REQUEST_COMPLETED` with `execution="unknown"` and `detail.interruption=<exception type name>`. The attempt is synchronous and bounded. Any error from it is suppressed and logged, never raised in place of the original exception.
3. The original `BaseException` is **re-raised unchanged**.

Because the exception propagates, the caller receives **no** `PipelineResult` in this case. The unknown outcome is visible in the audit: from the best-effort record, or, if that write failed, from the C4.4 rule. `PipelineResult.execution == "unknown"` remains a legal value; v1 code paths do not *return* it.

**Not established by evidence:** whether a best-effort audit write can complete *during* cancellation of an async task. The spikes recorded only proxy state, so this is a production test (AT-10).

**Rev. 6 (owner decision on operational refusals) — authoritative; supersedes every earlier "effective DENY" for these codes:**

> The `decision` field represents an actual, applicable policy decision. It must not be used merely to indicate that execution was refused.

| Situation | `decision` | `error_code` (and `reason`) | Execution |
|---|---|---|---|
| Invalid request | `None` | `INVALID_REQUEST` | not started |
| Unexpected internal evaluation error (Q-03c) | `None` | `INTERNAL_ERROR` | not started |
| Audit store unavailable **before** execution | the actual policy decision **if one was reached**, otherwise `None` | `AUDIT_UNAVAILABLE` | not started: never executes unless the required pre-execution audit write succeeded |
| Action mismatch (binding or digest) | `None` | `ACTION_MISMATCH` | not started |
| Path changed after authorization (C2.7) | `None` | `RESTRICTED_PATH` (existing code preserved) | not started |
| Decision already used (D-25) | `None` | `DECISION_ALREADY_USED` | not started |
| Duplicate tool-call ID (D-27) | `None` | `DUPLICATE_TOOL_CALL` | not started |
| Guard capacity exhausted (D-31) | `None` | `GUARD_CAPACITY_EXHAUSTED` | not started |
| Closing audit write fails **after** execution | the actual policy decision (`allow`) | `AUDIT_UNAVAILABLE` | truthful (`succeeded`/`failed`); `audit_complete=False`; output withheld |
| Policy denial (C1.5 rows 1–5) | `deny` | the policy reason | not started |
| Approval required (C1.5 row 6) | `require_approval` | the policy reason | not started |

- Every operational refusal keeps its specific error code and never executes the tool.
- **No operational refusal is a policy denial.** `decision="deny"` occurs **only** for C1.5 rows 1–5.
- `reason` carries the same stable code as `error_code` when `decision` is `None` (the rev. 5 Q-03c convention, extended).
- Note on `RESTRICTED_PATH`: the same code names a policy denial (C1.5 row 3, `decision="deny"`) and the path-changed refusal (`decision=None`). The two are distinguished by `decision`. The owner's instruction to "preserve its specific error code" keeps the existing code; see §14.R6.

**Rev. 5 (Q-03c Approved): internal errors are not decisions.**
- An unexpected internal failure that prevents a policy or enforcement decision is represented with `decision=None`, **never** `"deny"`.
- The serialized decision value set stays exactly `{"allow", "deny", "require_approval"}`; there is no `"error"` value.
- Such a failure carries `error_code="INTERNAL_ERROR"` and `reason="INTERNAL_ERROR"` (the existing stable code). If it happens before execution starts: `execution="not_started"`, `output_released=False`, `output=None`.
- No separate result-kind field is added: `decision=None` together with `error_code="INTERNAL_ERROR"` identifies the case unambiguously, and the D-14 field set stays as approved. The owner allowed such a field "if needed"; see §14.R5.
- An unexpected internal error **after** execution started keeps the decision that was enforced (`allow`), reports `execution` truthfully, withholds the output, and sets `error_code="INTERNAL_ERROR"`. It is never turned into a denial (D-03).

**Rev. 4 (D-14 complete, D-03 Approved):** the result model is the four separate fields above (`execution`, `output_released`, `audit_complete`, `error_code`; Q-14 = A). If the closing audit write fails after the tool ran, the output is **withheld** from the direct caller (Q-03a = A).

**Invariants:**
- `decision != ALLOW ⇒ execution == "not_started"`.
- `execution != "not_started"` is **never** paired with a DENY decision. A failure after invocation never turns into a DENY.
- **Rev. 2:** an interruption after `entered` is **never** reported as `not_started`, never converted to DENY or REQUIRE_APPROVAL, and never swallowed. The `BaseException` always propagates.
- `output_released ⇒ execution == "succeeded" ∧ audit_complete`.
- **Rev. 5 (Q-03c):**
  - *Rev. 5:* `decision is None ⇒ error_code == "INTERNAL_ERROR" ∧ …`. **Rev. 6:** `decision is None ⇒ error_code ∈ {INVALID_REQUEST, INTERNAL_ERROR, AUDIT_UNAVAILABLE, ACTION_MISMATCH, RESTRICTED_PATH, DECISION_ALREADY_USED, DUPLICATE_TOOL_CALL, GUARD_CAPACITY_EXHAUSTED} ∧ execution == "not_started" ∧ ¬output_released`, so it is fail closed: no execution.
  - **Rev. 6:** `decision == DENY ⇒ reason is a C1.5 policy reason` (`UNAUTHORIZED_AGENT`, `UNAUTHORIZED_TOOL`, `RESTRICTED_PATH`, `CAPABILITY_EXCEEDED`, a finding code, `RATE_LIMIT_EXCEEDED`), and `error_code` is not an operational-refusal code. **Rev. 7 correction (wording error, owner table prevails):** `AUDIT_UNAVAILABLE` *is* allowed with a preserved policy decision (`deny`, `require_approval` or `allow`). `INTERNAL_ERROR` is allowed only with `None` or with `allow` after execution started.
  - **Rev. 6:** `decision == ALLOW` does **not** imply execution. An allowed request can still be refused operationally before invocation (`AUDIT_UNAVAILABLE` keeps `allow`; the proxy-stage refusals report `None`).
  - `error_code == "INTERNAL_ERROR" ⇒ decision ≠ DENY`: an internal error is never reported as a policy denial.
  - `decision ∈ {None, ALLOW, DENY, REQUIRE_APPROVAL}`, and only the three non-`None` values are ever serialized as decision strings.

### C1.7 Audit behaviour (pre- and post-execution)

| Phase | Events (C4.3) | On write failure |
|---|---|---|
| Pre-execution | REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING×n, DECISION, EXECUTION_STARTED (ALLOW only) | Tool **not** invoked. *(Rev. 2–5: "Effective decision DENY `AUDIT_UNAVAILABLE`".)* **Rev. 6:** `decision` = the actual policy decision if one was reached (i.e. the write that failed was DECISION or EXECUTION_STARTED), otherwise `None`; `error_code="AUDIT_UNAVAILABLE"`; `execution="not_started"`; `audit_complete=False`. Each event is **committed** before the next stage runs |
| Post-execution | OUTPUT_FILTERED / OUTPUT_WITHHELD (if applicable), REQUEST_COMPLETED | Decision stays ALLOW; `execution` reports the truth (`succeeded`/`failed`); `output_released=False`; `audit_complete=False`; `error_code="AUDIT_UNAVAILABLE"`; best-effort record to the Python `logging` module (masked). The side effect is **not** undone, and the result says so |
| Non-ALLOW terminal | REQUEST_COMPLETED | Decision stays DENY/REQUIRE_APPROVAL; `audit_complete=False` |
| **Interrupted (rev. 2)** | REQUEST_COMPLETED(`execution="unknown"`), best effort | Suppressed; the original `BaseException` propagates; the C4.4 rule classifies the request as unknown |

**No re-execution after post-invocation failures (rev. 2, D-26 Approved).** Once a request's claim has been made, no Sentinel code path invokes the tool again for that request. This holds whatever happens afterwards: an output-filter failure, an audit write failure, a result-mapping failure, or an adapter error. Sentinel may retry an *audit write* (bounded); it never retries the *tool*. A framework-level retry creates a **new** request that is evaluated and claimed afresh. Preventing such a repeat depends on the adapter rules in C3.5 (rules 4 and 8), which the C-02b retry matrix showed to be effective in the tested configuration. It is not guaranteed for retry mechanisms outside that configuration.

[BRIEF R12; INCEPTION CF-09 option B, refined: the pipeline returns instead of raising]

### C1.8 Error handling and safe failure

- `SentinelClient.evaluate_request` **returns** a `PipelineResult` for every request outcome. It raises only for misuse of the API, such as a non-mapping `raw` argument, and lets `BaseException` (e.g. `KeyboardInterrupt`) propagate. [BRIEF R3; PHASE-1.5]
- **Rev. 4 (D-03, D-24d Approved; owner Q-03b):** for **handled** execution and audit failures, `evaluate_request` returns a structured result. It does not raise merely because a failure occurred after execution started. **Unexpected programming errors must not be falsely represented as policy denials.**
- *Rev. 4:* "Open, Q-03c …". **Rev. 5: resolved** (owner, Option B; §12, §14.R5).
- *Rev. 1–4 text (superseded):* "Any `Exception` in a security-critical stage **before invocation** (gateway, identity, detector, policy, registry lookup, proxy checks) → DENY `INTERNAL_ERROR`, `execution="not_started"`."
- **Rev. 5 (Q-03c Approved):** any unexpected `Exception` in a security-critical stage **before invocation** (gateway, identity, detector, policy, registry lookup, proxy checks) produces:
  - `decision=None` (not `"deny"`); `reason="INTERNAL_ERROR"`; `error_code="INTERNAL_ERROR"`;
  - `execution="not_started"`; `output_released=False`.

  It **fails closed**: the tool is never invoked. When possible the audit records an ERROR event with the D-29 structured diagnostics (never raw message text), and a `REQUEST_COMPLETED` with `decision` NULL, `reason="INTERNAL_ERROR"`, `execution="not_started"`. Anticipated, handled conditions keep their own codes: `INVALID_REQUEST`, `AUDIT_UNAVAILABLE`, `ACTION_MISMATCH`, `RESTRICTED_PATH`, `DECISION_ALREADY_USED`, `DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED`. Q-03c does not reclassify them; see §14.R5 for the open consistency question. **Rev. 6:** reclassified by the owner. They are operational refusals with `decision=None` (or, for `AUDIT_UNAVAILABLE`, the policy decision if one was reached). See the C1.6 rev. 6 table.
- **Rev. 5 mappings for callers:**
  - The framework adapter returns the fixed text `"not executed: INTERNAL_ERROR"`. This is distinct from the policy-denial text `"blocked: <REASON>"`. **Rev. 6:** every operational refusal uses the same `"not executed: <ERROR_CODE>"` form, never `"blocked: …"`. It never exposes diagnostics, and nothing escapes into the framework (D-26).
  - Direct callers that opt into exceptions get a distinct `SentinelError` subclass (name settled in C-03), **never** `ActionDenied`. **Rev. 6:** the same applies to operational refusals. `ActionDenied` and `ApprovalRequired` are reserved for actual policy decisions.
- Tool `Exception` → `execution="failed"`, `error_code="TOOL_FAILED"`. *Rev. 1 text:* "Only the exception **type name** is recorded." **Rev. 2 (D-26 Approved):** the audit preserves **internal diagnostics**. **Rev. 3 (D-29 Approved):** the diagnostics are structured fields only: exception type (qualified class name), the module and function of the raising frame, the line number, the pipeline stage, `request_id`, tool name and `error_code`. **Not stored:** exception message text, traceback text, frame-local values, argument values, and absolute file-system paths. *v1 provides no opt-in to store message text* (see D-29). No document claims that heuristic masking alone prevents secret leakage.
- Output-filter `Exception` → `output_released=False`, `error_code="OUTPUT_FILTER_FAILED"`.
- **Rev. 2:** a `BaseException` after `entered` follows the C1.6 interruption handling (best-effort `unknown`, re-raise). A `BaseException` *before* `entered` propagates with `execution="not_started"`, and nothing was invoked.
- Reason codes and error codes are stable constants. No exception message, stack trace, SQL or file path reaches the result **or any model-visible text**.
- *Rev. 1 text (now scoped to direct callers):* "Adapters map results to exceptions: `ActionDenied` (DENY), `ApprovalRequired` (REQUIRE_APPROVAL), `ToolExecutionError(execution=…, audit_complete=…)` (ALLOW without released output). All are `SentinelError` subclasses."
  **Rev. 2 (D-26):** these exceptions remain available to **direct callers** of `evaluate_request` and to adapters that explicitly halt a run. The **framework tool adapter (C3)** must **not** raise them, or any other `Exception`, into the framework for request outcomes. It returns the fixed-text in-tool `ToolException` described in C3.5 rule 4, because an `Exception` escaping into the framework was observed to trigger retries that re-executed the tool (C-02 E6, C-02b §6).

---

## 2. Filesystem authorization contract (C2)

**Scope:** filesystem tools are in v1 (PDF example `read_file` under `/workspace`; brief quickstart). This contract authorizes **path arguments**. It is **not** filesystem isolation or sandboxing.

| # | Contract |
|---|---|
| C2.1 Explicit grants | A grant for a tool with non-empty `path_args` must list `allowed_path_prefixes`. Each prefix must be absolute, must exist and must be a directory **when the grant is registered**. Prefixes are canonicalised once at registration with `os.path.realpath(prefix, strict=True)`; a failure raises `ConfigurationError`. |
| C2.2 Empty or missing | An empty prefix list for a path tool → DENY `RESTRICTED_PATH` on every call. Registration logs a warning. There is **no implicit unrestricted access**. Unrestricted access requires an explicit `("/",)`, which is logged at registration (D-05). |
| C2.3 Request path validation (gateway) | The value must be `str`, non-empty, contain no NUL, and be **absolute**. Relative paths and `~` are rejected as `INVALID_REQUEST`; nothing is expanded. |
| C2.4 Canonical resolution (gateway, before policy) | `canonical = os.path.realpath(path, strict=False)`. This resolves `..` and every symlink in the existing part of the path; a non-existent leaf is allowed (write tools). The canonical path replaces the original in the `AuthorizedAction`, and the original is kept (masked) in the REQUEST_RECEIVED event only. |
| C2.5 Containment (policy, pure) | Allowed iff `PurePosixPath(canonical)` equals or is under (`is_relative_to`, comparing whole path components) at least one canonical prefix. String-prefix comparison is never used. The prefix directory itself counts as contained. |
| C2.6 Path passed to the tool | Exactly `action.arguments[name]`, the canonical absolute path. |
| C2.7 Proxy re-resolution | Immediately before invocation the proxy recomputes `os.path.realpath(canonical)`. If the result differs (a component became a symlink since the check) or falls outside the prefixes, the tool is not invoked (`execution="not_started"`, `error_code="RESTRICTED_PATH"`; **rev. 6:** `decision=None`, an operational refusal). |
| C2.8 Same function | Containment (C2.5) is one pure function used by policy and by the proxy re-check. |

**Limitations to document (not claimed as enforced):**

| Limitation | Effect |
|---|---|
| TOCTOU window between proxy re-resolution and the tool's `open()` | A concurrent symlink swap can still redirect the access. Kernel-level containment (`openat2` + `RESOLVE_BENEATH`) is Linux-only and out of v1 |
| **Hard links** | A hard link inside a prefix to a file outside is indistinguishable by path. Mitigation: do not grant tools that can create links in directories that read tools use |
| Paths the tool derives internally, and paths nested in lists or dicts | Not checked. `path_args` covers top-level string fields only |
| Case-insensitive filesystems (macOS default) | A path whose case differs from the prefix fails closed (denied) |
| Mount points, bind mounts, network filesystems | Containment is lexical after resolution, not a mount boundary |
| Windows | Unsupported for path-constrained tools. Registering one on Windows raises `ConfigurationError` (D-21) |

---

## 3. Identity and framework integration contract (C3)

### C3.1 Identity supply
Covered by C1.2. In short: identity comes from application code (the `raw` dict built by the application, or the adapter's `agent_id` parameter). Model output can never set it.

### C3.2 Interception: Design B replacement tools (D-12 Approved, expanded in rev. 2)

```text
wrap_tools(
    tools, *, client: SentinelClient, agent_id: str, session_id: str | None = None,
    metadata: Mapping[str, ToolMetadata]          # destructive, path_args per tool (C1.3)
) -> list[langchain_core.tools.StructuredTool]
```

Module placement (`sentinel.integrations.langchain`, because the adapter depends only on `langchain-core` tool objects, vs. `…langgraph`) is settled at C-16. The signature is the tested shape; parameter names may be refined at C-16 without changing the contract.

- Each input tool is **replaced**, not modified. Its original callable (`.func` and/or `.coroutine`) is registered with Sentinel and becomes reachable **only through the proxy**. The returned objects keep the original name, description, argument schema and sync/async shape.
- `agent_id` (and `session_id`) are bound at wrap time from trusted code (C1.2). The model can never set them.

**Supported v1 tool patterns (D-12):**

| Pattern | Entry points | Evidence (observed) |
|---|---|---|
| Synchronous function tools (`@tool`, `StructuredTool` with `.func`) | Framework sync and async entry points | C-02 B1–B8; C-02b A1–A3, D4–D5 |
| Async-native tools (`StructuredTool` with `.coroutine` only) | **Async** entry points only | C-02b B1–B3, D4–D5 |
| `Command`-returning tools (sync or async) whose **only** injected parameter is `InjectedToolCallId` | As for their sync/async kind | C-02b C1–C6 |
| Callers: `langchain.agents.create_agent` and LangGraph `ToolNode` given the returned tools | — | C-02 B8; C-02b A, B, C |

**Refused at wrap time (raise, never silently wrap):**

| Pattern | Reason |
|---|---|
| Tool not registered with Sentinel metadata | No `destructive`/schema metadata (C1.3) |
| Provider built-in tools (`dict` tool specs) | Execute on the provider's side; cannot be intercepted in-process |
| Class-based `BaseTool` without `.func`/`.coroutine` | No original callable to relocate behind the proxy |
| Any injected parameter other than `InjectedToolCallId` (`InjectedState`, `InjectedStore`, `ToolRuntime`, …) | Framework-supplied values would reach the function without being evaluated. Only `InjectedState` was tested (C-02 B4h, C-02b C1–C2); the others are refused by the same schema-difference rule |

A **sync** entry into an **async-only** tool is rejected by the framework (`NotImplementedError`) before the adapter is reached: nothing executes and no Sentinel decision exists (C-02b B4, D4–D5). That is a framework rejection, not a Sentinel decision, and is reported as such.

*Rev. 1 text (superseded, kept as history):* "`sentinel.integrations.langgraph.wrap_tools(tools, *, client, agent_id, session_id=None)` … The async execution path of every returned object **raises `SentinelError` and never calls the original** until async support is designed (SEC-016). On DENY or REQUIRE_APPROVAL the wrapper raises `ActionDenied` / `ApprovalRequired` …". Superseded by the D-12 expansion (async-native) and by D-26 (no exceptions raised into the framework).

### C3.3 The guarantee, narrowed (rev. 2)

> **Guaranteed (by design, verified in the spikes for the tested configuration, and to be re-verified by production tests):** every invocation of a tool object **returned by `wrap_tools`**, through any entry point the framework supports for that tool's kind, passes through Sentinel's evaluation before the original function can run. The original runs only inside the proxy, only for an ALLOW decision bound to the exact evaluated action, and at most once per decision.
>
> **Not guaranteed, and never claimed:**
> - tools that were not wrapped;
> - **tools supplied by middleware** (e.g. an `AgentMiddleware.tools` attribute);
> - **provider built-in tools**;
> - references to an original tool or function kept elsewhere, and **trusted code that substitutes the original** (C-02b A8: middleware swapped in an original tool and it ran unevaluated);
> - graph nodes or application code calling functions directly;
> - **downstream effects of an allowed tool's `Command`** (routing, state updates);
> - **a new call with a new `tool_call_id`**, which is a new, separately evaluated request;
> - framework APIs, versions and tool patterns outside the tested set (C3.6);
> - anything that happens inside the model.

*Rev. 1 text:* "**Guaranteed:** every invocation … through its synchronous execution path … **Not guaranteed:** … async execution (which fails closed) …". The async exclusion is superseded by D-12.

The PDF/brief API `SentinelClient(policy).protect(workflow)` is **not** offered in v1, because it implies graph-wide coverage that cannot be enforced (D-12).

### C3.4 LangGraph feasibility experiment — original specification (history)

> **Rev. 2 status:** executed as **C-02** (`spike_framework_interception.md`). It was extended by **C-02b** (`spike_langchain_compatibility.md`: `create_agent`, async-native tools, `Command` tools, invariants). C-02 re-numbered its experiments; its §2.1 maps them to the E1–E8 below. E1 and E2 passed, so the stop condition was not triggered. The specification below is kept unchanged as history.

| Item | Specification |
|---|---|
| Location | `spikes/langgraph_interception/`, outside `src/`, excluded from packaging, coverage and the main test run |
| Environment | Its own virtual environment (e.g. `spikes/langgraph_interception/.venv`, git-ignored), Python 3.11 or 3.12. Never the project dev venv |
| Installation | `pip install langgraph langchain-core` (latest at run time). Record `pip freeze` and the Python version in the report. Requires **owner approval** (D-12 prerequisite) |
| Network | Only for `pip install`. No LLM APIs, no API keys. Tool calls are produced by a scripted message (an AI message with prepared tool calls) or a framework-provided fake chat model |
| Stand-in gate | A ~20-line function `gate(tool_name, args) -> bool` with a spy-wrapped original function. No Sentinel product code |
| Timebox | ½ day, extendable to 1 day on owner approval |

| Exp. | Question | Procedure | Pass criterion |
|---|---|---|---|
| E1 | Can a wrapped tool deny so that the original is never entered? | Run a graph whose tool node gets one allowed and one denied call | Allowed spy = 1, denied spy = 0 |
| E2 | Are all invocation APIs of the wrapped tool covered? | Call `invoke`, `batch`, `stream` (where present), and run through the tool node | Each path either goes through the gate or fails closed; spy = 0 on deny |
| E3 | How does a raised denial surface? | Raise from the wrapper; inspect graph output under default and error-handling configurations | Both "error message to the model" and "halt the graph" are achievable, or the limits are documented |
| E4 | Async path | `await tool.ainvoke(...)` on the wrapped tool; run the graph with `ainvoke` | Wrapper can force a raise without calling the original (spy = 0) |
| E5 | Parallel tool calls | One AI message with ≥3 tool calls; log thread and task identity in the spy | Concurrency model documented (sequential / threads / tasks) |
| E6 | Callback-based blocking | Raise from a tool-start callback | Expected: not a reliable stop. Record the observed spy count |
| E7 | Official hook | Inspect the installed version for a supported tool-call wrapping or middleware API | Present or absent recorded, with module and function name |
| E8 | Version floor | Read package metadata (`Requires-Python`) | Recorded; checked against D-01 |

**Report:** `docs/aidlc/02-construction/spike_framework_interception.md` with versions, per-experiment evidence (command and output), a recommended adapter design, and impacts on C1.6–C1.8, D-12 and D-20. **If E1 or E2 fails, stop:** the framework product promise must be re-scoped before C-03.

### C3.5 Adapter execution contract (rev. 2)

Each rule cites its decision. "Observed" cites spike evidence; production tests are listed in `testing_strategy.md` §15.

1. **Exact action (D-07 Approved in rev. 3; D-25 Approved).** The adapter passes the model-visible arguments, and only those, into the pipeline as the request's `arguments`. Framework-injected `tool_call_id` is excluded from the evaluated action and forwarded to the original function only at invocation time. The proxy executes the evaluated snapshot (C1.4).
2. **Sole executor (D-12).** Only the proxy calls the original function or coroutine. The replacement tool's own code never calls it directly.
3. **Non-ALLOW never executes and never returns a `Command` (D-12, SEC-002/003).** *Rev. 5:* an internal error (`decision=None`) is also non-executing and returns the fixed text `"not executed: INTERNAL_ERROR"`, never `"blocked: …"` and never a `Command`. **Rev. 6:** every operational refusal (`decision=None`) returns `"not executed: <ERROR_CODE>"`. DENY and REQUIRE_APPROVAL produce a fixed-text in-tool `ToolException` (`"blocked: <REASON_CODE>"`), which the framework turns into an error `ToolMessage`. No state update and no routing follow. *Observed:* C-02b C3–C4 (`side_node` ran 0 times and `notes` stayed empty when wrapped; the unwrapped control routed).
4. **Post-execution failures (D-26 Approved).** If the original raises an `Exception` after `entered`, the adapter returns the fixed-text in-tool `ToolException` `"tool failed (execution may have occurred)"`. It **never** lets the original exception, or a Sentinel exception, escape into the framework. The text never says "blocked" or "not executed". Internal diagnostics go to the audit (C1.8, D-29). Other post-invocation failures (output filter, audit) follow the same rule with their own fixed texts. *Observed:* C-02b retry matrix (13 rows): conversion → 1 execution; naive propagation → 3 executions under both `RetryPolicy(max_attempts=3)` and `ToolRetryMiddleware(max_retries=2)`.
5. **ALLOW return values pass through unchanged (D-12).** The original's return value is returned exactly: `str`, `ToolMessage`, or `Command`. *Observed:* C-02b C1–C2, C6, where the final state, messages and routing were identical to the unwrapped original. Sentinel authorizes the tool call. It does **not** authorize or inspect the `Command`'s downstream effects (C3.6).
6. **Async (D-12; D-30 Approved in rev. 3: internal entry).** Async-native tools stay async-only. They run through an **internal** asynchronous counterpart of the synchronous pipeline entry (D-30), which is **not** a stable public API in v1. Pre- and post-execution stages (blocking I/O) run in a worker thread. The original coroutine is awaited on the caller's event loop, through the async proxy path that uses the same atomic claim (rule 1, C1.4 rule 5). *Observed:* C-02b B1–B3 (stand-in evaluation ran in `asyncio_0`, not the loop thread).
7. **Cancellation / interruption (D-14 amendment Approved).** A `BaseException` after `entered` marks the request `interrupted`, triggers the best-effort `unknown` record (C1.6), and is re-raised. It never becomes a denial, a `not_started`, or a retry. *Observed:* C-02b B6 (started 1, completed 0, cancelled 1, no re-execution in the following 0.9 s).
8. **At-most-once per `tool_call_id` (D-27 Approved; D-31 Approved in rev. 3).** Defense in depth for rule 4.
   - **Key:** `(agent_id, session_id, tool_call_id)`. `agent_id` and `session_id` are trusted values from application code; `tool_call_id` comes from the framework. The adapter makes the framework's `tool_call_id` available; where the original tool does not declare it, the adapter adds it as a **hidden** injected parameter that stays out of the model-facing schema (observed in C-02b A10). A `tool_call_id` without a `session_id` → `INVALID_REQUEST` (C1.2).
   - **Claim:** immediately **after** an ALLOW decision and **before** `EXECUTION_STARTED`. If an unexpired entry with the same key exists, the call does not execute: `decision=None`, `error_code="DUPLICATE_TOOL_CALL"`, `execution="not_started"` *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*. Denied calls never create an entry.
   - **Expiry / retirement:**
     - while the request is in flight (claimed, not yet terminal) the entry **never expires**;
     - when the request reaches a terminal state (`completed`, `failed`, `interrupted`, or not-started after the claim), its expiry is set to *terminal time + TTL*;
     - expired entries are retired deterministically: purged before each new claim, by a monotonic clock that is injectable for tests;
     - entries never outlive the process.
   - **Capacity:** a fixed maximum number of entries. **An unexpired entry is never evicted to make room.** If, after purging expired entries, the guard is full, a new invocation that requires a guard entry **fails closed**: `decision=None`, `error_code="GUARD_CAPACITY_EXHAUSTED"`, not executed *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*. Calls without a `tool_call_id` (no guard entry) are unaffected.
   - **TTL and capacity** are configuration values. Their proposed defaults (TTL 1 hour after the terminal state; 100,000 entries) are listed in §8.6 as open until C-10.
   - **Guarantee (within one process):** for a given key, at most one execution *starts* while an entry for that key exists, that is, from the first claim until TTL after that request's terminal state.
   - **Not guaranteed:**
     - exactly-once *external* side effects;
     - protection against a **new call with a new `tool_call_id`**, including a new model-generated id; such a call is evaluated and executed independently (observed in C-02b A10: 2 calls, 2 decisions, 2 executions);
     - repeats after the entry expired, after a process restart, or in another process;
     - availability once capacity is exhausted (fail closed, T-21).
   - A model that repeats an existing id can only cause that later call to be refused; it cannot cause an extra execution.
   - If no `tool_call_id` is available (direct `evaluate_request` callers), the guard does not apply.
9. **Fixed text only.** Every model-visible string produced by the adapter is a fixed template plus a stable reason code. No exception text, policy contents, paths or secrets (SEC-008).
10. **Coverage report (SHOULD, FR-025).** The adapter offers a best-effort report of which tools in a compiled agent or tool node are Sentinel-protected. It depends on framework internals and returns "not inspectable" rather than guessing (C-02b A5–A6).

### C3.6 Framework limitations (explicit; not defended by the adapter)

| Limitation | Evidence |
|---|---|
| Trusted code (middleware, application code) can substitute or call an original tool; it runs unevaluated | C-02b A8, C-02 B5 |
| Unwrapped, middleware-supplied and provider built-in tools are outside the boundary | C-02b A5–A6 |
| A model-emitted unknown tool name is rejected by the **framework** before the adapter, so there is no Sentinel decision and no audit record | C-02b A4, C-02 B5 |
| Framework retries of a **new** request (new decision) and model-driven repeats cannot be distinguished from legitimate repeats by the adapter | C-02b A10 |
| Retry protection was verified for `RetryPolicy` and `ToolRetryMiddleware` only; other retry mechanisms are untested | C-02b §6 |
| `tool_call_id` uniqueness across real providers, checkpoint resume and replay were not tested. A model can repeat an id to *suppress* a later call (fails closed; it cannot cause extra execution) | C-02b §7, §9 |
| `Command` downstream effects of an ALLOW are applied by the framework, outside Sentinel; `Send` and `Command.PARENT` are untested | C-02b C2, §9 |
| Coverage inspection relies on internal attribute paths and may break across framework versions | C-02b A5 |
| Tested versions only: `langchain` 1.4.7, `langgraph` 1.2.18, `langgraph-prebuilt` 1.1.1, `langchain-core` 1.7.1, Python 3.11.14, macOS; scripted model; toy gate | both reports |
| `create_react_agent` is deprecated in favour of `create_agent` (framework API churn) | C-02 F14 |

### C3.7 Evidence vs decision summary

| Contract element | Observed in spike | Decision | Production test (§15) |
|---|---|---|---|
| Replacement tools, supported patterns | C-02 B; C-02b A–C | D-12 Approved | AT-13–AT-21 |
| Atomic single-use claim | C-02b B5/D3 | D-25 Approved | AT-01–AT-03 |
| Exact-action binding, canonical digest | C-02 B4, C-02b D1–D2 (stand-in digest only) | D-07 Approved (rev. 3) | AT-23, AT-28–AT-31 |
| Post-execution failure conversion | C-02b retry matrix | D-26 Approved | AT-11, AT-12 |
| At-most-once per `tool_call_id` | C-02b A10, B7, C5 | D-27, D-31 Approved | AT-04–AT-07, AT-25, AT-26, AT-35, AT-36 |
| In-process `unknown` on interruption | C-02b B6 (state only) | D-14 amendment Approved | AT-08–AT-10 |
| Internal diagnostics content | not tested | D-29 Approved (rev. 3) | AT-12, AT-32, AT-33 |
| Async pipeline entry (internal) | C-02b B (stand-in only) | D-30 Approved (rev. 3) | AT-02, AT-08, AT-34 |

All production tests are **not yet implemented**: the spikes ran against stand-ins, not Sentinel code.

---

## 4. Persistence model (C4)

### C4.1 Comparison

| Concept | ER diagram (DIAG, 2026-10-26) | PDF §2/§5 | Brief §5.2, R13, R14 | Recommended v1 representation |
|---|---|---|---|---|
| User | `USER{user_id, role}` registers Agents | Agent table holds "registered agents and users" | `Agent.user_id` | Attribute `user_id` on the in-memory `AgentRecord`. No entity |
| Agent | `AGENT{agent_id, status}` | `Agent` | `Agent{…, credential_hash, disabled}` | **In memory** (registered by application code) |
| Policy | `POLICY{policy_id, version}` governs Envelopes | `Policy` table or config | `Policy{id, version, rules}` | **In memory** `SecurityPolicy`; `policy_version` copied onto every decision event |
| Capability envelope | `CAPABILITY_ENVELOPE{envelope_id, allowed_actions json}` 1:1 Agent, M:N Tool | `CapabilityEnvelope` | grants JSON | **In memory**, held with the agent record |
| Tool | `TOOL{tool_id, risk_level}` | `Tool` definitions | name + metadata | **In memory** `ToolSpec` in the registry. `destructive` replaces `risk_level` |
| Request | `REQUEST{request_id, risk_score}` | "each Request links to an Agent, a Tool…" | No table; AuditEvent keyed by `request_id` | **Derived view**: all audit events sharing a `request_id` |
| Decision | `DECISION{decision_id, outcome}` 1:1 Request | `SecurityDecision` | DECISION audit event | The **DECISION audit event**, exactly one per request when audit is available |
| Alert | `ALERT{alert_id, severity}` 0..n per Request | Alert Manager | `logging` warning only | **Not persisted in v1**; `logging` warning (FR-020) |
| Audit event | **absent** | `AuditEvent` store | `AuditEvent` | **Persisted**: the only v1 table |

**Conclusion:** the ER diagram is a reasonable *conceptual* model of configuration plus outcomes, but it has no event history, and the PDF's audit requirement needs one. The brief's AuditEvent model covers Request, Decision and (later) Alert as views or events. Recommendation D-09: v1 persists **only `audit_events`**. The ER diagram is not modified. A revised diagram will be produced only after D-09 is approved.

### C4.2 The `audit_events` table (proposed; pending D-09)

| Column | Type | Null | Notes |
|---|---|---|---|
| `seq` | INTEGER PK AUTOINCREMENT | no | Total order of writes |
| `event_id` | TEXT (UUID4) UNIQUE | no | |
| `request_id` | TEXT, indexed | no | Correlation key |
| `event_type` | TEXT | no | C4.3 enumeration |
| `occurred_at` | TEXT (ISO-8601 UTC) | no | Injected clock |
| `agent_id` | TEXT | yes | Null only if the request was invalid before `agent_id` was parsed |
| `session_id` | TEXT | yes | |
| `tool` | TEXT | yes | |
| `decision` | TEXT | yes | Set on DECISION and REQUEST_COMPLETED |
| `reason` | TEXT | yes | Reason code |
| `policy_version` | TEXT | yes | |
| `action_digest` | TEXT | yes | Set on DECISION, EXECUTION_STARTED, REQUEST_COMPLETED for ALLOW |
| `execution` | TEXT | yes | Set on REQUEST_COMPLETED |
| `detail` | TEXT (JSON) | yes | Masked and truncated (NFR-017): arguments, finding evidence, error type names |
| `schema_version` | INTEGER | no | Sentinel refuses to write to a store with an unknown schema version |

Relationships and ownership: the table has **no foreign keys**. `agent_id` and `tool` are logical references to in-memory configuration as it was when the event was written. The audit store owns its rows. Sentinel exposes insert and read only.

### C4.3 Audit event lifecycle

```text
REQUEST_RECEIVED                                   (always first)
  ├─ invalid ─────────────────────────► REQUEST_COMPLETED(decision NULL, INVALID_REQUEST, not_started)        (rev. 6; rev. 1–5: "DECISION(deny, INVALID_REQUEST) ─► …")
  └─ IDENTITY_RESOLVED → FINDING×n → DECISION
        ├─ deny / require_approval ───► REQUEST_COMPLETED(not_started)
        ├─ allow, duplicate tool_call_id, guard full, or decision already claimed ─► REQUEST_COMPLETED(decision NULL; DUPLICATE_TOOL_CALL | GUARD_CAPACITY_EXHAUSTED | DECISION_ALREADY_USED; not_started)   (rev. 2; NULL decision rev. 6)
        └─ allow → EXECUTION_STARTED ─► [OUTPUT_FILTERED | OUTPUT_WITHHELD] ─► REQUEST_COMPLETED(succeeded|failed|not_started*)
                                     └─ BaseException after entered ─► REQUEST_COMPLETED(unknown), best effort; exception re-raised   (rev. 2)
ERROR events may appear at any point (diagnostics per C1.8 / D-29: type, module, stage, location; no message text by default).
Rev. 5 (Q-03c): unexpected internal error before execution ─► ERROR ─► REQUEST_COMPLETED(decision NULL, reason INTERNAL_ERROR, not_started), best effort.
* not_started after EXECUTION_STARTED = proxy binding or re-resolution check blocked the call.
```

Every event up to and including EXECUTION_STARTED is **committed** before the next stage runs (C1.7).

**Rev. 6:**
- A DECISION event exists **only** when policy reached a decision. Invalid requests and pre-policy internal errors have none.
- REQUEST_COMPLETED records the result's `decision` (NULL for operational refusals) and its error code.
- Exactly one REQUEST_COMPLETED per request when the audit store is available; at most one DECISION.

### C4.4 Reconstruction rules for audit readers (normative)

| Events present for a `request_id` | Execution status |
|---|---|
| No DECISION, or DECISION ≠ allow | **Not executed** (guaranteed) |
| DECISION = allow, no EXECUTION_STARTED | **Not executed** (guaranteed: EXECUTION_STARTED is committed before invocation) |
| EXECUTION_STARTED and REQUEST_COMPLETED | As recorded in `REQUEST_COMPLETED.execution`, which **may be `unknown`** after an interruption (rev. 2) |
| EXECUTION_STARTED, no REQUEST_COMPLETED | **Unknown**: the tool may have run fully, partially, or not at all |

### C4.5 Storage defaults (pending D-11)

- `SentinelConfig.audit_db_path` defaults to **`sentinel_audit.db`** in the working directory. The path is resolved to an absolute path when the client is constructed, logged at INFO, and the file is created then (never at import).
- SQLite with `journal_mode=WAL` and `synchronous=FULL`, so a commit is durable when it returns (with a performance cost, to be measured under NFR-011).
- `audit_db_path=":memory:"` is accepted only explicitly. It logs a WARNING, and every result reports `audit_complete=False`, because records do not survive the process. **Recommended for tests only.** Tests normally use a file under `tmp_path`.
- `*.db` is git-ignored.

### C4.6 Integrity limitations

1. **Append-only through Sentinel's API only.** Anyone with write access to the file, or in-process access to the engine, can modify or delete rows. There is no tamper evidence in v1 (hash-chaining is post-v1). [BRIEF R19]
2. No foreign keys: audit rows reference configuration by value; configuration is not versioned.
3. Single process. Concurrent writers from several processes are unsupported.
4. No migrations. A schema-version mismatch fails closed (writes refused, so calls are denied).
5. Durability depends on the filesystem honouring `fsync`.

---

## 5. Contract → requirement → test traceability

| Contract | Requirements (rev. 3) | Acceptance tests (`testing_strategy.md` rev. 3) |
|---|---|---|
| C1.1 request identity | FR-002 | `test_fr002_*`, NI-12 |
| C1.2 identity and grants | FR-005–007, SEC-001, SEC-004, SEC-013 | identity suite, E2E-04, E2E-08, NI-10 |
| C1.3 tool metadata | FR-010, FR-008 | registry suite, policy truth table |
| C1.4 action binding, atomic single use | SEC-010, SEC-021, **SEC-024** | NI-08, NI-09, NI-13, NI-16, AT-01–AT-03, AT-22, AT-23 |
| C1.5 policy outcomes | FR-008, SEC-002, SEC-003, SEC-012 | truth table §4, NI-01, NI-02 |
| C1.6 execution outcomes (incl. in-process `unknown`) | FR-017, SEC-022, **SEC-027** | NI-07, NI-14, NI-17, fault-injection matrix §6, AT-08–AT-10 |
| C1.7 audit behaviour, no re-execution | FR-012, SEC-005, SEC-006, **SEC-026** | NI-04, NI-06, NI-15, NI-18, audit fault injection, AT-11 |
| C1.8 errors, diagnostics | SEC-009, SEC-017, FR-018, **SEC-026** | fault-injection matrix, canary test, AT-12 |
| C2 filesystem | SEC-007 | path matrix §5 (F1–F20) |
| C3 identity/integration (adapter) | SEC-013, SEC-016, FR-021, FR-022, FR-025, FR-026, **SEC-025, SEC-028–SEC-031** | AT-04–AT-07, AT-13–AT-21, AT-25–AT-27; spike evidence in both reports |
| C4 persistence | FR-012, FR-024, SEC-018, SEC-023 | audit repository suite, reconstruction tests, durability test |

---

## 6. Residual risks this contract does NOT remove

In-process bypass (forged decisions, direct function calls, monkey-patching); prompt injection in general; free-form argument misuse within a granted tool; the path TOCTOU window and hard links; tamper with the audit file; side effects of a tool that ran before an audit or filter failure. **Rev. 2:**
- trusted-code substitution of original tools inside frameworks;
- unwrapped, middleware-supplied and provider built-in tools;
- model-driven repeats under new `tool_call_id`s;
- framework retry mechanisms other than the two tested;
- `Command` downstream effects;
- side effects of a call interrupted after it started (outcome unknown).

See `threat_model.md` rev. 3.

---

## 7. Decision register

Each entry lists: **Q** question · **Options** · **Rec.** recommended option · **Rationale** · **Consequences** (security / engineering) · **Approval** whether owner approval is required · **Status** · **Affects** documents and requirements · **Source**.

### D-01 — Python version floor
- **Q:** What is the minimum supported Python version?
- **Options:** (a) ≥3.9 (PDF); (b) ≥3.10 (brief R1); (c) **≥3.11**; (d) ≥3.12.
- **Rec.:** (c). CI matrix 3.11, 3.12, 3.13.
- **Rationale:** 3.9 is past end of life; 3.10 reaches end of life in October 2026 (INFERRED from the PEP 619 schedule, not checked online in this phase). Both 3.11 and 3.12 are installed locally (OBSERVED).
- **Consequences:** security: supported interpreters get security fixes. Engineering: excludes 3.10 users. LangGraph compatibility is confirmed later by E8.
- **Approval:** required. **Status:** **Approved** 2026-10-28 by the project owner ("D-01: Python >=3.11", C-01 instruction; see §12). **Affects:** NFR-001, `pyproject.toml` (C-01), CI. **Source:** INCEPTION OD-06.
- **Rejected alternatives (history):** (a) unsupported interpreter; (b) end of life this month.

### D-02 — Distribution and import names
- **Q:** What are the PyPI distribution name and the import name?
- **Options:** (a) `sentinel-ai` / `sentinel` (PDF); (b) `sentinel-ai` / `sentinel_ai`; (c) another distinctive name.
- **Rec.:** keep (a) **provisionally**, and verify both names on PyPI before the first publish and preferably before C-01 (an owner-side check takes minutes). If `sentinel` is already taken by another distribution, switch to (b).
- **Rationale:** names have no security impact, but renaming the import package later touches every file and test.
- **Consequences:** engineering: rename cost grows with each increment. Security: none.
- **Approval:** required (accept provisional names, or choose). **Status:** **Approved as provisional** 2026-10-28 by the project owner ("`sentinel-ai` distribution name and `sentinel` import name are provisional, subject to later verification"; see §12). Final names remain **Pending** PyPI verification, required before C-18. **Affects:** NFR-013, C-01, C-18. **Source:** EXISTING PDF §5/§7; INCEPTION CF-17.

### D-03 — Representing post-execution audit failure
- **Q:** What does the caller receive when the tool has run but a post-execution audit write fails?
- **Options:** (a) return the output normally and log the failure; (b) raise `AuditUnavailable` from `evaluate_request` (Inception rec.); (c) **return a result with `execution` truthful, `output_released=False`, `audit_complete=False`, `error_code=AUDIT_UNAVAILABLE`; adapters raise `ToolExecutionError(execution=…)`**; (d) report DENY.
- **Rec.:** (c).
- **Rationale:** never implies that execution did not happen; keeps one rule (the pipeline returns); unaudited output does not reach the agent.
- **Consequences:** security: auditability is preferred over availability of output; the side effect remains. Engineering: callers must check `audit_complete`.
- **Approval:** required. **Status:** Proposed. **Affects:** C1.6–C1.8, FR-017, SEC-006, SEC-022, testing §6. **Source:** INCEPTION CF-09.
- **Rejected:** (d) falsely reports non-execution; (a) releases unaudited data; (b) superseded, because raising hides the execution state from code that only reads results.

- **Rev. 4 status: Approved** 2026-10-28 by the project owner (verbatim in §12).
  - Output **withheld** from the direct caller when the closing audit write fails after a tool ran.
  - Execution status, output release, audit completeness and error code are separate fields.
  - `evaluate_request` returns a structured result for handled post-execution failures.
  - **Reconciliation with D-26:** the framework adapter returns a fixed-text tool error, exposes no internal diagnostics, and never lets an exception escape in a way that can trigger a retry. Internal diagnostics are written to the audit when possible.
  - The rev. 1–3 text "adapters raise `ToolExecutionError`" now applies **only** to direct callers that request exceptions, never to the framework adapter.
  - Open: Q-03c (§14.R4).
- **Rev. 5:** Q-03c resolved: an unexpected internal error is represented separately from policy decisions (`decision=None`, `error_code="INTERNAL_ERROR"`), never as `"deny"` (C1.6, C1.8).
### D-04 — Trusted agent identity
- **Q:** Where does `agent_id` come from?
- **Options:** (a) from the request dict, whatever its origin; (b) **from trusted application code: the `raw` dict built by the app, or the adapter's `agent_id` parameter; reserved keys rejected inside `arguments`; credentials optional with a `require_credentials` flag**; (c) mandatory signed tokens.
- **Rec.:** (b).
- **Rationale:** the realistic attacker is the model. Binding defeats model-supplied identity. Tokens held in the same process add little against in-process code (C6).
- **Consequences:** security: an integration that reads identity from model data voids envelope isolation, so this is documented as a hard rule. Engineering: adapters need an `agent_id` parameter.
- **Approval:** required. **Status:** Proposed. **Affects:** C1.2, C3, SEC-013, FR-005/006, T-03. **Source:** BRIEF §1, §6.2; INCEPTION CF-12.
- **Rejected:** (a) spoofable; (c) disproportionate for an in-process library in v1. Kept as a future option.

- **Rev. 4 status: Approved** 2026-10-28 by the project owner (verbatim in §12), with a **deviation from the recorded recommendation**:
  - credentials are configured per agent, and `require_credentials` defaults to **`True`** (recommendation was `False`);
  - no mandatory signed tokens in v1;
  - reserved identity-related keys in arguments are **rejected**, not stripped;
  - trusted identity as in option (b).
### D-05 — Missing or empty path grants
- **Q:** What does a path tool's grant without `allowed_path_prefixes` mean?
- **Options:** (a) unrestricted (brief's `None` default); (b) **deny every call; unrestricted only via explicit `("/",)`**; (c) registration error.
- **Rec.:** (b), plus a warning at registration.
- **Rationale:** a missing constraint must not widen access (default deny). (c) would stop the configuration of a grant that the owner intends to fill in later.
- **Consequences:** security: fails closed. Engineering: an explicit `"/"` is needed for broad access.
- **Approval:** required. **Status:** Proposed. **Affects:** C2.1–C2.2, SEC-007, policy truth table. **Source:** INCEPTION CF-13.
- **Rejected:** (a) fails open.

- **Rev. 8 status: Approved** 2026-11-08 by the project owner (verbatim in §12): **option (b)**.
  - **Decision:** a path-constrained tool whose grant has missing or empty `allowed_path_prefixes` is denied on every call: `decision="deny"`, reason `RESTRICTED_PATH`. Empty or missing never means unrestricted. Unrestricted access exists only as the explicit prefix `("/",)`. Registering empty prefixes emits a warning; registering `("/",)` is logged (C2.2).
  - **Rationale:** as above. A missing constraint must not widen access.
  - **Security:** fails closed. No implicit default grants broader filesystem access.
  - **Affects requirements:** SEC-007, FR-010. **Increments:** C-04 (containment of an empty prefix set is always false; registration warning), C-07 (grants), C-08 (policy DENY `RESTRICTED_PATH`).

### D-06 — Destructive tools and approval
- **Q:** How is "destructive" declared, and what happens to REQUIRE_APPROVAL?
- **Options:** (a) `destructive: bool = False` (brief); (b) **required keyword with no default**; (c) default `True`. And for approval: (i) **never executes in v1**; (ii) an approve-and-replay API.
- **Rec.:** (b) + (i). `require_approval_for_destructive=True` by default, so destructive tools are unusable in v1 unless the owner sets it to `False`.
- **Rationale:** forces a conscious classification of every tool; the PDF puts the approval workflow out of scope.
- **Consequences:** security: no fail-open default on the highest-impact control. Engineering: slightly more verbose registration; destructive tools are blocked by default.
- **Approval:** required. **Status:** Proposed. **Affects:** C1.3, C1.5, FR-010, SEC-003, T-10. **Source:** EXISTING PDF §4.4, §7; BRIEF R9, R10; INCEPTION CF-04, CF-16.
- **Rejected:** (a) fails open; (c) noisy; (ii) out of scope.

- **Rev. 4 status: Approved** 2026-10-28 by the project owner (verbatim in §12): every tool explicitly declares `destructive` (no default); destructive tools require approval by default (`require_approval_for_destructive=True`). Together with the owner contract requirement that approval-required calls never execute, destructive tools do not run in v1 unless a deployment opts out.
### D-07 — Binding decisions to request and action
- **Q:** How does the proxy know it is executing what policy evaluated?
- **Options:** (a) nothing beyond the decision value (PDF); (b) `request_id` match (Inception); (c) **`AuthorizedAction` embedded in the decision, plus digest verification; the proxy executes only `decision.action`**; (d) HMAC-signed decisions with a per-process key.
- **Rec.:** (c).
- **Rationale:** guards against divergence and nested mutation between policy and proxy at low cost. (d) adds no real protection in-process, because the key is reachable by the same code.
- **Consequences:** security: SEC-010/021 become exactly testable. Engineering: arguments must be JSON-serialisable after validation (also needed for the audit).
- **Approval:** required. *Rev. 1–2 status:* Proposed. **Rev. 3 status: Approved** 2026-10-28 by the project owner (verbatim in §12). Scope as approved:
  - one exact, validated action per decision;
  - bound to request identity, tool identity, canonical arguments and relevant resolved path information;
  - a digest that is deterministic across runs and changes when any security-relevant nested argument changes;
  - `tool_call_id` excluded from the digest but used for duplicate-execution protection;
  - execution of a differing action is rejected.

  Contract: C1.4 rules 1–4 and 6.
- **Affects:** C1.4, SEC-010, SEC-021, SEC-032, FR-011, C-03, C-10. **Source:** INCEPTION CF-08; PHASE-1.5.
- **Rejected:** (a), (b) insufficient; (d) false sense of security.

### D-08 — Strict validation, a single coercion, required schemas
- **Q:** How are arguments validated, and is `arg_schema` mandatory?
- **Options:** (a) optional schema, lax validation, re-validation in the proxy (brief); (b) strict validation once, schema required only for path tools; (c) **strict validation once in the gateway, schema required for every tool, extra fields forbidden, the proxy executes the validated values unchanged (no second validation)**.
- **Rec.:** (c).
- **Rationale:** one validation means one meaning. The digest and the audit need a known shape.
- **Consequences:** security: removes the coercion mismatch (B3). Engineering: every tool needs a small Pydantic model. Adapters can derive it from framework tool schemas (confirmed by the experiment).
- **Approval:** required. **Status:** Proposed. **Affects:** FR-004, FR-010, SEC-010, T-13. **Source:** BRIEF §6.5; INCEPTION OD-09.
- **Rejected:** (a) check/use mismatch; (b) leaves schema-less tools unvalidated.

- **Rev. 4 status: Approved** 2026-10-28 by the project owner (verbatim in §12): every registered tool requires an argument schema; validation is strict with no type coercion; unexpected argument keys are rejected.
### D-09 — v1 persistence model
- **Q:** Which model is built: the ER diagram's, or the audit-event model?
- **Options:** (a) the ER diagram (REQUEST/DECISION/ALERT/USER tables); (b) the brief R14 (ORM for five entities, only AuditEvent written); (c) **only the `audit_events` table (C4.2); configuration in memory; ER concepts mapped per C4.1**.
- **Rec.:** (c). A revised ER diagram is produced after approval, as a new file; the original stays.
- **Rationale:** the ER diagram lacks event history; (b) creates dead schema.
- **Consequences:** security: one append-only store is simpler to reason about. Engineering: agents and policies must be re-registered at each process start.
- **Approval:** required. **Status:** Proposed. **Affects:** C4, FR-012, FR-024, SEC-018, C-09. **Source:** DIAG ER; BRIEF R13/R14; INCEPTION OD-01.
- **Rejected:** (a), (b) as above.

### D-10 — Out-of-scope diagram extras
- **Q:** Are the September diagrams' features (provenance, RAG trust, quarantine, delegation, privilege drift, risk engine/CONFIRM, scoped credentials, dashboard) part of v1?
- **Options:** (a) **exclude from v1; record multi-agent delegation as the first post-v1 candidate**; (b) include some.
- **Rec.:** (a).
- **Rationale:** absent from the PDF and brief v1 scope; including them would delay the enforcement core.
- **Consequences:** the "multi-agent" product has no delegation controls in v1, so README limitations must say so.
- **Approval:** required. **Status:** Proposed. **Affects:** `requirements.md` §4. **Source:** DIAG Sept; INCEPTION OD-03.

### D-11 — Audit storage default
- **Q:** What is the default audit store?
- **Options:** (a) `sqlite:///:memory:` (brief §9); (b) no default, explicit path required (Inception OD-07); (c) **durable SQLite file `sentinel_audit.db` in the working directory, resolved and logged at construction; WAL + `synchronous=FULL`; `:memory:` only explicitly, and then `audit_complete=False`**.
- **Rec.:** (c), matching the owner's stated preference.
- **Rationale:** the audit trail survives by default; the zero-config quickstart still works.
- **Consequences:** security: there is no silent non-durable mode. Engineering: creates a file in the working directory when the client is constructed (documented); fsync cost.
- **Approval:** required. **Status:** Proposed. **Affects:** C4.5, FR-024, SEC-023, C-09. **Source:** BRIEF §9; INCEPTION OD-07.
- **Rejected:** (a) loses records silently. (b) is a valid alternative, kept as the fallback if the owner prefers no implicit file creation.

### D-12 — Scope and name of framework protection
- **Q:** What does Sentinel promise for LangGraph and LangChain?
- **Options:** (a) `protect(graph)` covering "every invocation" (PDF); (b) `protect()` with narrowed documentation; (c) **`wrap_tools(tools, client=, agent_id=)` with the C3.3 guarantee; `protect` not offered in v1**.
- **Rec.:** (c), final design after the experiment (E1–E8).
- **Rationale:** the name `protect(graph)` implies coverage that cannot be enforced.
- **Consequences:** a deviation from the PDF's headline example. README and examples must use `wrap_tools`.
- **Approval:** required (also for installing LangGraph in the separate spike environment). *Rev. 1 status:* **Pending**: depends on the E1/E2/E7 results.
- **Rev. 2 status:** **Approved (expanded)** 2026-10-28 by the project owner (verbatim in §12). Scope: Design B replacement tools for **synchronous function tools**, **async-native tools through async entry points**, and **`Command`-returning tools whose only supported injected parameter is `InjectedToolCallId`**; **explicit refusal** of unsupported patterns; **no claim** that unwrapped, middleware-supplied or provider built-in tools are protected. Contract: C3.2, C3.3, C3.5, C3.6. Evidence: C-02, C-02b.
- **Affects:** C3, FR-021, FR-022, FR-025, FR-026, SEC-016, SEC-028–SEC-031, C-16, C-17. **Source:** EXISTING PDF §1, §5; INCEPTION CF-18; C-02/C-02b.
- **Rejected:** (a) unenforceable. Also rejected after C-02: a `ToolNode` `wrap_tool_call` hook as the sole boundary (Design A). The framework, not the proxy, runs the function; installing only the async hook left the sync path unguarded; direct tool calls bypass it (C-02 F3, F4, F6).

### D-13 — Commits and pushes during Construction
- **Q:** What may be committed or pushed, and when?
- **Options:** (a) **one local conventional commit per increment, made only after the increment's evidence (tests, lint, types) has been produced and shown; no push without explicit owner permission each time**; (b) owner commits manually; (c) commit and push freely.
- **Rec.:** (a). The first commit adds `.gitignore` (excluding `.DS_Store`). Original design documents are committed in a separate `docs:` commit only if the owner asks.
- **Approval:** required. **Status:** **Approved** 2026-10-28 by the project owner ("Local commits are permitted after completed, verified increments. Never push without explicit permission."; see §12). **Affects:** `implementation_plan.md` §5. **Source:** BRIEF §0.3; INCEPTION OD-11.

### D-14 — Execution outcome model
- **Q:** How are execution results and partial failures represented?
- **Options:** (a) `PipelineResult(decision, reason, tool_result)` (brief); (b) a single `outcome` enum (Inception); (c) **separate `execution` / `output_released` / `audit_complete` / `error_code` (C1.6), with `unknown` defined for audit reconstruction**.
- **Rec.:** (c).
- **Rationale:** orthogonal facts need separate fields; avoids misreporting.
- **Approval:** required (public result shape). **Status:** **Partly approved.** The **C1.6 amendment** was approved 2026-10-28 by the project owner ("Revise C1.6 to permit an unknown in-process execution outcome when cancellation or interruption occurs after execution begins."; §12): `unknown` is produced in-process after an interruption, recorded best-effort, and the exception is re-raised. The rest of the result model (field set, invariants) remains **Proposed**. **Affects:** C1.6, C1.7, FR-017, SEC-022, SEC-027, C-03, C-10, C-11. **Source:** BRIEF R3; INCEPTION CF-05; C-02b B6.

- **Rev. 4 status: Approved (complete)** 2026-10-28 by the project owner (verbatim in §12): separate fields `execution`, `output_released`, `audit_complete`, `error_code` (Q-14 = A), in addition to the earlier C1.6 amendment.
- **Rev. 5 (Q-03c):** `PipelineResult.decision` is `Decision | None`. `None` means an internal error prevented a decision. The four approved result fields are unchanged and no result-kind field is added (§14.R5).
### D-15 — Policy owns authorization; policy receives tool metadata
- **Q:** Which component decides, and with what inputs?
- **Rec.:** policy is the sole authority; `evaluate(request, context, findings, tool_spec)`; the Tool-Abuse detector is dropped from v1; containment is one pure function.
- **Options rejected:** a detector duplicating capability checks (PDF §4.3); policy reaching into the registry (hidden I/O).
- **Approval:** required (changes the PDF interface, drops a PDF-named detector). **Status:** Proposed. **Affects:** C1.3, FR-008, FR-014. **Source:** BRIEF R8; INCEPTION CF-07.

- **Rev. 4 status: Partly approved** 2026-10-28 by the project owner (verbatim in §12).
  - **Approved:** the registry is the authoritative source of security-relevant tool metadata, which policy evaluates; no independent detector may act as a separate allow/deny authority.
  - **Not decided by that wording:**
    - (i) the metadata delivery mechanism: an explicit `tool_spec` parameter (option A) or a registry lookup inside policy (option C);
    - (ii) whether an *informational-only* Tool-Abuse detector exists in v1. Option A drops it; option B keeps it as informational, which the wording permits.
  - Neither affects C-03a or C-03's model shapes; both must be settled before C-08 (and C-13 for (ii)).
### D-16 — Orchestrator and sole audit writer
- **Q:** Does `Pipeline` or `Gateway` orchestrate?
- **Rec.:** `Pipeline` orchestrates and is the **only** component that writes audit events. The gateway validates and canonicalises.
- **Rejected:** Gateway-as-orchestrator (class and sequence diagrams); stages writing audit independently (PDF).
- **Approval:** required (contradicts the owner's diagrams). **Status:** Proposed. **Affects:** architecture §2–4, C-11. **Source:** BRIEF R15; INCEPTION OD-02.

### D-17 — Audit read API
- **Q:** Should there be a public way to read audit events?
- **Rec.:** `SentinelClient.audit_events(request_id=None, limit=100)`, read-only.
- **Approval:** required (public API). **Status:** Proposed. **Affects:** FR-013. **Source:** DIAG use case; INCEPTION OD-04.

### D-18 — Filesystem contract details
- **Q:** Should C2.3–C2.8 apply (absolute paths only, gateway canonicalisation, prefix directory counts as contained, prefixes must exist at registration, proxy re-resolution)?
- **Rec.:** adopt C2 as written.
- **Options rejected:** resolve relative paths against the CWD (environment-dependent); exclude the prefix directory itself (breaks listing tools).
- **Approval:** required. **Status:** Proposed. **Affects:** SEC-007, testing §5. **Source:** BRIEF R11; INCEPTION CF-13; PHASE-1.5.
- **Rev. 8 status: Approved** 2026-11-08 by the project owner (verbatim in §12): **adopt C2 as written** (C2.1–C2.8), with no new semantics.
  - **Decision:** absolute request paths only (relative paths and `~` → `INVALID_REQUEST`, never resolved against the working directory or expanded); canonicalisation in the gateway; prefixes canonicalised and validated at registration and required to exist as directories; component-wise containment, never string-prefix comparison; the prefix directory itself is contained; the canonical path is passed to the tool; the proxy re-resolves and re-validates immediately before invocation and refuses a path that changed or is no longer contained.
  - **Rationale:** as above (environment-independent resolution; listing tools keep working).
  - **Security:** closes pre-existing symlink, `..` and sibling-prefix escapes. **Limitations that must stay explicit** (C2 table): re-resolution does not remove the time-of-check/time-of-use window before the tool's own `open`; hard links are not detected; this is path-argument authorization, not an operating-system sandbox or filesystem isolation.
  - **Affects requirements:** SEC-007, FR-004 (path part), FR-010 (prefix rules). **Increments:** C-04 (functions), C-06 (gateway use), C-07 (prefix registration for grants), C-08 (policy containment), C-10 (proxy re-resolution).

### D-19 — Output filter failure and M3 mode
- **Q:** What happens when the filter fails, and what is the M3 default?
- **Rec.:** failure → output withheld (from M1). M3 default mode `redact`. Unsupported output types → withheld in `enforce` mode.
- **Approval:** required for the M3 mode only. **Status:** Proposed (failure rule) / Pending until M3 (mode). **Affects:** FR-015, SEC-011. **Source:** EXISTING PDF §4.5; INCEPTION CF-14.

### D-20 — Concurrency
- **Q:** What concurrency does v1 support?
- **Rec.:** thread-safe synchronous use within one process; async fails closed; one SQLAlchemy session per request (or serialised writes); atomic rate-limit check-and-record (M4).
- **Rev. 2 update:** "async fails closed" is **superseded** for adapter-wrapped async-native tools by D-12. The recommendation becomes:
  - thread-safe sync use **and** asyncio-safe async use within one process;
  - decision claiming per D-25;
  - blocking pipeline stages never run on the event loop (C3.5 rule 6);
  - one SQLAlchemy session per request (or serialised writes);
  - atomic rate-limit check-and-record (M4).

  *Observed:* C-02 E7 and C-02b B7 saw sync tool calls in 1–2 thread-pool workers and async calls in executor threads.
- **Approval:** confirm. **Status:** Proposed (the claim rule within it is Approved as D-25). **Affects:** NFR-016, FR-019, SEC-024. **Source:** INCEPTION OD-08; C-02, C-02b.

### D-21 — Supported operating systems
- **Q:** Which platforms are supported?
- **Rec.:** Linux and macOS. On Windows, registering a path-constrained tool raises `ConfigurationError`. CI on `ubuntu-latest` and `macos-latest`.
- **Approval:** required. **Status:** Proposed. **Affects:** NFR-012, C2. **Source:** INCEPTION OD-10.
- **Rev. 8 status: Approved** 2026-11-08 by the project owner (verbatim in §12), with a clarification.
  - **Decision:** Linux and macOS are the supported platforms **for path-constrained filesystem enforcement**. Registering a path-constrained tool on Windows raises `ConfigurationError`. The restriction applies to path-constrained tools only: Sentinel as a whole is **not** declared unsupported on Windows (it is also not tested there). CI runs on `ubuntu-latest` and `macos-latest`.
  - **Rationale:** C2 relies on POSIX path semantics (`realpath`, `PurePosixPath`); Windows paths (drive letters, UNC and `\\?\` forms, junctions) would need their own unverified rules.
  - **Security:** the unsound case is refused at registration rather than enforced incorrectly.
  - **Affects requirements:** NFR-012, SEC-007. **Increments:** C-04 (platform check, F20), C-05 (registry refuses path tools on Windows), CI workflow.

### D-22 — Development dependencies and build backend
- **Q:** Which development-only dependencies and which build backend?
- **Rec.:** pytest, pytest-cov, ruff, mypy; Hypothesis optional (recommended for C2 property tests); build backend `hatchling`; framework packages only in optional extras.
- **Approval:** required for mypy, pytest-cov, Hypothesis and hatchling (pytest and ruff come from the brief). **Status:** **Partly approved** 2026-10-28 by the project owner ("Use pytest and Ruff with a standard pyproject.toml-based build configuration. Use Hatchling unless existing project constraints justify another backend."; see §12). Approved: pytest, Ruff, `pyproject.toml`, Hatchling. **Not approved, still Proposed:** mypy (NFR-005), pytest-cov (NFR-006), Hypothesis. **Affects:** NFR-004–006, C-01. **Source:** BRIEF R16; INCEPTION OD-12.

### D-23 — Location of the authoritative decision register
- **Q:** Where are decisions recorded?
- **Rec.:** this file is authoritative. `open_decisions.md` is history. The README links here.
- **Approval:** confirm. **Status:** **Approved** 2026-10-28 by the project owner ("`docs/aidlc/01-inception/decision_record.md` is the canonical decision register"; see §12). **Source:** INCEPTION OD-05.

### D-24 — Baseline confirmations (brief recommendations kept unchanged)

| Sub-ID | Item | Rec. | Status | Source |
|---|---|---|---|---|
| D-24a | Default deny via explicit grant | Adopt | Proposed | BRIEF R5; CF-01 |
| D-24b | Grant granularity = tool name (no sub-actions) | Adopt | **Approved** (rev. 9, owner 2026-11-08; addendum below) | BRIEF §1; CF-02 |
| D-24c | Precedence R4 with deterministic tie-break; risk score informational; deny at ≥ HIGH. **Rev. 4:** exact order and tie-break documented in C1.5 | Adopt | **Approved** (rev. 4, owner Q-24c) | BRIEF R4, R7; CF-03 |
| D-24d | `evaluate_request` returns, adapters raise. **Rev. 2:** the *framework tool adapter* does not raise into the framework; it returns fixed-text in-tool `ToolException`s (D-26). "Adapters raise" now applies only to adapters that deliberately halt a run. **Rev. 4:** handled execution and audit failures → structured result. **Rev. 5:** internal errors → structured result with `decision=None` | Adopt (as revised) | **Approved** (rev. 4, owner Q-03b; Q-03c resolved rev. 5) | BRIEF R3; CF-05; D-26 |
| D-24e | Detector `analyze(request, context)`; recursive string scan; detector failure → DENY | Adopt | Proposed | BRIEF R6; CF-06 |
| D-24f | Audit wording "append-only through Sentinel's API"; never "immutable" | Adopt | Proposed | BRIEF R19; CF-10 |
| D-24g | Known-limitations section (in-process boundary, heuristic detection, invisible LLM context, no timeouts) | Adopt | Proposed | BRIEF R17; CF-11 |
| D-24h | Injection detection described as advisory | Adopt | Proposed | BRIEF §1; CF-15 |
| D-24i | Class `SentinelClient`; module `audit.py`; lowercase decision values. **Rev. 5 (Q-03c):** the value set stays exactly `allow`/`deny`/`require_approval`; no `"error"` value | Adopt | **Approved in part** (rev. 4, owner Q-24i: serialized decision values are lowercase). Class name `SentinelClient` and module name `audit.py` were not addressed; they stay Proposed and are needed by C-09 and C-12, not by C-03a | BRIEF R2, R15; CF-17 |

Approval: one confirmation covers the bundle; individual items may be rejected.

**D-24b rev. 9 addendum — Approved** 2026-11-08 by the project owner (verbatim in §12).
- **Decision:** a `ToolGrant` authorizes the entire registered tool by its registered name. Sentinel v1 has no sub-action, operation-level or argument-level grants.
- **Distinctions that stay in force:**
  - a grant establishes whether an agent is authorized to use a registered tool; it is **not** a policy ALLOW;
  - each invocation is still evaluated independently by policy (C1.5 rows 1–7);
  - the exact action stays bound by `AuthorizedAction` and its digest (C1.4, D-07);
  - destructive status (D-06), path restrictions (C2, D-05, D-18), rate limits (M4), risk findings and policy precedence (D-24c) remain separate controls;
  - a grant bypasses neither request validation (C-06) nor policy evaluation (C-08).
- **Rationale:** the registered name is already the tool's stable identity (D-07). Argument-level grants would add a second permission language and blur schema validation, capability and policy conditions. Because `AuthorizedAction` binds the complete call, tool-level grants are a coherent v1 boundary that does not replace per-action policy.
- **Security consequence (T-02):** a granted tool is trusted with everything its validated arguments allow, within path constraints and policy. Narrower operations need separate tools (CF-02).
- **Affects:** C1.2, C1.5 rows 2–3, FR-007, FR-010, SEC-001 (still pending D-24a), T-02. **Increments:** C-07 (models and lookup), C-08 (policy rows 2–3).

**C-07 interpretations (rev. 9).** These fill gaps the contracts leave open. Each one fails closed, and none widens access. Owner confirmation is requested; until then they stand as recorded.
- **I-1 Grants name registered tools.** Agent registration checks every grant against the `ToolRegistry`. A grant for an unregistered tool is a `RegistrationError`, so tools are registered before agents. A grant can therefore never silently refer to another or a future tool.
- **I-2 Prefixes only on path tools.** A path tool's prefixes go through `paths.register_prefixes` (C2.1, C2.2: canonical, existing directories; empty or missing → warning and deny everything; `("/",)` logged). Prefixes on a grant for a tool without `path_args` are a `RegistrationError`, because they would constrain nothing.
- **I-3 Rate limits refused until enforced.** `RateLimit{max_calls, window_seconds}` (both positive integers) is modelled, but a grant carrying one is refused with `ConfigurationError` until C-15 (M4, D-20) enforces it. A configured but unenforced limit would give a false sense of control.
- **I-4 Credentials.** A credential is passed as a non-empty `SecretStr` and stored only as its SHA-256 digest. Verification hashes the presented token and compares digests with `hmac.compare_digest`. The comparison also runs against a fixed dummy digest when the agent is unknown or has no credential (best-effort timing uniformity). Plain SHA-256 assumes high-entropy tokens such as API keys; it is not a password hash.
- **I-5 Facts, not decisions.** Identity returns `SecurityContext{agent_id, user_id, authorized, envelope}` and never raises for unknown, disabled or unauthenticated agents. It sets `authorized=False`, and an unauthorized context carries **no** envelope. Policy row 1 turns that into DENY `UNAUTHORIZED_AGENT` (C-08). Identity never looks at the requested tool; matching a grant (`CapabilityEnvelope.grant_for`) is a lookup used by policy row 2.
- **I-6 `require_credentials` is supplied to identity.** FR-009 places it on `SecurityPolicy`, which is C-08. C-07 takes it as a constructor parameter that defaults to `True`; the pipeline (C-11) passes the policy's value.
- **I-7 Registration is setup-time only.** Agents are registered once, by trusted application code. There is no replace, remove or enable/disable-later API, and nothing on the request path can mutate agents or grants (SEC-014's principle applied to identity).

### D-25 — Atomic, single-use decision claiming (rev. 2)
- **Q:** How is "one decision, one execution" enforced under concurrency?
- **Options:** (a) check-then-mark without atomicity; (b) **an atomic claim (check and mark under one lock, no `await` or I/O in between), shared by sync and async paths, before `entered`**; (c) persistent claims in the audit store.
- **Decision:** (b). C1.4 rule 5.
- **Rationale / evidence:** C-02b B5/D3: (b) executed exactly once in 100/100 trials × 8 contenders for threads and for asyncio; (a), as a control, duplicated in 50/50 trials.
- **Consequences:** security: replay and concurrent consumption fail closed. Engineering: claims are per process; a second process cannot see them (single-process scope, C4.6).
- **Status:** **Approved** 2026-10-28 by the project owner (§12). **Affects:** C1.4, SEC-024, NFR-016, C-10, testing AT-01–AT-03. **Source:** C-02b.
- **Rejected:** (a) demonstrably racy; (c) unnecessary for single-process v1 and adds I/O to the claim.

### D-26 — Adapter handling of post-execution failures (rev. 2)
- **Q:** What does the framework adapter do when the original raises after execution began, or a later step fails?
- **Options:** (a) let the original exception propagate into the framework; (b) raise a Sentinel exception into the framework; (c) **return a fixed-text in-tool `ToolException` (`"tool failed (execution may have occurred)"`); never let an `Exception` escape into the framework for request outcomes; preserve internal diagnostics in the audit; no Sentinel path re-invokes the tool for a claimed request**.
- **Decision:** (c). C1.7, C1.8, C3.5 rule 4.
- **Rationale / evidence:** C-02 E6 and the C-02b retry matrix. (a) gave 3 executions under `RetryPolicy` and `ToolRetryMiddleware` (sync, async, `Command`), and surfaced the exception text to the graph caller. (c) gave 1 execution in every row, and the planted canary reached neither the model nor the caller.
- **Consequences:** the model sees a generic error; operators rely on the audit for diagnosis. The guarantee covers the tested retry mechanisms; others are a documented limitation (C3.6).
- **Status:** **Approved** 2026-10-28 by the project owner (§12). The *content* of the diagnostics is D-29 (Proposed). **Affects:** C1.7, C1.8, C3.5, SEC-026, FR-018, D-24d, testing AT-11–AT-12. **Source:** C-02, C-02b.
- **Rejected:** (a) re-executed side effects; (b) the same failure mode as (a), since `ToolRetryMiddleware` retries any `Exception` by default.

### D-27 — At-most-once guard per `tool_call_id` (rev. 2)
- **Q:** Should the adapter refuse a second execution for the same framework tool-call id?
- **Decision:** yes, as **defense in depth** behind D-26. Claim `(agent_id, session_id, tool_call_id)` after ALLOW and before `EXECUTION_STARTED`; a repeat → `decision=None`, `error_code="DUPLICATE_TOOL_CALL"`, not executed (C3.5 rule 8) *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*.
- **Explicit limit (owner's instruction):** this does **not** prevent a new call with a new `tool_call_id`. Such a call is a new request, evaluated and executed independently.
- **Evidence:** C-02b A10, B7, C5: the "propagate + once-per-call-id" rows executed exactly once while the framework retried; the agent-loop retry (new id) executed again under a new decision, as expected.
- **Status:** **Approved** 2026-10-28 by the project owner (§12). Parameters (key scope, capacity, expiry, model field) are D-31: *rev. 2:* Proposed (with eviction); **rev. 4: Approved**, with no eviction of unexpired entries and fail-closed at capacity. **Affects:** C1.2, C3.5, C4.3, SEC-025, testing AT-04–AT-07, AT-25–AT-26. **Source:** C-02b.

### D-28 — Ruff exclusion for experimental `spikes/` (rev. 2)
- **Q:** How are throwaway experiment files kept out of production linting?
- **Decision:** add `spikes` to `[tool.ruff] extend-exclude` in `pyproject.toml`, next to the existing `SENTINEL_BUILD_BRIEF.md` and `docs` entries. Remove the file-wide `# ruff: noqa` headers from the spike files. Production code (`src/`, `tests/`) keeps the full rule set, and **no blanket suppression** is added to production code.
- **Status:** **Approved** 2026-10-28 by the project owner (§12). Applied in this revision (§13). **Affects:** `pyproject.toml`, spike files and READMEs. **Source:** C-02 §11, C-02b §10.

### D-29 — Content of internal failure diagnostics in the audit (rev. 2; approved rev. 3)
- **Q:** D-26 requires "preserve internal diagnostics in audit records". What exactly is stored?
- **Options considered:** (a) type name only (rev. 1 C1.8); (b) structured diagnostics, no message text by default, optional masked message text behind a flag (default off); (c) full message and traceback.
- **Decision (Approved):** structured diagnostics by default; **no exception message text by default**.
  - **Stored fields:** exception type (qualified class name); module and function of the raising frame; line number; pipeline stage; `request_id`; tool name; `error_code`.
  - **Not stored:** message text, traceback text, frame-local values, argument values, absolute file-system paths.
- **Opt-in message text:** **v1 does not provide one.** This is the smallest option compatible with the approval: the approval permits an opt-in but does not require one. If one is ever added it must be disabled by default, its data-exposure risk must be documented (exception messages can contain arbitrary secrets, as C-02b's canary did), and it must not be described as safe because of masking.
- **No promise:** no document may claim that heuristic masking alone prevents secret leakage.
- **Status:** **Approved** 2026-10-28 by the project owner (verbatim in §12). **Affects:** C1.8, SEC-008, SEC-017, SEC-026, AT-12, AT-32, AT-33, C-09, C-10.
- **Rejected:** (c) leaks; (a) too little to diagnose failures. The "optional flag" part of (b) is deferred and not implemented in v1.

### D-30 — Async pipeline entry point (rev. 2; approved rev. 3)
- **Q:** D-12 includes async-native tools through async entry points; how does the pipeline expose async execution?
- **Decision (Approved):** an **internal** asynchronous counterpart to the synchronous pipeline entry, used for async-native tool execution.
  - Pre- and post-execution stages run in a worker thread, and the original coroutine is awaited on the caller's loop.
  - It shares the D-25 claim, the D-31 guard and the C1.6 interruption handling.
  - It is **not** a stable public API in v1: not in `sentinel.__all__`, not a public `SentinelClient` method, and not documented as supported. The framework adapter may call it.
  - Promotion to public requires its interface and behaviour to be tested and then reviewed by the owner.
- **Internal vs public API (definition, rev. 3):**
  - **public** = names exported in `sentinel.__all__` or in the `__all__` of a `sentinel.integrations.*` module, *and* documented in the README or API docs as supported;
  - **internal** = everything else, including underscore-prefixed names and modules. Internal names carry no stability guarantee and may change without notice.
- **Status:** **Approved** 2026-10-28 by the project owner (verbatim in §12). **Affects:** FR-026, C3.5 rule 6, C-11, C-12, C-16, AT-34.
- **Rejected for v1:** a public `SentinelClient` async method (left open for a later, reviewed decision).
- **Note:** this revises the brief's "async APIs deferred" [REC] only in the narrow internal scope that D-12 requires. Public async APIs remain deferred.

### D-31 — Parameters of the `tool_call_id` guard (rev. 2; approved rev. 3)
- **Q:** Key, scope, lifetime, capacity and model field for D-27.
- **Decision (Approved):**
  - Bind guard entries to the trusted agent identity, the session identity and the `tool_call_id`.
  - Reject duplicate use.
  - **Never evict an unexpired entry to make room if that could permit a duplicate execution.**
  - When capacity is exhausted, **fail closed** for new invocations that require a guard entry.
  - Define expiry and retirement, and document the resulting guarantee and limitations.
  - Keep it deterministic and testable.
  - Do not claim exactly-once external side effects, or protection against a new model-generated `tool_call_id`.
- **Contract (C3.5 rule 8):**
  - In-memory, per process.
  - Entries are created at the claim after ALLOW; denied calls create none.
  - In-flight entries never expire; terminal entries expire TTL after the terminal state; expired entries are purged deterministically before each claim using an injectable monotonic clock.
  - When full after purging → `decision=None`, `error_code="GUARD_CAPACITY_EXHAUSTED"` *(rev. 6: operational refusal, not a policy decision; rev. 2–5 said "DENY")*.
  - Optional adapter-supplied `tool_call_id` field on the request, excluded from the D-07 digest.
- **Derived rule (flagged in §14):** a `tool_call_id` without a `session_id` → `INVALID_REQUEST`, because the guard cannot bind it, and failing closed matches the approval's stance.
- **Still open (not a C-03 blocker):** the default values for TTL and capacity. Proposed: TTL 1 hour after the terminal state; capacity 100,000 entries. Both are configurable; they must be set before C-10.
- **Status:** **Approved** 2026-10-28 by the project owner (verbatim in §12). Default values: Proposed. **Affects:** C1.2, C3.5 rule 8, SEC-025, T-17, T-21, AT-04–AT-07, AT-25, AT-26, AT-35, AT-36, C-03, C-10.
- **Rejected (history):** the rev. 2 proposal of "oldest-first eviction" when full. It could re-open duplicate execution for evicted, unexpired keys, which the approval forbids.
---

## 8. Construction entry gate

### 8.1 Owner decisions that block the scaffold (C-01)

C-01 creates no security logic. It needs only the decisions that are baked into packaging, tooling and history:

| Decision | Why it blocks C-01 |
|---|---|
| **D-01** Python floor | `requires-python`, CI matrix |
| **D-02** Names: accept provisional `sentinel-ai`/`sentinel` **or** choose | Package directory, `pyproject.toml`. Renaming later is costly |
| **D-13** Commit policy | C-01 ends in the first commit |
| **D-22** Dev dependencies and build backend | `pyproject.toml` `[dev]`, CI steps |
| **D-23** Decision location | The README links to it |

Plus: an explicit owner instruction to begin Construction.

### 8.2 Decisions that can safely stay provisional at C-01

D-10 (scope; affects only later docs and limitations), D-12 (pending the experiment), D-17 (read API, C-12), D-19 M3 mode, D-20 final form (after E5), D-21 (CI OS matrix can be added in C-01 as recommended and adjusted later), D-24 items that only affect later modules.

### 8.3 Security contracts that must be Approved before any execution code

"Execution code" here means C-03 onward: the models encode these contracts.

| Must be approved before | Decisions |
|---|---|
| **C-03** (models and contracts) | D-03, D-04, D-06, D-07, D-08, D-14 (remainder; the C1.6 amendment is already Approved), D-15, D-24c, D-24d, **D-31** (model field) |
| **C-04** (path guard) | D-05, D-18, D-21 (**all Approved, rev. 8**) |
| **C-09** (audit store) | D-09, D-11, D-24f, **D-29** (diagnostics content) |
| **C-10** (proxy) | **D-31** (guard parameters). D-25, D-26 and D-27 are already Approved |
| **C-11** (pipeline) | D-16, D-20, **D-30** (async entry) |
| **C-16** (adapter) | D-12 Approved; D-26, D-27 Approved; D-30 and D-31 as above |

If any of these is rejected, the affected contract section is revised and re-reviewed before the increment starts. None may be bypassed by "implement now, decide later".

### 8.4 Framework feasibility questions for the isolated experiment

E1–E8 (C3.4) settle D-12 and refine D-20 and the adapter part of D-04. The experiment needs owner approval to install LangGraph/LangChain in a separate environment. It runs as C-02, after C-01 and before C-03, so that a negative E1 or E2 result can still change the C1 contracts.

**Rev. 2:** done. C-02 and C-02b ran with owner approval; E1/E2 passed; D-12 is Approved (expanded). Remaining framework questions (real providers, checkpoint resume, other retry mechanisms, `Send`/`PARENT`, human-in-the-loop middleware) are listed in C3.6 and are **not** prerequisites for C-03.

### 8.5 Gate checklist (G-0)

- [x] Owner has read `decision_record.md` (this file) and the rev. 2 documents. *(Implied by the owner's C-01 instruction of 2026-10-28.)*
- [x] D-01, D-02, D-13, D-22, D-23 set to Approved (or Rejected with a replacement recorded). *(2026-10-28; D-02 provisional, D-22 partial; see §12.)*
- [x] Owner instruction: "begin C-01". *(2026-10-28; C-01 committed locally as `8a5a993`.)*
- [x] (For C-02) owner approval to install LangGraph in the spike environment. *(2026-10-28; C-02 and C-02b executed.)*
- [x] C-02 and C-02b reports reviewed by the owner. *(2026-10-28; six changes approved, §12.)*
- [ ] (Before C-03) every decision in §8.3's C-03 row Approved. *Rev. 2 list:* D-03, D-04, D-06, D-07, D-08, D-14 remainder, D-15, D-24c, D-24d, D-31. **Rev. 3:** D-07 and D-31 are now Approved; the authoritative checklist is **§8.6** (still open: D-03, D-04, D-06, D-08, D-14 remainder, D-15, D-24c, D-24d, D-24i).

### 8.6 C-03 entry gate (rev. 3, final contract gate)

C-03 encodes the core models and contracts (`implementation_plan.md` C-03). Every decision that shapes a C-03 model must be **Approved** first. Status as of 2026-10-28:

| # | Decision | What C-03 needs from it | Status | Gate |
|---|---|---|---|---|
| 1 | D-07 exact-action binding | `AuthorizedAction`, canonical encoding, digest, `SecurityDecision.action` | **Approved** (rev. 3) | ✅ |
| 2 | D-25 atomic single-use claim | reason code `DECISION_ALREADY_USED` | **Approved** | ✅ |
| 3 | D-27 / D-31 `tool_call_id` guard | optional `tool_call_id` field (outside the digest); session-required rule; reason codes `DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED` | **Approved** (D-31 default values open, not needed by C-03) | ✅ |
| 4 | D-14 C1.6 amendment | `execution="unknown"` value semantics | **Approved** | ✅ |
| 5 | D-14 remainder (result model) | `PipelineResult` field set | Proposed: open choice (§14 Q-14) | ❌ |
| 6 | D-03 post-execution audit failure | `PipelineResult` semantics; exception set | Proposed: open choices (§14 Q-03a, Q-03b) | ❌ |
| 7 | D-24d return vs raise | exception hierarchy (FR-018) | Proposed: open choice (§14 Q-03b) | ❌ |
| 8 | D-04 trusted identity, credentials | `SecurityRequest.auth_token`, `SecurityContext`; reserved-key rule | Proposed: open choices (§14 Q-04a, Q-04b) | ❌ |
| 9 | D-06 destructive declaration | `ToolSpec.destructive` (required or default) | Proposed: open choices (§14 Q-06a, Q-06b) | ❌ |
| 10 | D-08 validation and schemas | `ToolSpec.arg_schema` required or optional; strict mode; extra fields | Proposed: open choices (§14 Q-08a–c) | ❌ |
| 11 | D-15 policy authority, tool metadata | `ToolSpec` metadata-only; finding codes (Tool-Abuse kept or dropped) | Proposed: open choice (§14 Q-15) | ❌ |
| 12 | D-24c precedence, severity scale | `Severity` enum; `SecurityDecision.finding_codes` / `risk_score` | Proposed: open choice (§14 Q-24c) | ❌ |
| 13 | **D-24i** names and decision value casing | `Decision` enum values (`"allow"` vs `"ALLOW"`), class names | Proposed. *Not listed in earlier gates; found in this review* | ❌ |
| 14 | **D-24b** grant granularity | `ToolGrant` shape, **only if** `ToolGrant` is modelled in C-03 (it can move to C-07) | Proposed. *Found in this review* | ⚠️ |

**Result: C-03 is NOT authorized by this gate.** Rows 5–13 are open.

**Rev. 4 gate update (owner answers, 2026-10-28):**

| Row | Rev. 4 status |
|---|---|
| 5 D-14 remainder | ✅ Approved |
| 6 D-03 | ✅ Approved (Q-03c open, see below) |
| 7 D-24d | ✅ Approved for handled failures |
| 8 D-04 | ✅ Approved (`require_credentials=True` default) |
| 9 D-06 | ✅ Approved |
| 10 D-08 | ✅ Approved |
| 11 D-15 | ⚠️ Partly approved: metadata authority settled; delivery mechanism and informational detector open (C-08/C-13, not C-03) |
| 12 D-24c | ✅ Approved |
| 13 D-24i | ⚠️ Lowercase values Approved; class and module names open (C-09/C-12) |
| 14 D-24b | ⚠️ Still Proposed (only matters if `ToolGrant` stays in C-03) |
| new | ~~❌ Q-03c~~ → ✅ **Approved in rev. 5** (Option B: `decision=None`, `error_code="INTERNAL_ERROR"`; no `"error"` decision value) |

- **C-03a (action record and digest): AUTHORIZED** by the owner, scope as in `implementation_plan.md` C-03a (rev. 5).
- **Rev. 6 gate result (2026-10-28):**
  - **Owner approval:** ✅ the owner approved the C-03 model and exception increment, with `ToolGrant` out of scope until D-24b is resolved.
  - **`ToolGrant` exclusion:** ✅ clean. `ToolGrant` is used only by `CapabilityEnvelope`, which is used only by `SecurityContext.envelope`. No other C-03 model depends on them (`SecurityRequest`, `ToolSpec`, `SecurityFinding`, `SecurityDecision`, `PipelineResult`, `AuthorizedAction`, enums, exceptions). They therefore move to C-07 **as a group**: `ToolGrant`, `RateLimit`, `CapabilityEnvelope`, `SecurityContext`. No grant contract is invented.
  - **Decisions shaping C-03 models:** ✅ D-03, D-04, D-06, D-07, D-08, D-14, D-24c, D-24d, D-25, D-27, D-31, Q-03c, rev. 6 refusals; D-24i (values); D-15 (metadata authority). D-15's remainder affects C-08 only.
  - **❌ BLOCKER: runtime dependency.** The approved C-03 contract requires **Pydantic v2**:
    - C1.3 defines `arg_schema` as a *Pydantic model class*;
    - D-08's strict, no-coercion validation is specified in terms of Pydantic strict mode;
    - C1.2/D-04 specify `auth_token` as `SecretStr`;
    - the brief and source document require "Pydantic for all inter-module objects" (brief §2 [DOC]).

    Pydantic is **not installed** in the project `.venv` and **not declared** (`dependencies = []`). Adding it is NFR-002, which is still **Proposed**. This task prohibits installing dependencies. **C-03 is therefore not implemented.**
  - **Owner options:**
    - **A (recommended):** approve the Pydantic part of NFR-002, i.e. add `pydantic>=2.14,<3` to runtime `dependencies` (2.14.1 was the version used in both spikes), pin it in `constraints-dev.txt`, and authorize installing it into the project `.venv`.
    - **B:** implement C-03 with the standard library only. This needs new decisions replacing C1.3's `arg_schema` type, the strict-validation mechanism and `SecretStr`. It is a contract change and is not recommended.
  - **Details settled during C-03 implementation (delegated, not blockers):** the names of the internal-error and operational-refusal exception classes (Q-03c: "name settled in C-03"); re-parenting C-03a's interim `ActionEncodingError` under the request-validation exception (foreseen in its docstring).
- **Rev. 7 (2026-10-28):**
  - **Pydantic blocker resolved** by owner option A: `pydantic>=2.14,<3`, resolved 2.14.1.
  - **C-03 implemented** in `src/sentinel/exceptions.py` and `src/sentinel/models.py`, with `ToolGrant`, `RateLimit`, `CapabilityEnvelope` and `SecurityContext` excluded.
  - Delegated names chosen: `ExecutionRefused` (operational refusals) and `InternalEvaluationError` (internal errors). Neither subclasses `ActionDenied`.
  - C-03a's `ActionEncodingError` re-parented under `InvalidRequestError`, keeping `ValueError`.
- *Rev. 4–6 status (superseded by rev. 7):* **Full C-03: NOT AUTHORIZED.** The owner stated this explicitly. *(Rev. 4: "In addition, Q-03c is open and D-24b may be needed.")* **Rev. 5:** Q-03c is resolved. The remaining items before full C-03 are:
  - the **owner's explicit review and approval of the full implementation gate**;
  - D-24b, only if `ToolGrant` stays in C-03;
  - the open consistency question in §14.R5 (non-blocking unless the owner says otherwise).

**Exact contract C-03 will implement once rows 5–13 are Approved:** the C-03 scope in `implementation_plan.md` (rev. 4), consisting of:
- C1.2 request fields including the optional `tool_call_id` and the session rule;
- C1.3 `ToolSpec` (per D-06, D-08, D-15);
- C1.4 rules 1–6 at model level (`AuthorizedAction`, canonical digest, `SecurityDecision`);
- C1.5 enum values;
- C1.6 `PipelineResult` (per D-14, D-03);
- the exception hierarchy (per D-03, D-24d);
- reason-code constants (`ACTION_MISMATCH`, `DECISION_ALREADY_USED`, `DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED`, `INVALID_REQUEST`, …).

No behaviour beyond model validation and digest computation.

**Optional split (requires owner approval; not authorized by default):** a **C-03a** "action identity" increment that depends only on Approved decisions (D-07, D-25, D-27, D-31):
- canonical JSON encoding with JSON-native validation;
- `action_digest()`;
- a frozen `AuthorizedAction` (`request_id`, `agent_id`, `tool`, `arguments`, `digest`);
- the `tool_call_id` exclusion;
- the reason-code constants listed above.

Acceptance: AT-28, AT-29, AT-30, AT-31 (model level). It would not create `SecurityDecision`, `PipelineResult`, `ToolSpec`, `Decision` or `Severity`, so it does not touch rows 5–14.

**May safely remain open until later increments:**

| Decision | Needed by |
|---|---|
| ~~D-05, D-18, D-21 (path semantics, OS support)~~ **Approved in rev. 8** | C-04 |
| ~~D-24b (if `ToolGrant` moves to C-07)~~ **Approved in rev. 9** | C-07 |
| D-24a (default deny; policy behaviour) | C-08 |
| D-09, D-11, D-24f (persistence, storage default, wording) | C-09 |
| D-31 default values (TTL, capacity); D-19 failure rule | C-10 |
| D-16, D-20 (orchestration, concurrency) | C-11 |
| D-17 (audit read API) | C-12 |
| D-24e, D-24h (detection) | C-13 |
| D-19 M3 mode | C-14 |
| D-10, D-24g (scope, limitations text) | C-18 / README |
| D-02 final names | C-18 |

---

## 9. Changes made to other documents in this phase

| Document | Change |
|---|---|
| `open_decisions.md` | Banner and CF/OD → D mapping added at the top; original entries unchanged (history) |
| `requirements.md` | Rev. 2: FR-004/010/012/016/017/021 and SEC-005/006/007/010/013 revised; added FR-024, SEC-021–SEC-023; status column references D-IDs; change log |
| `testing_strategy.md` | Rev. 2: path matrix F16–F20; fault-injection matrix uses the C1.6 fields; NI-13–NI-15; E2E audit sequences per C4.3; experiment reference; contract → test map |
| `implementation_plan.md` | Rev. 2: G-0 per §8; increment dependencies, blocking decisions and tests updated (gateway now depends on the path guard; C-09 lifecycle; C-16 `wrap_tools`) |
| `architecture_assessment.md` | Rev. 2: enforcement sequence §4 replaced by the C1/C4 sequence; §8 mapped to D-IDs |
| `threat_model.md` | Rev. 2: T-03, T-06, T-07, T-09, T-11, T-12 updated (re-resolution, hard links, EXECUTION_STARTED/unknown, `wrap_tools`) |
| `repository_assessment.md` | Phase 1.5 verification section appended |

The C-02/C-02b finalization (rev. 2) changes are listed in §13.

## 10. Not done in this phase (by constraint)

No product code; no dependency installation; no network calls (so D-02 name availability and every framework claim remain unverified); no commits or pushes; original diagrams and the brief untouched; no revised ER diagram (waits for D-09).

## 11. Commands run in this phase

| Command | Result |
|---|---|
| `git status --short`; `find … -newer repository_assessment.md`; `stat` mtimes; `shasum -a 256` | No new or changed files besides the Inception documents, which were written 20:30–20:40. Originals predate them |

## 12. Approval log

| Date | Decision | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | D-01 | Approved | "D-01: Python >=3.11." | Claude, from the owner's C-01 instruction in the working session |
| 2026-10-28 | D-02 | Approved as provisional (final names Pending verification) | "D-02: `sentinel-ai` distribution name and `sentinel` import name are provisional, subject to later verification." | same |
| 2026-10-28 | D-13 | Approved | "D-13: Local commits are permitted after completed, verified increments. Never push without explicit permission." | same |
| 2026-10-28 | D-22 | Partly approved (pytest, Ruff, pyproject.toml, Hatchling) | "D-22: Use pytest and Ruff with a standard pyproject.toml-based build configuration. Use Hatchling unless existing project constraints justify another backend." | same |
| 2026-10-28 | D-23 | Approved | "D-23: `docs/aidlc/01-inception/decision_record.md` is the canonical decision register." | same |

Note: when the C-01 instruction arrived, the register still showed these entries as Proposed or Pending. The approvals above were transcribed from that explicit owner instruction, and this discrepancy was reported to the owner. Every other decision keeps its previous status.

**C-02/C-02b review approvals.** Source: the owner's instruction in the working session, "The project owner has reviewed the reports and approved the six proposed changes listed below."

| Date | Decision | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | D-12 | Approved (expanded) | "Expand D-12 to cover the tested Design B replacement-tool adapter patterns: Synchronous function tools. Async-native tools through async entry points. `Command`-returning tools whose only supported injected parameter is `InjectedToolCallId`. Explicit refusal of unsupported tool patterns. No claim that unwrapped tools, middleware-supplied tools, or provider built-in tools are protected." | Claude, from the owner's C-02b review instruction |
| 2026-10-28 | D-14 (C1.6 amendment only) | Approved (partial) | "Revise C1.6 to permit an unknown in-process execution outcome when cancellation or interruption occurs after execution begins." | same |
| 2026-10-28 | D-25 | Approved | "Require atomic, single-use decision claiming across threads and asyncio tasks." | same |
| 2026-10-28 | D-26 | Approved | "Require appropriate adapter handling of post-execution failures so framework retry behavior does not accidentally repeat side effects. Use fixed-text model-visible errors where appropriate, and preserve internal diagnostics in audit records." | same |
| 2026-10-28 | D-27 | Approved | "Add an at-most-once guard per `tool_call_id` as defense in depth. State explicitly that this does not prevent a new call with a new ID." | same |
| 2026-10-28 | D-28 | Approved | "Add a narrow Ruff exclusion for experimental `spikes/` files from routine production linting. Do not add blanket lint suppression to production code." | same |

D-29, D-30 and D-31 were created in this revision as **Proposed** details needed to implement the approved changes. They are **not** approved. *(Rev. 3: approved on the same day; see below.)*

**Final contract gate approvals (rev. 3).** Source: the owner's final-contract-gate instruction in the working session ("Owner-approved recommendations … Record these decisions as Approved, using the project owner's approval and preserving their scope").

| Date | Item | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | D-29 | Approved | "Store structured diagnostics by default: exception type, module, execution stage, and safe location/context identifiers. Do not store exception message text by default. If message text is supported as an opt-in, document its data-exposure risks and ensure it is disabled by default. Do not promise that heuristic masking alone prevents secret leakage." | Claude, from the owner's final-contract-gate instruction |
| 2026-10-28 | D-30 | Approved | "Provide an internal asynchronous counterpart to the synchronous pipeline entry for async-native tool execution. Do not expose it as a stable public API in v1 until its interface and behavior have been tested and reviewed. Document the distinction between internal and public APIs." | same |
| 2026-10-28 | D-31 | Approved (default values remain Proposed) | "Bind guard entries to trusted agent identity, session identity, and tool-call ID. Reject duplicate use. Never evict an unexpired guard entry merely to make room if doing so would permit duplicate execution. When capacity is exhausted, fail closed for new invocations requiring a guard entry. Define how entries expire or are retired, and document the resulting guarantee and limitations. Keep the implementation deterministic and testable. Do not claim exactly-once external side effects or protection against a new model-generated tool-call ID." | same |
| 2026-10-28 | D-07 | Approved | "A decision authorizes one exact, validated action. Bind it to the request identity, tool identity, canonical arguments, and relevant resolved path information. Ensure the action digest is deterministic across runs and changes when any security-relevant nested argument changes. Exclude `tool_call_id` from the action digest, while still using it in duplicate-execution protection. Reject attempts to execute an action that differs from the approved action." | same |
| 2026-10-28 | FR-022 (requirement) | Approved, narrowed | "Approve `create_agent` support as a MUST only for the tested and explicitly documented adapter patterns. Do not imply support for provider-built-in tools, unwrapped tools, middleware-supplied tools, or unsupported injected parameters." | same |
| 2026-10-28 | C-17 → C-16 consolidation (plan) | Approved, conditional; **condition satisfied** by the C-17 obligations table in `implementation_plan.md` C-16 | "C-17 may be folded into C-16 only if every acceptance criterion and test obligation from C-17 remains explicitly represented in the revised plan." | same |

**Owner answers to §14 (rev. 4).** Source: the owner's C-03a authorization instruction in the working session ("The project owner has explicitly decided: …"; "The owner has authorized a narrow C-03a increment only. Full C-03 remains unauthorized.").

| Date | Item | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | D-03 (Q-03a) | Approved | "If the closing audit write fails after a tool has run, withhold the output from the direct caller. Represent execution status, output release, audit completeness, and error code separately." | Claude, from the owner's C-03a instruction |
| 2026-10-28 | D-03 / D-24d (Q-03b) | Approved (handled failures); Q-03c opened | "For handled execution and audit failures, `evaluate_request` returns a structured result rather than raising merely because a failure occurred after execution started. Unexpected programming errors must not be falsely represented as policy denials." | same |
| 2026-10-28 | D-03 / D-26 reconciliation | Approved | "The framework adapter must return a fixed-text tool error response for post-execution failures, must not expose internal diagnostics, and must not allow an exception to escape in a way that can trigger a tool retry. Internal diagnostics are written to audit when possible." | same |
| 2026-10-28 | D-04 (Q-04a) | Approved (default `True`) | "Credentials are configured per agent. `require_credentials=True` by default. Mandatory signed tokens are not a new v1 requirement." | same |
| 2026-10-28 | D-04 (Q-04b) | Approved | "Reject calls whose tool arguments contain reserved identity-related keys. Do not silently strip them." | same |
| 2026-10-28 | D-06 (Q-06a) | Approved | "Every tool must explicitly declare whether it is destructive. No default." | same |
| 2026-10-28 | D-06 (Q-06b) | Approved | "Destructive tools require approval by default." | same |
| 2026-10-28 | D-08 (Q-08a) | Approved | "Every registered tool requires an argument schema." | same |
| 2026-10-28 | D-08 (Q-08b) | Approved | "Validation is strict and does not coerce types." | same |
| 2026-10-28 | D-08 (Q-08c) | Approved | "Unexpected argument keys are rejected." | same |
| 2026-10-28 | D-14 (Q-14) | Approved (complete) | "Use separate result fields for execution status, output release, audit completion, and error code." | same |
| 2026-10-28 | D-15 (Q-15) | Partly approved | "The registry is the authoritative source of security-relevant tool metadata, which policy evaluates. No independent detector may act as a separate allow/deny authority." | same |
| 2026-10-28 | D-24c (Q-24c) | Approved | "Use the brief's evaluation order, a deterministic tie-break, and denial at HIGH. Document the exact order and tie-break rule." | same |
| 2026-10-28 | D-24i (Q-24i) | Approved in part (values only) | "Serialized decision values are lowercase." | same |
| 2026-10-28 | D-29 (confirmation) | Approved (interpretation confirmed) | "No raw exception-message storage option in v1. Use structured diagnostics only, and design them to avoid secret leakage." | same |
| 2026-10-28 | D-31 (confirmation) | Approved (interpretations confirmed; TTL/capacity defaults still open) | "Reject a guarded call with a tool-call ID but no session ID. A guard entry cannot expire while its call is running. TTL begins only after the call finishes. Never evict an unexpired entry to free capacity. Refuse new guarded calls when full." | same |
| 2026-10-28 | D-30 (confirmation) | Approved (interpretation confirmed) | "An async counterpart can exist internally for tested async-native tools, but it is not a stable public v1 API and must not be exported as one." | same |
| 2026-10-28 | D-07 (confirmation) | Approved (interpretation confirmed) | "Registered tool name defines tool identity." | same |
| 2026-10-28 | C-03a | **Authorized**; full C-03 not authorized | "The owner has authorized a narrow C-03a increment only. Full C-03 remains unauthorized." | same |

**Q-03c (rev. 5).** Source: the owner's Q-03c instruction in the working session ("The project owner has explicitly approved Q-03c, Option B.").

| Date | Item | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | Q-03c (D-03, D-14, D-24d, D-24i) | Approved (Option B, refined by the owner) | "Unexpected internal errors must be represented separately from policy decisions." • "Do not represent an internal evaluation failure as `decision="deny"`." • "Do not add `"error"` to the set of policy decision values." • "If needed, represent evaluation failure through a separate result status or result-kind field." • "Use `error_code="INTERNAL_ERROR"` for unexpected internal failures." • "When the failure occurs before execution starts, represent execution status as `not_started`." • "Do not release tool output when authorization or evaluation fails." • "Record the failure in the audit trail when possible, without storing raw exception-message text." • "Fail closed: an unresolved internal evaluation failure must never permit tool execution." • "Keep the existing lowercase serialized policy decision values and the separately approved result fields for execution status, output release, audit completion, and error code." • "C-03 remains unauthorized until the full implementation gate is explicitly reviewed and approved." | Claude, from the owner's Q-03c instruction |

**C-03 gate approval and operational refusals (rev. 6).** Source: the owner's C-03 gate instruction in the working session ("The project owner has approved the C-03 model and exception increment, subject to the scope restriction below.").

| Date | Item | Status set | Owner's words (verbatim) | Recorded by |
|---|---|---|---|---|
| 2026-10-28 | Operational refusals (C1.6, C1.7, C1.8; reclassifies §14.R5) | Approved | "The `decision` field represents an actual, applicable policy decision. It must not be used merely to indicate that execution was refused." • "Invalid request: `decision=None`, `INVALID_REQUEST`, execution not started." • "Unexpected internal evaluation error: `decision=None`, `INTERNAL_ERROR`, execution not started." • "Audit store unavailable before execution: preserve an actual policy decision if one was reached; otherwise use `None`. Do not execute unless the required pre-execution audit write succeeds." • "Action mismatch: `decision=None` for the refused attempt." • "Path changed after authorization: `decision=None` for the refused attempt." • "Decision already used: `decision=None` for the refused attempt." • "Duplicate tool-call ID: `decision=None` for the refused attempt." • "Guard capacity exhausted: `decision=None` for the refused attempt." • "For every refusal, preserve its specific error code and ensure the tool does not execute. Do not classify an operational refusal as a policy denial." • "If the closing audit write fails after execution, retain the actual policy decision, report execution status truthfully, mark the audit incomplete, and withhold the tool output." | Claude, from the owner's C-03 gate instruction |
| 2026-10-28 | C-03 increment | Approved, with scope restriction; **implementation blocked** (§8.6 rev. 6) | "The project owner has approved the C-03 model and exception increment, subject to the scope restriction below." • "Implement the approved model and exception contracts, including the previously approved decisions and the Q-03c result semantics." • "**ToolGrant is out of scope until D-24b is resolved.** First inspect the design and determine whether it can be excluded cleanly. If C-03 cannot be implemented correctly without deciding D-24b, stop and report the exact blocker. Do not invent a ToolGrant contract." | same |
| 2026-10-28 | NFR-002 (Pydantic part) | Approved; C-03 unblocked (rev. 7) | "I approve Pydantic v2 as a runtime dependency for Sentinel, using the compatibility range `pydantic>=2.14,<3`." • "I authorize installing the dependency into the existing project environment for C-03. Update `pyproject.toml` and `constraints-dev.txt` consistently, recording the exact resolved version in the constraints file." | Claude, from the owner's Pydantic instruction |
| 2026-11-08 | D-05 | Approved, option (b) (rev. 8) | "Decision: Option B." • "A path-constrained tool with missing or empty `allowed_path_prefixes` must deny every path access request." • "Empty or missing prefixes must never mean unrestricted filesystem access." • "Explicit unrestricted access may only be represented by an explicit root prefix: `(\"/\",)`." • "The policy outcome for an attempted access without an allowed prefix must be `deny`, with reason `RESTRICTED_PATH`." | Claude, from the owner's C-04 instruction |
| 2026-11-08 | D-18 | Approved (adopt C2 as written) | "Decision: Adopt the C2 filesystem contract as specified in the existing architecture documentation." • "Do not silently resolve relative paths against the current working directory." • "Re-resolution immediately before invocation does not eliminate all time-of-check/time-of-use race conditions." • "This mechanism is not an operating-system sandbox." • "Do not invent new semantics." | same |
| 2026-11-08 | D-21 | Approved, clarified | "Decision: Linux and macOS are supported for path-constrained tools." • "Registering a path-constrained tool on Windows must raise `ConfigurationError`." • "Do not declare the entire Sentinel framework unsupported on Windows. The restriction applies specifically to path-constrained tools." • "Configure CI to test Linux and macOS using appropriate GitHub Actions runners (`ubuntu-latest` and `macos-latest`)." | same |
| 2026-11-08 | D-24b | Approved (rev. 9) | "A ToolGrant authorizes the entire registered tool by its registered name. No sub-action, argument-level grant or operation-level grant model is introduced in Sentinel v1." • "A grant is not itself a policy ALLOW." • "Each invocation is still evaluated independently by the policy engine." • "Granting a tool does not bypass request validation or policy evaluation." | Claude, from the owner's C-07 instruction |

With these rows, the rev. 3 "Interpretations … that the owner should confirm" items 1–5 are **confirmed**. D-30's internal/public definition was not addressed word for word; the owner's statement is consistent with it.

**Not approved in rev. 3** (reviewed in §14; open owner choices): D-03, D-04, D-06, D-08, D-14 (remainder), D-15, D-24c, D-24d. Also D-24i and D-24b, which this review found to be C-03-relevant.

**Interpretations recorded in rev. 3 that the owner should confirm** (each is the most restrictive reading of the approved wording; none widens a guarantee):
1. D-29: the opt-in for message text is **not provided** in v1.
2. D-31: a `tool_call_id` without a `session_id` → `INVALID_REQUEST`.
3. D-31: entries never expire while in flight; TTL starts at the terminal state.
4. D-30: the definition of "internal" vs "public" API.
5. D-07: tool identity = the registered tool name (unique and non-replaceable per pipeline); non-JSON-native argument values are rejected.

## 13. C-02/C-02b finalization (rev. 2): changes and commands

| File | Change |
|---|---|
| `decision_record.md` | Header; §0.2; new §0.4; C1.2, C1.4 rule 5, C1.6, C1.7, C1.8; C3.2, C3.3 rewritten (rev. 1 text kept); C3.4 status; new C3.5–C3.7; C4.3, C4.4; §5, §6; D-12, D-14, D-20, D-24d updated; new D-25–D-31; §8; §12; §13 |
| `requirements.md` | Rev. 3: SEC-024–SEC-031, FR-025, FR-026, NFR-019 added; FR-012, FR-017, FR-018, FR-021, FR-022, SEC-008, SEC-016, SEC-022, NFR-016 revised |
| `testing_strategy.md` | Rev. 3: NI-16–NI-18; §15 adapter acceptance tests AT-01–AT-27, each marked as spike-run or not run; production status |
| `threat_model.md` | Rev. 3: T-12 updated; T-17–T-20 added |
| `architecture_assessment.md` | Rev. 3: component table notes, enforcement sequence (claim, guard, interruption, async path), boundary and bypass tables |
| `implementation_plan.md` | Rev. 3: C-02/C-02b recorded as done; C-03, C-05, C-09, C-10, C-11, C-12, C-16, C-17 updated; gate |
| `pyproject.toml` | `spikes` added to Ruff `extend-exclude` (D-28) |
| `spikes/**/*.py` (6 files) | File-wide `# ruff: noqa` header lines removed (D-28); no other change |
| `spikes/*/README.md` | Lint note updated |
| `docs/aidlc/02-construction/*.md` | A dated "rev. 2 update" note added; findings unchanged |
| `README.md` | Status row for framework integrations updated |

No production code, no dependency changes, no installs, no commits or pushes. The original brief and architecture references are unchanged.

**Rev. 3 (final contract gate) changes:**

| File | Change |
|---|---|
| `decision_record.md` | Header; C1.2 (session rule); C1.4 rule 6 (D-07: binding fields, canonical encoding); C1.8 (D-29 diagnostics); C3.5 rules 1, 6 (internal async entry), 8 (D-31 expiry, capacity, fail-closed); C3.7; D-07, D-29, D-30, D-31 Approved (D-31's rev. 2 eviction proposal kept as rejected history); §8.5; new §8.6 C-03 entry gate; §12 log rows; new §14 review |
| `requirements.md` | Rev. 4: FR-011, FR-022 (narrowed, Approved), FR-026 (internal), SEC-008, SEC-010, SEC-015, SEC-017, SEC-021, SEC-025, SEC-026 statuses and text; new SEC-032 (digest determinism) |
| `testing_strategy.md` | Rev. 4: AT-06, AT-26 revised (capacity fails closed, no eviction); AT-28–AT-39 added; C-17 obligations mapped |
| `threat_model.md` | Rev. 4: T-17, T-18 updated; T-21 (guard capacity exhaustion) added |
| `architecture_assessment.md` | Rev. 4: claim/guard step, internal async entry, diagnostics, approvals table |
| `implementation_plan.md` | Rev. 4: C-03 gate and scope; optional C-03a; C-10, C-11, C-16 updated; explicit C-17 obligations table in C-16 |

**Rev. 6 (operational refusals; C-03 gate) changes:** this file (header; C1.2; C1.4 rules 2, 5, 6; C1.6 rev. 6 table and invariants; C1.7; C1.8; C2.7; C3.5 rules 3, 8; C4.3; D-27, D-31 lines; §8.6 rev. 6; §12; §14.R6); `requirements.md` rev. 7; `testing_strategy.md` rev. 7; `architecture_assessment.md` rev. 7; `implementation_plan.md` rev. 7; `threat_model.md` unchanged. **No code change** (C-03 blocked).

**Rev. 5 (Q-03c) changes:** this file (header; C1.4 rule 2; C1.6 decision type, rules and invariants; C1.8; C3.5 rule 3; C4.3; D-03, D-14, D-24d, D-24i; §8.6; §12; §14.R5); `requirements.md` rev. 6; `testing_strategy.md` rev. 6; `threat_model.md` rev. 6; `architecture_assessment.md` rev. 6; `implementation_plan.md` rev. 6. No code change.

**Rev. 4 (owner answers; C-03a) changes:** this file (header; C1.2 credentials default; C1.3 rev. 4 note; C1.5 exact order and tie-break; C1.6/C1.8 notes and Q-03c; D-03, D-04, D-06, D-08, D-14, D-15 status lines; D-24c/d/i rows; §8.6 rev. 4 gate; §12 rows; §14.R4); `requirements.md` rev. 5; `testing_strategy.md` rev. 5; `threat_model.md` rev. 5 (T-03 note); `architecture_assessment.md` rev. 5; `implementation_plan.md` rev. 5 (C-03a authorized and narrowed to the owner's scope). **Code (C-03a only):** `src/sentinel/action.py`, `tests/unit/test_action.py`.

## 14. Final contract gate review: D-03, D-04, D-06, D-08, D-14, D-15, D-24c, D-24d (rev. 3)

**Method.** For each decision, the recorded recommendation was compared with what the owner has **explicitly** approved. That includes the approved decisions in §12 and the contract requirements the owner stated directly in the C-02b finalization instruction:
- "Every decision is bound to the exact validated action."
- "Decision claiming is atomic and single-use."
- "The proxy is the only component that calls the original wrapped tool."
- "Denied and approval-required calls never execute."
- "Post-execution failures are never falsely reported as proof of non-execution."
- "Cancellation does not silently become a denial."
- "Retries cannot repeat an action merely because a completion or audit operation failed."
- "Framework limitations are explicit."

A decision is recorded as Approved only if those already settle **every** choice in it. **None of the eight passes that test.** Each has parts that are settled and at least one genuine choice that is not. The brief's "[REC]s apply unless the user rejects" clause was **not** treated as explicit approval.

### D-03 — post-execution audit failure (Proposed)
- **Settled:** not reported as DENY or as non-execution (owner contract requirements); the framework adapter returns a fixed-text in-tool error and never raises into the framework (D-26); no re-execution (D-26, C1.7).
- **Conflict found:** the recorded recommendation (c) says "*adapters raise `ToolExecutionError`*". That contradicts D-26 for the framework adapter, so (c) cannot be approved as written. It must at least be amended to "direct callers only".
- **Q-03a: when a post-execution audit write fails, is the tool's output released to a direct caller?**
  - A. Withhold it (`output_released=False`, `audit_complete=False`, `error_code=AUDIT_UNAVAILABLE`): recorded recommendation.
  - B. Release it, with `audit_complete=False`.
- **Q-03b (also D-24d): for direct callers of `evaluate_request`, are request outcomes returned or raised?**
  - A. Always return a `PipelineResult`; exceptions only for API misuse and `BaseException` (recorded recommendation; brief R3).
  - B. Raise `ToolExecutionError` / `AuditUnavailable` for post-execution failures.

### D-04 — trusted identity and credentials (Proposed)
- **Settled:** agent identity is trusted, supplied by application code (D-31 approval: "trusted agent identity"; D-12 scope binds `agent_id` at wrap time).
- **Q-04a: credentials.**
  - A. Optional per agent; `require_credentials` flag, default `False` (recorded recommendation; brief §6.2).
  - B. Optional per agent; flag default `True`.
  - C. Mandatory signed tokens.
- **Q-04b: reserved identity keys (`agent_id`, `session_id`, `auth_token`, `request_id`, `tool_call_id`) inside `arguments`.**
  - A. Reject with DENY `INVALID_REQUEST` (recorded recommendation).
  - B. Strip silently and continue.

### D-06 — destructive tools (Proposed)
- **Settled:** REQUIRE_APPROVAL never executes in v1 (owner contract requirements).
- **Q-06a: how is `destructive` declared?**
  - A. Required keyword, no default (recorded recommendation).
  - B. `destructive: bool = False` (brief R10).
  - C. Default `True`.
- **Q-06b: `require_approval_for_destructive` default.**
  - A. `True`, so destructive tools are unusable until the owner opts out (recorded recommendation).
  - B. `False`.

### D-08 — validation and schemas (Proposed)
- **Settled by D-07:** a decision covers one exact *validated* action in *canonical* form, and a differing action is rejected. So there is no re-validation or coercion between evaluation and execution (brief option (a)'s proxy re-validation is excluded).
- **Q-08a: is an `arg_schema` required?**
  - A. For every tool (recorded recommendation).
  - B. Only for tools with `path_args`.
  - C. Optional.
- **Q-08b: validation mode at the gateway.**
  - A. Strict, no type coercion (recorded recommendation).
  - B. Pydantic's default lax mode (e.g. `"5"` → `5`).
  - Note: through the framework adapter, the framework has already coerced values before Sentinel sees them (C-02 F7). Q-08b matters mainly for direct callers.
- **Q-08c: extra (undeclared) argument keys.**
  - A. Forbidden, rejected (recorded recommendation).
  - B. Ignored and dropped.

### D-14 — result model, remainder (Partly approved)
- **Settled:** the `execution` dimension with values including `unknown` (C1.6 amendment, SEC-027); truthful execution reporting (owner contract requirements).
- **Q-14: the rest of the result shape.**
  - A. Separate fields `execution`, `output_released`, `audit_complete`, `error_code` (recorded recommendation, C1.6).
  - B. A single `outcome` enum.
  - C. The brief's `PipelineResult(request_id, decision, reason, tool_result)` plus only `execution`.

### D-15 — policy authority and inputs (Proposed)
- **Settled:** the proxy is the only caller of tools (owner contract requirements); a decision is bound to the tool identity (D-07).
- **Q-15: authority and the Tool-Abuse detector.**
  - A. Policy is the sole ALLOW/DENY authority; `evaluate(request, context, findings, tool_spec)`; the PDF's Tool-Abuse detector is dropped from v1 (recorded recommendation).
  - B. As A, but keep a Tool-Abuse detector that only emits informational findings using the same helper (brief R8).
  - C. Policy reads tool metadata from the registry itself.

### D-24c — precedence and severity (Proposed)
- **Settled:** both DENY and REQUIRE_APPROVAL never execute, so precedence changes the *reported* outcome, not whether a call runs.
- **Q-24c: evaluation order and thresholds.**
  - A. Brief R4 order (DENY checks before the approval check), deterministic tie-break (highest severity, then code order), deny at ≥ HIGH, risk score informational (recorded recommendation; brief R4, R7).
  - B. PDF §4.4 order (approval check before findings).
  - C. As A but deny only at CRITICAL.

### D-24d — return vs raise (Proposed)
- **Settled:** the framework adapter does not raise into the framework (D-26).
- **Open:** identical to Q-03b.

### Also found: D-24i and D-24b
These were not listed in the previous C-03 gate but shape C-03 models:
- **Q-24i:** `Decision` enum string values lowercase (`"allow"`) as recommended, or uppercase; class name `SentinelClient`; module `audit.py`.
- **D-24b:** tool-name grant granularity. It only blocks C-03 if `ToolGrant` stays in C-03's scope.

### Derived rules recorded in rev. 3 (confirm)
See the "Interpretations recorded in rev. 3" list in §12.

### 14.R4 Owner answers reconciled (rev. 4)

| Question | Owner answer | Matches recorded option | Result |
|---|---|---|---|
| Q-03a | withhold output; separate fields | A (recommendation) | D-03 Approved |
| Q-03b | structured result for handled failures | A (recommendation) | D-03, D-24d Approved; **Q-03c opened** |
| D-03/D-26 | fixed-text adapter error; no diagnostics exposed; no retry-triggering escape; diagnostics to audit | consistent with D-26 | recorded |
| Q-04a | per-agent credentials; `require_credentials=True` default; no mandatory signed tokens | **B** (not the recommendation A) | D-04 Approved |
| Q-04b | reject reserved keys | A | D-04 Approved |
| Q-06a / Q-06b | explicit `destructive`, no default; approval required by default | A / A | D-06 Approved |
| Q-08a–c | schema for every tool; strict; extra keys rejected | A / A / A | D-08 Approved |
| Q-14 | separate fields | A | D-14 Approved (complete) |
| Q-15 | registry authoritative for metadata, policy evaluates it; no detector as an allow/deny authority | **A–C partially**: does not choose explicit `tool_spec` vs lookup, nor informational detector yes/no | D-15 **partly** approved |
| Q-24c | brief order, deterministic tie-break, deny at HIGH; document exactly | A | D-24c Approved; rule documented in C1.5 |
| Q-24i | lowercase serialized values | A (values only) | D-24i **partly** approved |

**Q-03c (new, blocks full C-03): how is an unexpected programming error *before invocation* represented?**

The current C1.8 bullet maps any unexpected `Exception` in a pre-invocation stage to `decision="deny"`, reason `INTERNAL_ERROR`. The call is not executed, and there is no policy DECISION event when policy did not run. The owner's answer says such errors "must not be falsely represented as policy denials". Options:
- **A.** Keep `decision="deny"` (the effective, enforced outcome) with `reason="INTERNAL_ERROR"` and `error_code="INTERNAL_ERROR"`, and document that `INTERNAL_ERROR` denials are fail-closed errors, never policy outcomes. The audit then has no policy DECISION event for them.
- **B.** Add a distinct non-policy outcome for these cases (for example `decision=None`, or a fourth serialized value such as `"error"`), so `"deny"` only ever means a policy or enforcement decision. This changes D-24i's value set and the C1.6 invariants.
- **C.** Write the audit record (when possible) and then re-raise the unexpected exception to the caller instead of returning a result. Still not executed, but `evaluate_request` raises.

No option is recorded as chosen.

**D-15 remainder (blocks C-08, not C-03a or C-03 models):**
- (i) explicit `tool_spec` parameter vs a registry lookup inside policy;
- (ii) an informational-only Tool-Abuse detector in v1: yes or no.

**Also still open:**
- D-24b, but only if `ToolGrant` stays in C-03;
- D-24i class and module names (C-09, C-12);
- D-31 TTL and capacity default values (C-10);
- the decisions listed in §8.6 "may safely remain open".

### 14.R5 Q-03c resolved (rev. 5)

- **Owner choice:** Option B as recorded in §14.R4, *without* the `"error"` decision-value variant (explicitly excluded by the owner). The remaining form of B is `decision=None`, plus a result-kind field only "if needed".
- **Recorded representation:** `decision=None`, `reason="INTERNAL_ERROR"`, `error_code="INTERNAL_ERROR"`; before execution, `execution="not_started"` and `output_released=False`. Audit: ERROR with D-29 diagnostics plus REQUEST_COMPLETED with NULL `decision`, best effort. Fail closed (C1.6, C1.8).
- **Judgement recorded for owner visibility:**
  - no result-kind field is added, because `decision=None` with `error_code="INTERNAL_ERROR"` is unambiguous and adding a field would change the approved D-14 field set;
  - `reason` keeps the existing stable code `INTERNAL_ERROR` rather than becoming nullable.

  Either can be revisited at the C-03 gate review.
- **Open consistency question (non-blocking unless the owner decides otherwise):** Q-03c covers *unexpected internal* failures. Anticipated, handled non-policy outcomes are still represented as `decision="deny"` with their own reason codes: request validation (`INVALID_REQUEST`), pre-execution audit unavailability (`AUDIT_UNAVAILABLE`), and proxy-stage enforcement blocks (`ACTION_MISMATCH`, `RESTRICTED_PATH`, `DECISION_ALREADY_USED`, `DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED`). They are enforcement outcomes, not internal errors, and the owner's wording does not reclassify them. Should any of them also be separated from `"deny"`? This should be confirmed at the C-03 gate review.

### 14.R6 Operational refusals reclassified; C-03 gate (rev. 6)

- **§14.R5 open question resolved by the owner:** request validation, pre-execution audit unavailability and proxy-stage refusals are **not** policy decisions. They carry `decision=None` (or, for `AUDIT_UNAVAILABLE`, the actual policy decision if one was reached) with their specific error code. Authoritative table: C1.6 (rev. 6).
- **Recorded as decided, with no further action:** an allowed request that fails the pre-execution audit keeps `decision="allow"` (because a policy decision was reached), whereas an allowed request refused by the proxy (mismatch, path changed, already used, duplicate id, guard full) reports `decision=None` "for the refused attempt". Both never execute. The difference is the owner's explicit choice and is recorded as such.
- **`RESTRICTED_PATH` is used twice:** as a policy-denial reason (C1.5 row 3, `decision="deny"`) and as the path-changed refusal code (`decision=None`). The owner's instruction to "preserve its specific error code" keeps the existing code; the two cases are told apart by `decision`. If the owner wants a distinct code (e.g. `PATH_CHANGED`), that is a new decision.
- **C-03 gate:** see §8.6 rev. 6. Approval ✅; `ToolGrant` exclusion clean ✅; **blocked by the Pydantic runtime dependency** (options A/B).
