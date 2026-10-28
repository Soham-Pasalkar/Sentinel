# Decision Record and Reconciled Contracts — Sentinel v1 (AI-DLC Phase 1.5)

| | |
|---|---|
| Phase | 1.5 — Decision lock and contract reconciliation |
| Date | 2026-10-28 |
| Decision owner | Soham Pasalkar |
| Status | **No decision in this record is Approved.** Every entry is *Proposed* (a recommendation ready for owner review) or *Pending* (needs information or an experiment first). |
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

---

## 1. Core execution contract (C1)

### C1.1 Request identity

- The pipeline assigns `request_id` (UUID4, string form) and `received_at` (timezone-aware UTC) **before** any validation. Every audit event and result for that call carries this `request_id`. [EXISTING PDF §4.1; INCEPTION FR-002]
- `session_id` is supplied by trusted application code and is used **only for correlation** in v1. It has no security role, and rate limits (M4) are keyed by `agent_id`. [PHASE-1.5; INCEPTION T-14]

### C1.2 Trusted agent identity and capability grants

- `agent_id` is **trusted input from application code**. Both public entry points take it from trusted code, never from model output:
  - `SentinelClient.evaluate_request(raw)`: the documented contract is that `raw` is constructed by application code. The model's tool-call payload maps only to `raw["tool"]` and `raw["arguments"]`.
  - Framework adapters: `agent_id` is a required parameter at wrap time (C3.2).
- `raw["arguments"]` must not contain the reserved keys `agent_id`, `session_id`, `auth_token`, `request_id` → DENY `INVALID_REQUEST`.
- Credentials are optional per agent (PDF "if used"). If an agent has a stored credential hash, the request must present a matching `auth_token` (compared as SHA-256 digests with `hmac.compare_digest`). `SecurityPolicy.require_credentials: bool = False` lets a deployment require credentials for all agents. [BRIEF §6.2; INCEPTION CF-12]
- Grants: `CapabilityEnvelope{agent_id, grants: tuple[ToolGrant, ...]}`; `ToolGrant{tool, allowed_path_prefixes: tuple[str, ...] = (), rate_limit: RateLimit | None}`. ALLOW is reachable only for a tool with a grant (default deny). [BRIEF R5]

### C1.3 Tool metadata required by policy

`ToolSpec` (metadata only; the registry holds the callable beside it, never inside it):

| Field | Type | Rule |
|---|---|---|
| `name` | `str` | Unique in the registry; re-registration is rejected |
| `arg_schema` | Pydantic model class | **Required** (D-08). Must forbid extra fields; validated in strict mode |
| `destructive` | `bool` | **Required keyword**, no default (D-06) |
| `path_args` | `tuple[str, ...]` | Default `()`. Each name must be a top-level `str` field of `arg_schema` |

Policy receives the `ToolSpec` explicitly: `PolicyEngine.evaluate(request, context, findings, tool_spec) -> SecurityDecision`. [INCEPTION CF-07]

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

   Otherwise it does not invoke the tool. The **effective** decision becomes DENY with reason `ACTION_MISMATCH` (binding or digest), `RESTRICTED_PATH` (re-resolution) or `INTERNAL_ERROR` (registry lookup), and `execution="not_started"`. The DECISION audit event still shows policy's `allow`; REQUEST_COMPLETED shows the enforced `deny`.
3. The tool is called as `fn(**deepcopy(action.arguments))`. A tool that mutates its arguments therefore cannot change what was audited.
4. **Limit, stated plainly:** the digest is an integrity check against accidental divergence and mutation inside the process. It is **not** a cryptographic authorization token. Code in the same process can forge a decision (C6).

[PHASE-1.5, refining INCEPTION CF-08 and OD-09]

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
4. Highest finding severity ≥ `deny_at_severity` → DENY with that finding's code (ties broken by code order)
5. Rate limit exceeded (M4) → DENY `RATE_LIMIT_EXCEEDED`
6. Destructive and approval required → REQUIRE_APPROVAL
7. Otherwise → ALLOW

Enum values: `Decision.ALLOW = "allow"`, `DENY = "deny"`, `REQUIRE_APPROVAL = "require_approval"`. No `RESTRICT` in v1. [BRIEF R9]

### C1.6 Execution outcomes (result model)

```text
PipelineResult (frozen)
  request_id      : str
  decision        : Decision        # the EFFECTIVE decision that was enforced
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
| `unknown` | Whether or how the function completed cannot be established | **Not produced by the in-process pipeline in v1.** It is the state an audit reader must assign to a request that has `EXECUTION_STARTED` but no `REQUEST_COMPLETED` (crash, kill, post-execution audit loss; C4.4). Reserved for future timeouts or cancellation |

**Invariants:**
- `decision != ALLOW ⇒ execution == "not_started"`.
- `execution != "not_started"` is **never** paired with a DENY decision. A failure after invocation never turns into a DENY.
- `output_released ⇒ execution == "succeeded" ∧ audit_complete`.

### C1.7 Audit behaviour (pre- and post-execution)

| Phase | Events (C4.3) | On write failure |
|---|---|---|
| Pre-execution | REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING×n, DECISION, EXECUTION_STARTED (ALLOW only) | Tool **not** invoked. Effective decision DENY `AUDIT_UNAVAILABLE`; `execution="not_started"`; `audit_complete=False`. Each event is **committed** before the next stage runs |
| Post-execution | OUTPUT_FILTERED / OUTPUT_WITHHELD (if applicable), REQUEST_COMPLETED | Decision stays ALLOW; `execution` reports the truth (`succeeded`/`failed`); `output_released=False`; `audit_complete=False`; `error_code="AUDIT_UNAVAILABLE"`; best-effort record to the Python `logging` module (masked). The side effect is **not** undone, and the result says so |
| Non-ALLOW terminal | REQUEST_COMPLETED | Decision stays DENY/REQUIRE_APPROVAL; `audit_complete=False` |

[BRIEF R12; INCEPTION CF-09 option B, refined: the pipeline returns instead of raising]

### C1.8 Error handling and safe failure

- `SentinelClient.evaluate_request` **returns** a `PipelineResult` for every request outcome. It raises only for misuse of the API, such as a non-mapping `raw` argument, and lets `BaseException` (e.g. `KeyboardInterrupt`) propagate. [BRIEF R3; PHASE-1.5]
- Any `Exception` in a security-critical stage **before invocation** (gateway, identity, detector, policy, registry lookup, proxy checks) → DENY `INTERNAL_ERROR`, `execution="not_started"`.
- Tool `Exception` → `execution="failed"`, `error_code="TOOL_FAILED"`. Only the exception **type name** is recorded.
- Output-filter `Exception` → `output_released=False`, `error_code="OUTPUT_FILTER_FAILED"`.
- Reason codes and error codes are stable constants. No exception message, stack trace, SQL or file path reaches the result.
- Adapters map results to exceptions: `ActionDenied` (DENY), `ApprovalRequired` (REQUIRE_APPROVAL), `ToolExecutionError(execution=…, audit_complete=…)` (ALLOW without released output). All are `SentinelError` subclasses.

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
| C2.7 Proxy re-resolution | Immediately before invocation the proxy recomputes `os.path.realpath(canonical)`. If the result differs (a component became a symlink since the check) or falls outside the prefixes, the tool is not invoked (`execution="not_started"`, `error_code="RESTRICTED_PATH"`). |
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

### C3.2 Interception (recommended API, D-12)

```text
sentinel.integrations.langgraph.wrap_tools(
    tools, *, client: SentinelClient, agent_id: str, session_id: str | None = None
) -> list[<framework tool objects>]
```

- Each input tool's underlying function is moved into the Sentinel registry. Registration metadata (`destructive`, `arg_schema`, `path_args`) is provided by the caller; for example, a mapping is required for every wrapped tool. The returned objects' sync execution path calls `client.evaluate_request` with the bound identity.
- The async execution path of every returned object **raises `SentinelError` and never calls the original** until async support is designed (SEC-016).
- On DENY or REQUIRE_APPROVAL the wrapper raises `ActionDenied` / `ApprovalRequired`. Whether the framework surfaces this to the model as a tool error message or halts the graph is decided after the experiment (C3.4, E3).

### C3.3 The guarantee, narrowed

> **Guaranteed:** every invocation of a tool object **returned by `wrap_tools`**, through its synchronous execution path, is evaluated by Sentinel before the underlying function runs, and the function runs only on ALLOW.
>
> **Not guaranteed:** tools that were not wrapped; references to the original function kept elsewhere; graph nodes or application code that call functions directly; async execution (which fails closed); other framework APIs or versions outside the tested range; anything that happens inside the model.

The PDF/brief API `SentinelClient(policy).protect(workflow)` is **not** offered in v1, because it implies graph-wide coverage that cannot be enforced (D-12).

### C3.4 LangGraph feasibility experiment — specification only (NOT executed in this phase)

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
  ├─ invalid ─────────────────────────► DECISION(deny, INVALID_REQUEST) ─► REQUEST_COMPLETED(not_started)
  └─ IDENTITY_RESOLVED → FINDING×n → DECISION
        ├─ deny / require_approval ───► REQUEST_COMPLETED(not_started)
        └─ allow → EXECUTION_STARTED ─► [OUTPUT_FILTERED | OUTPUT_WITHHELD] ─► REQUEST_COMPLETED(succeeded|failed|not_started*)
ERROR events may appear at any point (type name and stage only).
* not_started after EXECUTION_STARTED = proxy binding or re-resolution check blocked the call.
```

Every event up to and including EXECUTION_STARTED is **committed** before the next stage runs (C1.7).

### C4.4 Reconstruction rules for audit readers (normative)

| Events present for a `request_id` | Execution status |
|---|---|
| No DECISION, or DECISION ≠ allow | **Not executed** (guaranteed) |
| DECISION = allow, no EXECUTION_STARTED | **Not executed** (guaranteed: EXECUTION_STARTED is committed before invocation) |
| EXECUTION_STARTED and REQUEST_COMPLETED | As recorded in `REQUEST_COMPLETED.execution` |
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

| Contract | Requirements (rev. 2) | Acceptance tests (`testing_strategy.md` rev. 2) |
|---|---|---|
| C1.1 request identity | FR-002 | `test_fr002_*`, NI-12 |
| C1.2 identity and grants | FR-005–007, SEC-001, SEC-004, SEC-013 | identity suite, E2E-04, E2E-08, NI-10 |
| C1.3 tool metadata | FR-010, FR-008 | registry suite, policy truth table |
| C1.4 action binding | SEC-010, SEC-021 | NI-08, NI-09, NI-13, proxy forged/mutated-action tests |
| C1.5 policy outcomes | FR-008, SEC-002, SEC-003, SEC-012 | truth table §4, NI-01, NI-02 |
| C1.6 execution outcomes | FR-017, SEC-022 | NI-07, NI-14, fault-injection matrix §6 |
| C1.7 audit behaviour | FR-012, SEC-005, SEC-006 | NI-04, NI-06, NI-15, audit fault injection |
| C1.8 errors | SEC-009, SEC-017, FR-018 | fault-injection matrix, canary test |
| C2 filesystem | SEC-007 | path matrix §5 (F1–F20) |
| C3 identity/integration | SEC-013, SEC-016, FR-021 | E1–E8 (experiment), adapter tests at C-16 |
| C4 persistence | FR-012, FR-024, SEC-018, SEC-023 | audit repository suite, reconstruction tests, durability test |

---

## 6. Residual risks this contract does NOT remove

In-process bypass (forged decisions, direct function calls, monkey-patching); prompt injection in general; free-form argument misuse within a granted tool; the path TOCTOU window and hard links; tamper with the audit file; side effects of a tool that ran before an audit or filter failure. See `threat_model.md` rev. 2.

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

### D-04 — Trusted agent identity
- **Q:** Where does `agent_id` come from?
- **Options:** (a) from the request dict, whatever its origin; (b) **from trusted application code: the `raw` dict built by the app, or the adapter's `agent_id` parameter; reserved keys rejected inside `arguments`; credentials optional with a `require_credentials` flag**; (c) mandatory signed tokens.
- **Rec.:** (b).
- **Rationale:** the realistic attacker is the model. Binding defeats model-supplied identity. Tokens held in the same process add little against in-process code (C6).
- **Consequences:** security: an integration that reads identity from model data voids envelope isolation, so this is documented as a hard rule. Engineering: adapters need an `agent_id` parameter.
- **Approval:** required. **Status:** Proposed. **Affects:** C1.2, C3, SEC-013, FR-005/006, T-03. **Source:** BRIEF §1, §6.2; INCEPTION CF-12.
- **Rejected:** (a) spoofable; (c) disproportionate for an in-process library in v1. Kept as a future option.

### D-05 — Missing or empty path grants
- **Q:** What does a path tool's grant without `allowed_path_prefixes` mean?
- **Options:** (a) unrestricted (brief's `None` default); (b) **deny every call; unrestricted only via explicit `("/",)`**; (c) registration error.
- **Rec.:** (b), plus a warning at registration.
- **Rationale:** a missing constraint must not widen access (default deny). (c) would stop the configuration of a grant that the owner intends to fill in later.
- **Consequences:** security: fails closed. Engineering: an explicit `"/"` is needed for broad access.
- **Approval:** required. **Status:** Proposed. **Affects:** C2.1–C2.2, SEC-007, policy truth table. **Source:** INCEPTION CF-13.
- **Rejected:** (a) fails open.

### D-06 — Destructive tools and approval
- **Q:** How is "destructive" declared, and what happens to REQUIRE_APPROVAL?
- **Options:** (a) `destructive: bool = False` (brief); (b) **required keyword with no default**; (c) default `True`. And for approval: (i) **never executes in v1**; (ii) an approve-and-replay API.
- **Rec.:** (b) + (i). `require_approval_for_destructive=True` by default, so destructive tools are unusable in v1 unless the owner sets it to `False`.
- **Rationale:** forces a conscious classification of every tool; the PDF puts the approval workflow out of scope.
- **Consequences:** security: no fail-open default on the highest-impact control. Engineering: slightly more verbose registration; destructive tools are blocked by default.
- **Approval:** required. **Status:** Proposed. **Affects:** C1.3, C1.5, FR-010, SEC-003, T-10. **Source:** EXISTING PDF §4.4, §7; BRIEF R9, R10; INCEPTION CF-04, CF-16.
- **Rejected:** (a) fails open; (c) noisy; (ii) out of scope.

### D-07 — Binding decisions to request and action
- **Q:** How does the proxy know it is executing what policy evaluated?
- **Options:** (a) nothing beyond the decision value (PDF); (b) `request_id` match (Inception); (c) **`AuthorizedAction` embedded in the decision, plus digest verification; the proxy executes only `decision.action`**; (d) HMAC-signed decisions with a per-process key.
- **Rec.:** (c).
- **Rationale:** guards against divergence and nested mutation between policy and proxy at low cost. (d) adds no real protection in-process, because the key is reachable by the same code.
- **Consequences:** security: SEC-010/021 become exactly testable. Engineering: arguments must be JSON-serialisable after validation (also needed for the audit).
- **Approval:** required. **Status:** Proposed. **Affects:** C1.4, SEC-010, SEC-021, FR-011, C-03/C-10. **Source:** INCEPTION CF-08; PHASE-1.5.
- **Rejected:** (a), (b) insufficient; (d) false sense of security.

### D-08 — Strict validation, a single coercion, required schemas
- **Q:** How are arguments validated, and is `arg_schema` mandatory?
- **Options:** (a) optional schema, lax validation, re-validation in the proxy (brief); (b) strict validation once, schema required only for path tools; (c) **strict validation once in the gateway, schema required for every tool, extra fields forbidden, the proxy executes the validated values unchanged (no second validation)**.
- **Rec.:** (c).
- **Rationale:** one validation means one meaning. The digest and the audit need a known shape.
- **Consequences:** security: removes the coercion mismatch (B3). Engineering: every tool needs a small Pydantic model. Adapters can derive it from framework tool schemas (confirmed by the experiment).
- **Approval:** required. **Status:** Proposed. **Affects:** FR-004, FR-010, SEC-010, T-13. **Source:** BRIEF §6.5; INCEPTION OD-09.
- **Rejected:** (a) check/use mismatch; (b) leaves schema-less tools unvalidated.

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
- **Approval:** required (also for installing LangGraph in the separate spike environment). **Status:** **Pending**: depends on the E1/E2/E7 results. **Affects:** C3, FR-021/022, SEC-016, C-02, C-16. **Source:** EXISTING PDF §1, §5; INCEPTION CF-18.
- **Rejected:** (a) unenforceable.

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
- **Approval:** required (public result shape). **Status:** Proposed. **Affects:** C1.6, FR-017, SEC-022, C-03. **Source:** BRIEF R3; INCEPTION CF-05.

### D-15 — Policy owns authorization; policy receives tool metadata
- **Q:** Which component decides, and with what inputs?
- **Rec.:** policy is the sole authority; `evaluate(request, context, findings, tool_spec)`; the Tool-Abuse detector is dropped from v1; containment is one pure function.
- **Options rejected:** a detector duplicating capability checks (PDF §4.3); policy reaching into the registry (hidden I/O).
- **Approval:** required (changes the PDF interface, drops a PDF-named detector). **Status:** Proposed. **Affects:** C1.3, FR-008, FR-014. **Source:** BRIEF R8; INCEPTION CF-07.

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

### D-19 — Output filter failure and M3 mode
- **Q:** What happens when the filter fails, and what is the M3 default?
- **Rec.:** failure → output withheld (from M1). M3 default mode `redact`. Unsupported output types → withheld in `enforce` mode.
- **Approval:** required for the M3 mode only. **Status:** Proposed (failure rule) / Pending until M3 (mode). **Affects:** FR-015, SEC-011. **Source:** EXISTING PDF §4.5; INCEPTION CF-14.

### D-20 — Concurrency
- **Q:** What concurrency does v1 support?
- **Rec.:** thread-safe synchronous use within one process; async fails closed; one SQLAlchemy session per request (or serialised writes); atomic rate-limit check-and-record (M4).
- **Approval:** confirm. **Status:** Proposed (final after E5). **Affects:** NFR-016, FR-019. **Source:** INCEPTION OD-08.

### D-21 — Supported operating systems
- **Q:** Which platforms are supported?
- **Rec.:** Linux and macOS. On Windows, registering a path-constrained tool raises `ConfigurationError`. CI on `ubuntu-latest` and `macos-latest`.
- **Approval:** required. **Status:** Proposed. **Affects:** NFR-012, C2. **Source:** INCEPTION OD-10.

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
| D-24b | Grant granularity = tool name (no sub-actions) | Adopt | Proposed | BRIEF §1; CF-02 |
| D-24c | Precedence R4 with deterministic tie-break; risk score informational; deny at ≥ HIGH | Adopt | Proposed | BRIEF R4, R7; CF-03 |
| D-24d | `evaluate_request` returns, adapters raise | Adopt | Proposed | BRIEF R3; CF-05 |
| D-24e | Detector `analyze(request, context)`; recursive string scan; detector failure → DENY | Adopt | Proposed | BRIEF R6; CF-06 |
| D-24f | Audit wording "append-only through Sentinel's API"; never "immutable" | Adopt | Proposed | BRIEF R19; CF-10 |
| D-24g | Known-limitations section (in-process boundary, heuristic detection, invisible LLM context, no timeouts) | Adopt | Proposed | BRIEF R17; CF-11 |
| D-24h | Injection detection described as advisory | Adopt | Proposed | BRIEF §1; CF-15 |
| D-24i | Class `SentinelClient`; module `audit.py`; lowercase decision values | Adopt | Proposed | BRIEF R2, R15; CF-17 |

Approval: one confirmation covers the bundle; individual items may be rejected.

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
| **C-03** (models and contracts) | D-03, D-04, D-06, D-07, D-08, D-14, D-15, D-24c, D-24d |
| **C-04** (path guard) | D-05, D-18, D-21 |
| **C-09** (audit store) | D-09, D-11, D-24f |
| **C-11** (pipeline) | D-16, D-20 |

If any of these is rejected, the affected contract section is revised and re-reviewed before the increment starts. None may be bypassed by "implement now, decide later".

### 8.4 Framework feasibility questions for the isolated experiment

E1–E8 (C3.4) settle D-12 and refine D-20 and the adapter part of D-04. The experiment needs owner approval to install LangGraph/LangChain in a separate environment. It runs as C-02, after C-01 and before C-03, so that a negative E1 or E2 result can still change the C1 contracts.

### 8.5 Gate checklist (G-0)

- [x] Owner has read `decision_record.md` (this file) and the rev. 2 documents. *(Implied by the owner's C-01 instruction of 2026-10-28.)*
- [x] D-01, D-02, D-13, D-22, D-23 set to Approved (or Rejected with a replacement recorded). *(2026-10-28; D-02 provisional, D-22 partial; see §12.)*
- [x] Owner instruction: "begin C-01". *(2026-10-28; C-01 committed locally as `8a5a993`.)*
- [ ] (For C-02) owner approval to install LangGraph in the spike environment.
- [ ] (Before C-03) every decision in §8.3's C-03 row Approved, and the C-02 report reviewed.

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
