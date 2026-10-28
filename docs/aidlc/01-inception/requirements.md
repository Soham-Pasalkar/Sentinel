# Requirements Specification — Sentinel v1 (AI-DLC Inception, rev. 2)

| | |
|---|---|
| Phase | Inception, revised in Phase 1.5 (decision lock) |
| Date | 2026-10-28 (rev. 1 and rev. 2) |
| Owner | Soham Pasalkar |
| Status | **Draft. No requirement is approved.** Contracts referenced here are defined in [`decision_record.md`](decision_record.md) (C1–C4); decisions are D-01 … D-24 |

## 0. Conventions

- **Priority:** **MUST** (mandatory for v1 as specified), **SHOULD** (recommended for v1; can slip to a later milestone without breaking the core promise), **COULD** (optional).
- **Source:** `DOC` = architecture PDF; `BRIEF` = `SENTINEL_BUILD_BRIEF.md`; `DIAG` = diagram; `NEW` = Inception; `P1.5` = Phase 1.5.
- **Status:**
  - `Proposed`: no open decision affects the wording.
  - `Pending D-xx`: the wording depends on that decision.
  - `Approved`: **not used yet**. Only the owner can set it.
- **Verification:** **T** = automated test, **I** = inspection, **D** = demonstration, **A** = analysis or documentation review.
- **Milestone:** M1 = enforcement skeleton; M2 = detection; M3 = output filter; M4 = rate limits; M5 = framework integration.
- "**Not invoked**" means the registered function's spy call count stays at 0. In results it appears as `execution="not_started"`.

### Core invariant

> A tool invocation that Sentinel denies, or that awaits approval, is never executed. A tool executes only after Sentinel explicitly authorizes **that exact action** (C1.4). Every decision is audited, or the call does not execute (C1.7).

**Scope:** the invariant holds for calls routed through Sentinel. Sentinel is an in-process library and cannot stop code in the same process from bypassing it (`decision_record.md` §6).

---

## 1. Functional requirements

| ID | Requirement | Pri | Source | Status | Verif. | Acceptance criterion | MS |
|---|---|---|---|---|---|---|---|
| FR-001 | The pipeline accepts a raw mapping with `agent_id`, `session_id`, `tool` (non-empty str), `arguments` (mapping) and optional `auth_token`, and validates presence and types. | MUST | DOC §3, §4.1 | Proposed | T | Each missing field, wrong type, non-mapping `arguments`, or empty string → DENY `INVALID_REQUEST`, not invoked; audit has REQUEST_RECEIVED, DECISION, REQUEST_COMPLETED for the request. | M1 |
| FR-002 | Each request gets a unique `request_id` (UUID4) and UTC `received_at` **before** validation (C1.1). | MUST | DOC §4.1; NEW | Proposed | T | 1,000 requests → 1,000 distinct ids; timestamps are timezone-aware UTC; an invalid request's events share one `request_id`. | M1 |
| FR-003 | A request naming an unregistered tool → DENY `INVALID_REQUEST`. | MUST | DOC §4.1 | Proposed | T | No registered tool invoked. | M1 |
| FR-004 | Arguments are validated **once, in the gateway, before policy**, against the tool's required `arg_schema`, in strict mode with extra fields forbidden. Path arguments are then canonicalised (C2.3–C2.4). The result is the `AuthorizedAction` candidate that policy evaluates and the proxy executes, with **no second validation or coercion**. | MUST | DOC §4.5; P1.5 | Pending D-08, D-18 | T | Schema violation → DENY `INVALID_REQUEST`. `"1"` for an `int` field is rejected. Extra argument key → rejected. Mutating the caller's dict after submission does not change the executed arguments. | M1 |
| FR-005 | Identity resolves the agent; unknown or disabled → `authorized=False`. | MUST | DOC §4.2 | Proposed | T | Each case → DENY `UNAUTHORIZED_AGENT`, not invoked. | M1 |
| FR-006 | Credentials: if an agent has a stored credential hash, or `require_credentials=True`, the request must present a matching `auth_token`. Comparison uses `hmac.compare_digest` on SHA-256 digests; plaintext is never stored. | MUST | DOC §4.2; BRIEF §6.2 | Pending D-04 | T, I | Correct → authorized; missing or wrong → `UNAUTHORIZED_AGENT`. With `require_credentials=True`, an agent without a credential → `UNAUTHORIZED_AGENT`. | M1 |
| FR-007 | Identity loads the capability envelope; no envelope ⇒ no grants. | MUST | DOC §4.2 | Proposed | T | Any tool → DENY `UNAUTHORIZED_TOOL`. | M1 |
| FR-008 | `PolicyEngine.evaluate(request, context, findings, tool_spec)` applies C1.5 rows 1–7 (row 5 from M4) and returns a `SecurityDecision` carrying `request_id`, `decision`, `reason`, `policy_version`, `finding_codes` and the evaluated `AuthorizedAction`. | MUST | DOC §4.4; BRIEF R4 | Pending D-15, D-07, D-24c | T | Truth table and precedence pairs (`testing_strategy.md` §4) pass; every decision has a reason and `policy_version`. | M1 |
| FR-009 | `SecurityPolicy(version, deny_at_severity=HIGH, require_approval_for_destructive=True, require_credentials=False)` is constructed in code. JSON/YAML loading is SHOULD (later). | MUST / SHOULD | DOC §7; BRIEF §6.4 | Pending D-04 | T | Invalid policy → `ConfigurationError`, never a permissive policy. | M1 |
| FR-010 | Registration: unique `name`; callable; **required** `arg_schema`; **required keyword** `destructive`; optional `path_args` (top-level `str` fields of the schema). Grants for path tools take `allowed_path_prefixes`, each absolute, existing and a directory, canonicalised at registration. | MUST | DOC §5; BRIEF R10; P1.5 | Pending D-06, D-08, D-05, D-18 | T | Duplicate → `RegistrationError`. Missing `destructive` or `arg_schema` → error. A `path_args` entry not in the schema → error. A non-existent prefix → `ConfigurationError`. | M1 |
| FR-011 | Only the internal proxy invokes registered functions, and only for `decision.action` under the C1.4 checks. | MUST | DOC §4.5 | Pending D-07 | T, I | See SEC-010 and SEC-021. Inspection: no call to a registered function outside `proxy.py`. | M1 |
| FR-012 | Audit lifecycle per C4.3. Event types: REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING, DECISION, EXECUTION_STARTED, OUTPUT_FILTERED, OUTPUT_WITHHELD, REQUEST_COMPLETED, ERROR. Exactly one DECISION and one REQUEST_COMPLETED per request when audit is available. Columns per C4.2. | MUST | DOC §4.6; BRIEF §5.3; P1.5 | Pending D-09 | T | Each E2E scenario produces the expected ordered event-type sequence (`testing_strategy.md` §8); required columns are non-null where defined. | M1 |
| FR-013 | `SentinelClient.audit_events(request_id=None, limit=100)`: read-only, ordered by `seq`. | SHOULD | DIAG use case; NEW | Pending D-17 | T | Returns exactly the request's events in order; there is no public update or delete. | M1 |
| FR-014 | Detector `analyze(request, context) -> list[SecurityFinding]`. M1: stub `[]`. M2: injection keyword/pattern and sensitive-data regex over **all** string values in arguments, recursively. No Tool-Abuse detector in v1. | MUST | DOC §4.3; BRIEF §6.3 | Pending D-15, D-24e | T | M1: interface conformance. M2: table-driven positive and negative cases; nested strings scanned; evidence masked. | M1/M2 |
| FR-015 | Output-filter stage on every executed call: M1 pass-through; M3 redaction (`str`, recursively `dict`/`list`/`tuple`) in `redact` or `block` mode. | MUST | DOC §4.5 | Pending D-19 (M3 mode) | T | M1: stage invoked (spy). M3: canary redacted, or withheld in `block` mode. | M1/M3 |
| FR-016 | Public API: `SentinelClient(policy, config)`, `.register_tool`, `.register_agent`, `.evaluate_request(raw) -> PipelineResult`. `evaluate_request` **returns** for every request outcome, including DENY, REQUIRE_APPROVAL, tool failure, filter failure and audit failure. It raises only on API misuse (non-mapping `raw`), and `BaseException` propagates (C1.8). | MUST | DOC §5; BRIEF R2, R3; P1.5 | Pending D-03, D-14, D-24d, D-24i | T, D | All scenarios in testing §6 and §8 return a result without raising. | M1 |
| FR-017 | `PipelineResult{request_id, decision (effective), reason, execution ∈ {not_started, succeeded, failed, unknown}, output_released, output, audit_complete, error_code}` with the C1.6 invariants. | MUST | P1.5 | Pending D-14 | T | NI-07 and NI-14 hold for every scenario. | M1 |
| FR-018 | Exceptions: `SentinelError` ⊃ `InvalidRequestError`, `ConfigurationError`, `RegistrationError`, `ActionDenied`, `ApprovalRequired`, `ToolExecutionError(execution, audit_complete)`. | MUST | DOC §7; BRIEF §4.2; P1.5 | Pending D-03 | T, I | Every public-API exception (except `TypeError` for wrong arguments) is a `SentinelError`. | M1 |
| FR-019 | Rate limits per agent and tool, keyed by `agent_id`, checked and recorded atomically. | SHOULD | DOC §3, §4.4 | Proposed | T | N+1th → DENY `RATE_LIMIT_EXCEEDED`; rotating `session_id` does not reset; 8-thread race never exceeds N. | M4 |
| FR-020 | Alert manager: a `logging` warning on ≥ K high-severity denials per agent per window; not persisted. | SHOULD | DOC §4.6 | Proposed | T | K → one warning; K−1 → none. | M2/M4 |
| FR-021 | LangGraph integration via `wrap_tools(tools, *, client, agent_id, session_id=None)`, with the C3.3 guarantee and nothing broader. Denial raises `ActionDenied` / `ApprovalRequired` (how it surfaces to the model is settled by E3). | MUST for v1 release, conditional on C-02 | DOC §5; P1.5 | Pending D-12 | T, D | A scripted (offline) graph: allowed spy = 1, denied spy = 0; all invocation APIs covered or fail closed (E2 as a regression test). | M5 |
| FR-022 | LangChain tool wrapping, same contract. | COULD | DOC §5 | Pending D-12 | T | As FR-021. | M5 |
| FR-023 | `examples/quickstart.py` demonstrates allow, deny (traversal, ungranted, unknown agent), require-approval, and prints audit rows. | MUST | BRIEF §11 | Proposed | D, T | Exits 0; a subprocess test asserts the expected decisions. | M1 |
| FR-024 | Audit storage: a durable SQLite file by default (`sentinel_audit.db` resolved at construction and logged), WAL + `synchronous=FULL`. `:memory:` only when explicitly requested, with a WARNING and `audit_complete=False` on every result. The file is created at construction, never at import. | MUST | P1.5 | Pending D-11 | T | Default config → file exists at the logged absolute path after construction; rows survive closing and reopening the client; `:memory:` → warning and `audit_complete=False`. | M1 |

## 2. Security requirements

| ID | Requirement | Pri | Source | Status | Verif. | Acceptance criterion | MS |
|---|---|---|---|---|---|---|---|
| SEC-001 | **Default deny:** ALLOW only for explicitly granted tools. | MUST | DOC §7; BRIEF R5 | Pending D-24a | T | Ungranted → DENY `UNAUTHORIZED_TOOL`, not invoked; property test: ALLOW ⇒ tool ∈ grants. | M1 |
| SEC-002 | **DENY ⇒ not invoked**, for every reason code. | MUST | DOC §3, §6 | Proposed | T | Spy = 0 and `execution="not_started"` for every DENY reason reachable in the milestone. | M1 |
| SEC-003 | **REQUIRE_APPROVAL ⇒ not invoked**, and no v1 path executes it. | MUST | DOC §7; BRIEF R9 | Pending D-06 | T, I | Destructive granted tool → REQUIRE_APPROVAL, spy = 0; no approval or replay API exists. | M1 |
| SEC-004 | **Failed authorization ⇒ not invoked.** | MUST | DOC §4.2 | Proposed | T | Unknown, disabled or bad credential → spy = 0. | M1 |
| SEC-005 | **Pre-execution audit is mandatory.** REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING×n, DECISION and EXECUTION_STARTED are each **committed** before the next stage. If any write fails, the tool is not invoked and the result is DENY `AUDIT_UNAVAILABLE`, `audit_complete=False`. | MUST | BRIEF R12; P1.5 | Pending D-09 | T | Fault injection on each pre-execution event type → spy = 0. From inside the spy, a separate DB connection sees the committed DECISION(allow) and EXECUTION_STARTED rows with the matching `action_digest`. | M1 |
| SEC-006 | **Post-execution audit failure is reported truthfully:** decision stays ALLOW; `execution` is the real value (`succeeded`/`failed`); `output_released=False`; `audit_complete=False`; `error_code="AUDIT_UNAVAILABLE"`; masked best-effort `logging` record. The result is never a DENY. | MUST | P1.5 | Pending D-03 | T | Fault injection on OUTPUT_FILTERED or REQUEST_COMPLETED → spy = 1, the fields as specified, `output is None`. | M1 |
| SEC-007 | **Filesystem authorization contract C2**: explicit, existing, canonicalised prefixes; empty ⇒ deny; absolute-only request paths; canonicalisation in the gateway; component-wise containment as one pure function; the canonical path passed to the tool; proxy re-resolution before invocation; Windows unsupported. **Not** described as isolation. | MUST | DOC §3; BRIEF R11; P1.5 | Pending D-05, D-18, D-21 | T | Path matrix F1–F20 (`testing_strategy.md` §5). | M1 |
| SEC-008 | **No secret leakage** into audit rows, `logging`, exception strings, model `repr`/JSON, result `reason`/`error_code`. Mechanisms: `SecretStr`; key-name and pattern masking; validation errors without input values; tool and filter exceptions recorded by type name only; masked, truncated evidence. | MUST | DOC §5, §7; NEW | Proposed | T | Canary test across all sinks (NI-11). | M1 (M2/M3 extend patterns) |
| SEC-009 | **Fail closed before invocation:** an `Exception` in any security-critical stage before invocation → DENY `INTERNAL_ERROR`, `execution="not_started"`, generic text. | MUST | DOC §5; BRIEF §4.2 | Proposed | T | Fault-injection matrix (`testing_strategy.md` §6). | M1 |
| SEC-010 | **Decision–execution consistency:** the proxy executes only `decision.action` when the decision is ALLOW, `request_id`s match (decision, action, request) and the digest verifies. The spy receives exactly `action.arguments` (deep copy). | MUST | DOC §4.5; P1.5 | Pending D-07 | T | NI-08, NI-09, NI-13. | M1 |
| SEC-011 | **Output filter fails closed:** filter exception → `output_released=False`, `error_code="OUTPUT_FILTER_FAILED"`, OUTPUT_WITHHELD event. | MUST | P1.5 | Pending D-19 | T | Forced filter exception → as specified, spy = 1. | M1 |
| SEC-012 | **DENY over REQUIRE_APPROVAL; findings only restrict.** | MUST | BRIEF R4; NEW | Pending D-24c | T | Destructive + HIGH → DENY; property test: added findings never produce ALLOW from DENY or REQUIRE_APPROVAL. | M1/M2 |
| SEC-013 | **Trusted identity:** `agent_id` comes from application code (`raw` built by the app, or the adapter parameter). Reserved keys (`agent_id`, `session_id`, `auth_token`, `request_id`) inside `arguments` → DENY `INVALID_REQUEST`. Adapters never read identity from model output. | MUST | P1.5 | Pending D-04 | T | E2E-08; adapter test in which the model injects `agent_id` (M5). | M1/M5 |
| SEC-014 | **Registry integrity:** unique names; no registry mutation reachable from the tool-call path; callables never loaded from storage. | MUST | DOC §4.5 | Proposed | T, I | Duplicate → error; inspection. | M1 |
| SEC-015 | **Internal proxy:** not exported in `sentinel.__all__`. | SHOULD | NEW | Pending D-07 | I, T | `__all__` test. | M1 |
| SEC-016 | **Async fails closed** for every wrapped tool until async is supported. | MUST (M5) | P1.5 | Pending D-12 | T | `await wrapped.ainvoke(...)` raises; original spy = 0. | M5 |
| SEC-017 | **Tool errors contained:** `execution="failed"`, `error_code="TOOL_FAILED"`, exception type only. | MUST | DOC §5 | Pending D-14 | T | Canary in the exception message absent everywhere. | M1 |
| SEC-018 | **Append-only through Sentinel's API**; wording never "immutable" or "tamper-proof". | MUST | DOC §4.6; BRIEF R19 | Pending D-24f | T, I | Repository introspection (no update/delete); README review. | M1 |
| SEC-019 | **Deterministic, I/O-free policy:** same (request/action, context, findings, `tool_spec`, policy, time snapshot) ⇒ the same decision. | MUST | DOC §7 | Proposed | T, I | 1,000-iteration determinism; evaluation with file and socket access patched to raise still succeeds. Path canonicalisation (I/O) happens in the gateway, not in policy. | M1 |
| SEC-020 | **Heuristic-detection honesty** in all documentation. | MUST | BRIEF R17 | Pending D-24h | A | Documentation review checklist. | M2 |
| SEC-021 | **Action integrity:** if `decision.action` (including nested argument values) is mutated after policy, or a decision for another request or action is supplied, the proxy does not invoke (`execution="not_started"`, `error_code="ACTION_MISMATCH"`). | MUST | P1.5 | Pending D-07 | T | Mutate `action.arguments["path"]` after policy → spy = 0. Swap decisions between two requests → spy = 0. | M1 |
| SEC-022 | **Truthful execution reporting:** `decision ≠ ALLOW ⇒ execution = not_started`; a failure after the `entered` flag is set is never reported as `not_started` or DENY; `output_released ⇒ execution = succeeded ∧ audit_complete`. | MUST | P1.5 | Pending D-14 | T | NI-07 and NI-14 across all scenarios and fault injections. | M1 |
| SEC-023 | **Audit reconstruction rules (C4.4)** hold: for every request, the persisted events let a reader classify execution as not-executed (guaranteed), recorded, or unknown. | MUST | P1.5 | Pending D-09 | T | Reconstruction helper used in tests: for every scenario, the classification from audit rows alone equals the spy truth. A simulated crash after EXECUTION_STARTED → "unknown". | M1 |

## 3. Non-functional requirements

| ID | Requirement | Pri | Source | Status | Verif. | Acceptance criterion |
|---|---|---|---|---|---|---|
| NFR-001 | Python floor and CI matrix (`>=3.11`; 3.11/3.12/3.13). | MUST | BRIEF R1 | Proposed (D-01 Approved) | I, T | `requires-python` and the CI matrix match D-01; CI green. |
| NFR-002 | Runtime deps: Pydantic v2, SQLAlchemy 2.x only; frameworks as extras. | MUST | DOC §7 | Proposed | I | `dependencies` lists exactly these two; importing `sentinel` does not import any framework. |
| NFR-003 | No side effects at import; no env reads in the library. The audit file is created at client construction only. | MUST | DOC §7; BRIEF §9 | Proposed | T, I | Import with `os.environ` access patched to raise succeeds; no file is created on import. |
| NFR-004 | ruff lint and format clean. | MUST | BRIEF R16 | Proposed (D-22 Approved for Ruff) | T | CI. |
| NFR-005 | mypy clean on `src/`. | SHOULD | NEW | Pending D-22 | T | CI. |
| NFR-006 | Branch coverage ≥ 90% on policy, proxy, pipeline, path guard and audit; ≥ 85% overall (proposed). | SHOULD | NEW | Pending D-22 | T | Coverage report. |
| NFR-007 | Hermetic, deterministic tests (no network, injected clock, `tmp_path` only). | MUST | NEW | Proposed | T, I | Suite green offline. |
| NFR-008 | Docstrings on the public API; domain terms defined at first definition. | MUST | DOC §7 | Proposed | I | Ruff docstring rules. |
| NFR-009 | Living README: status, quickstart, limitations (`decision_record.md` §2, §4.6, §6), link to `decision_record.md`. | MUST | BRIEF §0.4 | Proposed (D-23 Approved) | I | Review at each gate. |
| NFR-010 | Stable reason and error codes; no secrets or internals in messages. | MUST | DOC §5 | Proposed | T | SEC-008, SEC-009. |
| NFR-011 | Measured overhead per call (median, p95) with the durable default store (WAL + FULL), reported before release. | SHOULD | NEW | Proposed | T | Benchmark output recorded. |
| NFR-012 | Linux and macOS supported; CI on both. | SHOULD | NEW | Pending D-21 | T | CI matrix. |
| NFR-013 | Packaging: editable install, wheel build, fresh-venv import smoke test. | MUST | BRIEF §11 | Pending D-02 (names provisional; verification open) | T | CI step. |
| NFR-014 | API clarity: one public entry class, explicit `__all__`, keyword-only security flags. | SHOULD | NEW | Proposed | I | API review at C-12. |
| NFR-015 | No circular imports; dependency direction per architecture §3. | MUST | NEW | Proposed | T | Per-module fresh-interpreter import test. |
| NFR-016 | Thread-safe synchronous use within one process. | SHOULD | NEW | Pending D-20 | T | 8 threads × 200 requests: no errors; expected audit row count; no unauthorized ALLOW. |
| NFR-017 | Audit field truncation (default 1,024 characters, marked). | SHOULD | NEW | Proposed | T | 1 MB argument → bounded stored value. |
| NFR-018 | Dependency version bounds; CI installs from constraints. | SHOULD | NEW | Proposed | I | Review at C-01. |

## 4. Out of scope for v1 (pending D-10)

- ML anomaly detection; LLM injection classifier.
- Human approval workflow and replay; `RESTRICT`.
- Dashboard or UI; external alert sinks; persisted alerts.
- Multi-process or distributed deployment.
- Async APIs (wrapped async paths fail closed).
- Registry signing; audit hash-chaining; migrations; secrets vault.
- Plan splitting; sub-action grants.
- Execution timeouts and resource caps.
- Injection scanning of tool outputs or LLM context; "strip instruction-like content".
- `protect(graph)` graph-wide protection (replaced by `wrap_tools`, D-12).
- Filesystem isolation or sandboxing (only path-argument authorization, C2).
- From the September diagrams: provenance, RAG trust and quarantine, delegation validation, privilege drift, execution graph, cross-domain risk engine, scoped credentials.

## 5. Traceability

Contract → requirement → test: `decision_record.md` §5 and `testing_strategy.md` §14. Threat → requirement: `threat_model.md` §6.

## 6. Change log

| Rev. | Date | Change |
|---|---|---|
| 1 | 2026-10-28 | Initial Inception requirements (FR-001–023, SEC-001–020, NFR-001–018) |
| 2 | 2026-10-28 | Phase 1.5. **Revised:** FR-004 (gateway-side single validation, `AuthorizedAction`), FR-006 (`require_credentials`), FR-008 (`tool_spec`, action in decision), FR-009, FR-010 (required schema; prefix rules), FR-012 (C4.3 lifecycle: TOOL_EXECUTED/TOOL_BLOCKED replaced by EXECUTION_STARTED and REQUEST_COMPLETED), FR-014 (no Tool-Abuse detector), FR-016 (returns for all outcomes; supersedes "raise AuditUnavailable"), FR-017 (`outcome` enum replaced by separate fields), FR-018 (`AuditUnavailable` replaced by `ToolExecutionError`), FR-021 (`protect` → `wrap_tools`), SEC-005 (EXECUTION_STARTED, `AUDIT_UNAVAILABLE` reason), SEC-006, SEC-007 (C2), SEC-010, SEC-013 (`request_id` reserved), SEC-019 (I/O moved to gateway). **Added:** FR-024, SEC-021, SEC-022, SEC-023. **Status column** now references D-IDs. Rev. 1 row text was overwritten in place, and since the repository has no commits yet, no verbatim copy is kept. Every superseded *position* is recorded in `decision_record.md` §0.3 and in each D-entry's "Rejected" line, and the original Inception recommendations remain verbatim in `open_decisions.md` |
