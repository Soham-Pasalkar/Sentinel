# Testing Strategy — Sentinel v1 (AI-DLC Inception)

| | |
|---|---|
| Phase | Inception |
| Date | 2026-10-28 |
| Status | Draft rev. 2 (Phase 1.5) — pending owner review. **No tests exist yet. Nothing here has been run.** Contracts C1–C4 and decisions D-xx: [`decision_record.md`](decision_record.md) |

## 1. Principles

1. **Invariants first.** The negative security invariants in §7 are written before or with the code they protect, never after.
2. **Every security claim maps to a test.** A requirement verified by "T" in `requirements.md` has at least one test whose name includes the requirement ID (e.g. `test_sec002_deny_never_invokes_tool`), so `pytest -k sec002` finds it.
3. **Spies, not trust.** "Tool not executed" is always asserted with a spy that counts calls and records arguments, never inferred from a return value.
4. **Hermetic.** No network; time injected through a clock parameter; files only under `tmp_path`; framework tests use scripted models, never real LLM APIs.
5. **Fault injection is a first-class test type.** Each security-critical stage has a test that forces it to raise.
6. **Regression tests for every security defect** (§11).
7. **No claim without a run.** Increment completion evidence includes the actual `pytest` output (`implementation_plan.md`).

## 2. Test pyramid and layout

| Layer | Directory (proposed) | Scope | Approx. share |
|---|---|---|---|
| Unit | `tests/unit/test_<module>.py` | Models, gateway, identity, detector, policy, path guard, registry, proxy (with fakes), audit repository | ~70% |
| Integration | `tests/integration/` | Proxy + registry + path guard on a real temporary filesystem; audit logger + SQLite file DB; pipeline with real components and a fault-injecting audit store | ~20% |
| End-to-end | `tests/e2e/` | `SentinelClient` from raw dict to `PipelineResult` plus audit rows; quickstart run as a subprocess | ~8% |
| Framework | `tests/integrations/` | LangGraph/LangChain adapters with scripted models; skipped with a clear reason when the extra is not installed (`pytest.importorskip`) | ~2% |
| Security invariants | `tests/security/` | Cross-cutting invariants (§7), canary-secret test, property tests | Runs in every CI job |

Markers: `security`, `fault_injection`, `regression`, `integration_framework`, `slow`. The security suite is never skipped in CI.

## 3. Requirement → suite mapping

| Requirement(s) | Suites |
|---|---|
| FR-001–004, SEC-013 (reserved keys) | `unit/test_gateway.py`, `unit/test_models.py` |
| FR-005–007 | `unit/test_identity.py` |
| FR-008, FR-009, SEC-001, SEC-012, SEC-019 | `unit/test_policy.py` (truth table §4, determinism, property tests) |
| SEC-007 | `unit/test_path_guard.py`, `integration/test_proxy_filesystem.py` (§5) |
| FR-010, SEC-014 | `unit/test_registry.py` |
| FR-011, SEC-002/3/10/11/17, SEC-021 | `unit/test_proxy.py`, `security/test_action_integrity.py`, `security/test_invariants.py` |
| FR-012, FR-013, SEC-005/6/18, NFR-017 | `unit/test_audit_repository.py`, `integration/test_audit_ordering.py` |
| SEC-022, FR-017 | `security/test_invariants.py` (NI-07, NI-14), `security/test_fault_injection.py` |
| SEC-023 | `integration/test_audit_reconstruction.py` (NI-15) |
| FR-024 | `integration/test_audit_storage_default.py` |
| SEC-008 | `security/test_secret_canary.py` |
| SEC-009 | `security/test_fault_injection.py` (§6) |
| FR-016–018, FR-023 | `e2e/test_client.py`, `e2e/test_quickstart.py` |
| FR-014 (M2), SEC-020 | `unit/test_detector.py`, `unit/test_detector_corpus.py` |
| FR-015 (M3) | `unit/test_output_filter.py` |
| FR-019 (M4), NFR-016 | `unit/test_rate_limit.py`, `integration/test_concurrency.py` |
| FR-021/022, SEC-016 | `integrations/test_langgraph.py`, `integrations/test_langchain.py` |
| NFR-003, NFR-015 | `unit/test_import_hygiene.py` |

## 4. Policy truth table (unit, `test_policy.py`)

Each row is a parametrised case; expected values follow `architecture_assessment.md` §4. Fixtures: tool `read_file` (path_args=`["path"]`, not destructive), tool `delete_file` (destructive), grant `read_file` with prefix `/ws`.

| # | authorized | granted | path ok | max finding | destructive | approval req'd | Expected |
|---|---|---|---|---|---|---|---|
| P1 | F | – | – | – | – | – | DENY `UNAUTHORIZED_AGENT` |
| P2 | T | F | – | – | – | – | DENY `UNAUTHORIZED_TOOL` |
| P3 | T | T | F | – | – | – | DENY `RESTRICTED_PATH` |
| P4 | T | T | T | HIGH (`PROMPT_INJECTION`) | F | – | DENY `PROMPT_INJECTION` |
| P5 | T | T | T | MEDIUM | F | – | ALLOW (risk_score recorded) |
| P6 | T | T | T | none | T | T | REQUIRE_APPROVAL |
| P7 | T | T | T | none | T | F | ALLOW |
| P8 | T | T | T | none | F | – | ALLOW |

**Precedence pairs** (each must return the earlier row's result):

| Case | Expected |
|---|---|
| unauthorized + ungranted + HIGH finding | `UNAUTHORIZED_AGENT` |
| ungranted + path violation | `UNAUTHORIZED_TOOL` |
| path violation + HIGH finding | `RESTRICTED_PATH` |
| destructive + HIGH finding | DENY (not REQUIRE_APPROVAL) |
| destructive + path violation | DENY `RESTRICTED_PATH` |
| two HIGH findings with different codes | deterministic tie-break (CF-03) |
| CRITICAL with `deny_at_severity=CRITICAL`, plus HIGH | deny with the CRITICAL code |
| grant with empty `allowed_path_prefixes` for a path tool | DENY `RESTRICTED_PATH` (C2.2, pending D-05) |
| grant with explicit `("/",)` | ALLOW for any absolute path (C2.2) |

Policy tests construct canonical paths directly. Policy performs **no** path resolution (C2.4, SEC-019); resolution is tested in the gateway and path-guard suites.

**Determinism:** each case evaluated 1,000 times → one distinct result. `evaluate` run with `open`, `socket` and `time.time` patched to raise still succeeds.
**Property tests (optional Hypothesis, OD-12):** random grants and requests → `ALLOW ⇒ tool ∈ grants ∧ path within prefixes`; adding findings never turns DENY/REQUIRE_APPROVAL into ALLOW.

## 5. Filesystem security matrix (`test_path_guard.py` + `integration/test_proxy_filesystem.py`)

Built in `tmp_path` with `ws/` as the allowed prefix and `outside/secret.txt`. On macOS, `tmp_path` lies under `/private/var/...`; tests also give the prefix in its *unresolved* form to exercise prefix canonicalisation.

| Case | Input | Expected |
|---|---|---|
| F1 | `ws/a.txt` (absolute) | allowed; the tool receives the resolved absolute path |
| F2 | `ws/../outside/secret.txt` | denied `RESTRICTED_PATH` |
| F3 | sibling prefix `ws2/x` vs prefix `ws` | denied |
| F4 | `ws/link → outside/secret.txt` (file symlink) | denied |
| F5 | `ws/dirlink → outside/` then `ws/dirlink/secret.txt` | denied |
| F6 | `ws/inner → ws/a.txt` (symlink staying inside) | allowed; receives the resolved target |
| F7 | relative path `a.txt` | denied `INVALID_REQUEST` (C2.3) |
| F8 | `""`, `"\x00"`, `"ws/a\x00.txt"` | denied `INVALID_REQUEST` |
| F9 | `~/.ssh/id_rsa` | denied (relative / outside); never expanded |
| F10 | non-existent file under `ws` (write tool) | allowed; resolved parent inside `ws` |
| F11 | non-existent path whose parent is a symlink to outside | denied |
| F12 | prefix itself is a symlink (`/tmp` → `/private/tmp` style) | correct containment after both sides are canonicalised |
| F13 | the prefix directory exactly (`ws`) | allowed (C2.5) |
| F14 | proxy given a forged ALLOW for an escaping path (policy bypassed in the test) | blocked, `execution="not_started"`, `error_code="RESTRICTED_PATH"` or `ACTION_MISMATCH`, spy = 0 |
| F15 | symlink swap between proxy re-resolution and the tool's `open` | `xfail(strict=True)` documenting the residual risk (T-07) |
| F16 | after policy ALLOW, but before the proxy runs, replace `ws/sub` with a symlink to `outside/` (test hook between stages) | proxy re-resolution differs → not invoked, `RESTRICTED_PATH` (C2.7) |
| F17 | hard link `ws/hl` → `outside/secret.txt` | **allowed**. A normal passing test `test_limitation_hardlink_not_detected` asserts this, so the documented limitation is proven real and any future fix must update the test deliberately |
| F18 | grant prefix that does not exist, or is a file | `ConfigurationError` at registration (C2.1) |
| F19 | empty prefix list for a path tool | every call DENY `RESTRICTED_PATH`; registration logs a warning (C2.2) |
| F20 | path-constrained tool registered when `os.name == "nt"` (simulated by monkeypatch) | `ConfigurationError` (C2, D-21) |

## 6. Failure-injection matrix (`security/test_fault_injection.py`)

Each row injects an exception into one component via a fake or monkeypatch, and runs a request that would otherwise be ALLOW.

Result fields follow C1.6: `decision` / `reason` / `execution` / `output_released` / `audit_complete` / `error_code`. `evaluate_request` raises in **no** row (FR-016).

| Injected failure | decision / reason | execution | output_released | audit_complete | error_code | Spy |
|---|---|---|---|---|---|---|
| Audit write: REQUEST_RECEIVED | deny / `AUDIT_UNAVAILABLE` | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Gateway raises unexpectedly | deny / `INTERNAL_ERROR` | not_started | F | T | — | 0 |
| Identity raises | deny / `INTERNAL_ERROR` | not_started | F | T | — | 0 |
| Detector raises | deny / `INTERNAL_ERROR` | not_started | F | T | — | 0 |
| Policy raises | deny / `INTERNAL_ERROR` | not_started | F | T | — | 0 |
| Audit write: IDENTITY_RESOLVED / FINDING / DECISION | deny / `AUDIT_UNAVAILABLE` | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Audit write: EXECUTION_STARTED | deny / `AUDIT_UNAVAILABLE` | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Registry lookup fails in proxy | deny / `INTERNAL_ERROR` | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Action digest mismatch (mutated action) | deny / `ACTION_MISMATCH` | not_started | F | T | `ACTION_MISMATCH` | 0 |
| Proxy path re-resolution differs | deny / `RESTRICTED_PATH` | not_started | F | T | `RESTRICTED_PATH` | 0 |
| Tool raises | allow / `TOOL_FAILED` | failed | F | T | `TOOL_FAILED` | 1 |
| Output filter raises | allow / `OUTPUT_FILTER_FAILED` | succeeded | F | T | `OUTPUT_FILTER_FAILED` | 1 |
| Audit write: REQUEST_COMPLETED after success | allow / `AUDIT_UNAVAILABLE` | **succeeded** | F | F | `AUDIT_UNAVAILABLE` | 1 |
| Audit write: REQUEST_COMPLETED after a DENY | deny (unchanged reason) | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Process killed after EXECUTION_STARTED (simulated: abort the pipeline in the spy, e.g. with a `BaseException` subclass) | — (exception propagates) | audit reconstruction ⇒ **unknown** | — | — | — | 1 |
| Invalid `SecurityPolicy` / non-existent prefix at construction | `ConfigurationError`; no client | — | — | — | — | — |

Proxy-stage blocks (registry lookup, digest mismatch, re-resolution): the DECISION audit event records policy's `allow`, but the **effective** decision returned, and recorded on REQUEST_COMPLETED, is `deny` with the proxy's reason (C1.4, C1.6). The audit therefore shows both what policy decided and what was enforced.

Every row also asserts: no exception message, file path or SQL appears in `reason`, `error_code` or any audit field.

## 7. Negative security invariants

These are the non-negotiable invariants. Each one **will be** implemented in `tests/security/test_invariants.py` (planned; no such tests exist yet) and checked across **every** E2E scenario through a shared assertion helper.

| ID | Invariant | Requirement |
|---|---|---|
| NI-01 | decision = DENY ⇒ spy count = 0 | SEC-002 |
| NI-02 | decision = REQUIRE_APPROVAL ⇒ spy count = 0 | SEC-003 |
| NI-03 | `authorized = False` ⇒ spy count = 0 | SEC-004 |
| NI-04 | any pre-execution audit write fails ⇒ spy count = 0 | SEC-005 |
| NI-05 | any security-critical stage raises before execution ⇒ DENY `INTERNAL_ERROR` ∧ spy count = 0 | SEC-009 |
| NI-06 | spy count = 1 ⇒ committed DECISION(allow) **and** EXECUTION_STARTED events with the same `request_id` and `action_digest` existed **before** the call (checked from inside the spy through a separate DB connection) | SEC-005, SEC-010 |
| NI-07 | spy count = 0 ⇔ `execution == "not_started"`; spy count = 1 ⇔ `execution ∈ {succeeded, failed}` (the in-process pipeline never returns `unknown` in v1) | SEC-022 |
| NI-08 | the kwargs received by the spy equal `decision.action.arguments` (path arguments canonical), and mutating them inside the tool does not change the audited values | SEC-010 |
| NI-09 | proxy given a non-ALLOW decision, or a decision for another `request_id` ⇒ spy count = 0 | SEC-010 |
| NI-10 | ALLOW ⇒ tool ∈ agent grants | SEC-001 |
| NI-11 | the canary secret appears in no audit row, log record, exception string or serialised result | SEC-008 |
| NI-12 | when the audit store is available, every request produces exactly one DECISION and exactly one REQUEST_COMPLETED event, and REQUEST_COMPLETED is last | FR-012 |
| NI-13 | any mutation of `decision.action` after policy (top-level or nested argument values) ⇒ spy count = 0, `error_code="ACTION_MISMATCH"` | SEC-021 |
| NI-14 | `decision ≠ allow ⇒ execution = not_started`; `output_released ⇒ execution = succeeded ∧ audit_complete`; a post-invocation failure never yields `decision = deny` | SEC-022 |
| NI-15 | the C4.4 reconstruction of each request from audit rows alone matches the spy truth (not executed / executed); a run aborted after EXECUTION_STARTED reconstructs as **unknown** | SEC-023 |

## 8. Minimal end-to-end acceptance scenario ("walking skeleton")

This is the first E2E suite. It must pass before any detection, output-filter, rate-limit or framework work begins (gate G-M1 in `implementation_plan.md`).

**Setup (fixture):**
- File-backed SQLite audit DB in `tmp_path`.
- Workspace `tmp_path/ws/` containing `data.txt` (`"hello"`), and `tmp_path/outside/secret.txt`.
- Tools, each with a strict `arg_schema` (D-08): `read_file(path)` (path_args=`("path",)`, `destructive=False`); `delete_file(path)` (path_args=`("path",)`, `destructive=True`); `send_email(to, body)` (`destructive=False`, registered, not granted). Each tool is wrapped in a spy.
- Agent `research_agent` (enabled, no credential), grants: `read_file` and `delete_file`, each with `allowed_path_prefixes=(<tmp_path>/ws,)`.
- `SecurityPolicy(version="test-1")`; detector = stub.

Audit abbreviations: RR = REQUEST_RECEIVED, IR = IDENTITY_RESOLVED, DEC = DECISION, ES = EXECUTION_STARTED, RC = REQUEST_COMPLETED (C4.3). Paths are absolute under `tmp_path`.

| ID | Request | decision / reason | execution · released · audit_complete | Spy counts | Audit sequence for the request |
|---|---|---|---|---|---|
| E2E-01 | `research_agent` `read_file(<ws>/data.txt)` | allow | succeeded · T · T; output `"hello"` | read=1 | RR, IR, DEC(allow), ES, RC(succeeded) |
| E2E-02 | `read_file(<ws>/../outside/secret.txt)` | deny `RESTRICTED_PATH` | not_started · F · T | read=0 | RR, IR, DEC(deny), RC(not_started) |
| E2E-03 | `send_email(...)` | deny `UNAUTHORIZED_TOOL` | not_started · F · T | email=0 | RR, IR, DEC(deny), RC |
| E2E-04 | agent `unknown_agent` `read_file(<ws>/data.txt)` | deny `UNAUTHORIZED_AGENT` | not_started · F · T | read=0 | RR, IR, DEC(deny), RC |
| E2E-05 | `delete_file(<ws>/data.txt)` | require_approval | not_started · F · T; file still exists | delete=0 | RR, IR, DEC(require_approval), RC |
| E2E-06 | `{"agent_id": "research_agent"}` (missing fields) | deny `INVALID_REQUEST` | not_started · F · T | all 0 | RR, DEC(deny), RC |
| E2E-07 | E2E-01 with the audit store failing on DECISION | deny `AUDIT_UNAVAILABLE` | not_started · F · F | read=0 | RR, IR (then store down) |
| E2E-08 | E2E-01 with `arguments` containing `agent_id: "admin"` | deny `INVALID_REQUEST` | not_started · F · T | read=0 | RR, DEC(deny), RC |
| E2E-09 | E2E-01 with the audit store failing on RC | allow `AUDIT_UNAVAILABLE` | **succeeded** · F · F | read=1 | RR, IR, DEC(allow), ES (RC missing; masked fallback log present) |

Also asserted for all nine: `evaluate_request` raised nothing; all events share the `request_id`; NI-01–NI-15 hold where applicable. The quickstart (FR-023) demonstrates E2E-01 to E2E-05.

## 9. Test doubles and fixtures

| Double | Purpose |
|---|---|
| `SpyTool(fn)` | Counts calls, records received kwargs, optionally queries the audit DB from inside the call (NI-06) |
| `FailingAuditStore(fail_on={event_types})` | Raises on chosen event types; otherwise delegates to the real store |
| `RaisingStage` | Replaces a stage with one that raises (fault injection) |
| `FixedClock` | Deterministic timestamps and rate-limit windows |
| `workspace` fixture | Builds the `ws/` and `outside/` tree, symlinks included |
| `canary_secret` fixture | Generates a unique obviously-fake secret per test (`"CANARY-" + uuid4().hex`), per brief §9 |
| `StageHook` | Test-only hook that runs code between pipeline stages (e.g. F16 symlink swap after policy, NI-13 action mutation). Injected through a test seam, not a public API |
| `AbortRun(BaseException)` | Raised inside a spy to simulate a crash after EXECUTION_STARTED (NI-15 "unknown") |
| `reconstruct(rows)` | Test helper implementing the C4.4 rules from audit rows only |

## 10. Framework interception feasibility (C-02 experiment, then M5)

The experiment is now fully specified as **E1–E8 in `decision_record.md` §3.4**: environment, procedure, pass criteria, report location and stop condition. That specification supersedes the S1–S7 list from rev. 1, which maps as S1→E1, S2→E3, S3→E5, S4→E2/E4, S5→E6, S6→E8, S7→the offline constraint. It was **not executed** in Phase 1.5.

M5 adapter tests turn E1, E2 and E4 into permanent regression tests (FR-021, SEC-016), plus an identity-injection test (SEC-013: model-supplied `agent_id` is ignored or rejected).

## 11. Regression policy for security defects

- Each security defect gets an ID `SD-NNN`, logged in `docs/aidlc/02-construction/security_defects.md`.
- The fix commit contains a test marked `@pytest.mark.regression` and named `test_sdNNN_<summary>`, which **failed before the fix** (record the failing output in the defect log).
- Regression tests are never deleted or skipped without an owner-approved entry in the defect log.

## 12. CI gates (proposed)

| Gate | Command (indicative) | Blocking |
|---|---|---|
| Lint / format | `ruff check .` ; `ruff format --check .` | Yes |
| Types | `mypy src` | Yes once enabled (OD-12) |
| Tests | `pytest -m "not integration_framework"` on 3.11, 3.12, 3.13 | Yes |
| Security suite | `pytest -m security` (also included above; reported separately) | Yes |
| Coverage | `--cov=sentinel --cov-branch` with the NFR-006 thresholds | Yes after M1 |
| Framework tests | `pip install -e ".[dev,langgraph]"` then `pytest -m integration_framework` | Yes from M5 |
| Packaging smoke | build wheel → fresh venv → `python -c "import sentinel"` | Yes |

## 13. Explicit non-claims

- No test has been written or run during Inception.
- Detection effectiveness will be reported as measured counts on a stated corpus (M2), never as a general detection rate.
- Passing tests demonstrate the invariants for calls routed through Sentinel in the tested configurations. They do not show that an agent system is "safe".

## 14. Contract → acceptance-test map (rev. 2)

Every security contract in `decision_record.md` has at least one acceptance test. A contract becomes testable only once its decision is Approved; until then, the tests are specified but not yet authoritative.

| Contract | Decision(s) | Acceptance tests |
|---|---|---|
| C1.1 request identity | — | FR-002 tests; NI-12 |
| C1.2 trusted identity, reserved keys, credentials | D-04 | identity suite; E2E-04, E2E-08; adapter identity-injection test (M5) |
| C1.3 tool metadata | D-06, D-08, D-15 | registry suite; policy truth table P1–P8 |
| C1.4 action binding | D-07 | NI-08, NI-09, NI-13; fault rows "digest mismatch", "registry lookup" |
| C1.5 policy outcomes | D-06, D-24a/c | truth table and precedence pairs; NI-01, NI-02, NI-10; E2E-02–05 |
| C1.6 execution outcomes | D-14 | NI-07, NI-14; all §6 rows |
| C1.7 audit pre/post | D-03, D-09 | NI-04, NI-06; §6 audit rows; E2E-07, E2E-09 |
| C1.8 errors | D-03, D-24d | §6 matrix (no row raises); NI-11 canary |
| C2 filesystem | D-05, D-18, D-21 | §5 F1–F20; E2E-02 |
| C3 identity and integration | D-04, D-12 | E1–E8 (experiment evidence); M5 regression tests |
| C4 persistence | D-09, D-11 | NI-12, NI-15; `test_audit_storage_default.py` (FR-024); repository introspection (SEC-018); schema-version mismatch test (C4.6 item 4) |
