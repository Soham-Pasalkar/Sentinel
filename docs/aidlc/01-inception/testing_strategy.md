# Testing Strategy — Sentinel v1 (AI-DLC Inception)

| | |
|---|---|
| Phase | Inception |
| Date | 2026-10-28; 2026-11-08 (rev. 8) |
| Status | Draft rev. 14 (D-17 and the `SentinelClient` name Approved; E2E through the public client). Rev. 13 (D-16 and D-20 Approved: pipeline is the sole orchestrator and audit writer; asyncio-safe async entry). Rev. 12 (D-09, D-11, D-20 audit writes, D-24f Approved; the store uses `sqlite3`, not SQLAlchemy). Rev. 11 (D-19 failure rule and D-31 defaults Approved: guard TTL 300 s after the terminal state, 10,000 entries). Rev. 10 (D-24a and D-15 Approved: §4 rows P6/P7 use the I-8 reason codes `DESTRUCTIVE_TOOL` and `ALLOWED`; P5's "risk_score recorded" waits for an approved formula, I-11). Rev. 9 (D-24b Approved: grants are tool-level; the E2E fixture now sets `require_credentials=False` explicitly, since D-04 made `True` the default). Rev. 8 (D-05, D-18, D-21 Approved: §4 empty-grant row and §5 matrix no longer pending; F9 aligned with C2.3); rev. 7 (operational refusals are not policy decisions; at the time C-03 was blocked on Pydantic, since resolved and implemented); rev. 6 (Q-03c: internal errors distinct from denials; rev. 5 C-03a implemented; rev. 4 final contract gate; rev. 3 after C-02/C-02b) — pending owner review. **Production tests (2026-11-08):** 3 C-01 scaffold tests; **52 C-03a tests** (`tests/unit/test_action.py`; AT-28–AT-31, model level); **82 C-03 tests** (`test_models.py`, `test_exceptions.py`); **57 C-04 tests** (`test_path_guard.py`; §5 F1–F20 at function level, F15 strict xfail); **52 C-05 tests** (`test_registry.py`; FR-010, SEC-014); **108 C-06 tests** (`test_gateway.py`; FR-001, FR-003, FR-004, SEC-013, gateway parts of AT-31 and AT-36, F7–F9 at gateway level); **97 C-07 tests** (`test_identity.py`; FR-005, FR-006, FR-007 identity parts, D-24b grant model, C2.1/C2.2 prefixes on grants); **96 C-08 tests** (`test_policy.py`; §4 truth table P1–P8, precedence pairs, determinism; SEC-001, SEC-019 at unit level); **89 C-10 tests** (`test_proxy.py`; NI-08, NI-09, NI-13, NI-16, F14, F16, AT-01–AT-03, AT-06, AT-07, AT-22, AT-23, AT-26, AT-35, the D-19 failure rule, interruption). **C-09 tests:** `test_audit_repository.py` (store, logger, concurrency, fault injection), `test_masking.py`, `test_reconstruction.py` (C4.4; NI-15 at unit level), `integration/test_audit_storage_default.py` (FR-024). The planned `integration/test_audit_ordering.py` and `integration/test_audit_reconstruction.py` need the pipeline (C-11). **C-11 tests:** `integration/test_audit_ordering.py` (E2E-01…E2E-09), `integration/test_audit_reconstruction.py`, `integration/test_pipeline_async.py`, `security/test_fault_injection.py` (§6), `security/test_invariants.py` (§7), `security/test_secret_canary.py` (NI-11), `unit/test_pipeline_config.py`. Full suite: 933 passed, 1 xfailed locally (macOS). Remote CI (Linux and macOS × Python 3.11–3.13) passed on `fb4be1b` with 193 passed, 1 xfailed, i.e. through C-04. No other security test below is written. **Spike evidence:** C-02 (97 checks) and C-02b (120 checks) ran against *stand-ins*, not Sentinel code. §15 marks each adapter acceptance test as `SPIKE-RAN`, `NOT-RUN`, and `PROD-TODO`. Contracts C1–C4 and decisions D-xx: [`decision_record.md`](decision_record.md) |

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
| P5 | T | T | T | MEDIUM | F | – | ALLOW (risk_score recorded; rev. 10: `risk_score` stays `None` until a formula is approved, I-11) |
| P6 | T | T | T | none | T | T | REQUIRE_APPROVAL (`DESTRUCTIVE_TOOL`, I-8) |
| P7 | T | T | T | none | T | F | ALLOW (`ALLOWED`, I-8) |
| P8 | T | T | T | none | F | – | ALLOW (`ALLOWED`, I-8) |

**Precedence pairs** (each must return the earlier row's result):

| Case | Expected |
|---|---|
| unauthorized + ungranted + HIGH finding | `UNAUTHORIZED_AGENT` |
| ungranted + path violation | `UNAUTHORIZED_TOOL` |
| path violation + HIGH finding | `RESTRICTED_PATH` |
| destructive + HIGH finding | DENY (not REQUIRE_APPROVAL) |
| destructive + path violation | DENY `RESTRICTED_PATH` |
| two HIGH findings with different codes | deterministic tie-break (CF-03). **Rev. 5 (D-24c Approved):** reason = the code of the highest-severity finding at or above `deny_at_severity`; equal severities → lexicographically smallest `code` (Unicode code points); input order irrelevant; `finding_codes` sorted by descending severity, then ascending code |
| CRITICAL with `deny_at_severity=CRITICAL`, plus HIGH | deny with the CRITICAL code |
| grant with empty `allowed_path_prefixes` for a path tool | DENY `RESTRICTED_PATH` (C2.2, D-05 Approved) |
| grant with explicit `("/",)` | ALLOW for any absolute path (C2.2) |

Policy tests construct canonical paths directly. Policy performs **no** path resolution (C2.4, SEC-019); resolution is tested in the gateway and path-guard suites.

**Determinism:** each case evaluated 1,000 times → one distinct result. `evaluate` run with `open`, `socket` and `time.time` patched to raise still succeeds.

**C-08 evidence (rev. 10, 2026-11-08):** `tests/unit/test_policy.py`: `test_truth_table` (P1–P6, P8), `test_p7_destructive_without_approval_requirement_is_allowed`, `test_precedence_pairs_return_the_earlier_row` (five pairs), `test_two_high_findings_break_ties_by_smallest_code`, `test_critical_threshold_denies_with_the_critical_code`, `test_empty_prefix_list_denies_every_path`, `test_explicit_root_prefix_allows_every_absolute_path`, `test_one_thousand_evaluations_give_one_result`, `test_evaluation_needs_no_files_sockets_clock_or_environment` (also `time.monotonic`, `os.stat`, `os.lstat`, `os.path.realpath`, `os.getenv`, empty `os.environ`). P5's `risk_score` is `None` (I-11). The optional Hypothesis property tests are not written (Hypothesis not approved, D-22); `test_missing_grant_never_allows_across_all_inputs` enumerates every tool × severity × approval setting instead.
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
| F7 | relative path `a.txt` | refused, `decision=None`, `INVALID_REQUEST` (C2.3; rev. 7, was "denied") |
| F8 | `""`, `"\x00"`, `"ws/a\x00.txt"` | refused, `decision=None`, `INVALID_REQUEST` (rev. 7, was "denied") |
| F9 | `~/.ssh/id_rsa` | refused, `decision=None`, `INVALID_REQUEST` (C2.3: `~` is not absolute; rev. 8, was "denied"); never expanded |
| F10 | non-existent file under `ws` (write tool) | allowed; resolved parent inside `ws` |
| F11 | non-existent path whose parent is a symlink to outside | denied |
| F12 | prefix itself is a symlink (`/tmp` → `/private/tmp` style) | correct containment after both sides are canonicalised |
| F13 | the prefix directory exactly (`ws`) | allowed (C2.5) |
| F14 | proxy given a forged ALLOW for an escaping path (policy bypassed in the test) | blocked, `decision=None` (rev. 7), `execution="not_started"`, `error_code="RESTRICTED_PATH"` or `ACTION_MISMATCH`, spy = 0 |
| F15 | symlink swap between proxy re-resolution and the tool's `open` | `xfail(strict=True)` documenting the residual risk (T-07) |
| F16 | after policy ALLOW, but before the proxy runs, replace `ws/sub` with a symlink to `outside/` (test hook between stages) | proxy re-resolution differs → not invoked, `RESTRICTED_PATH` (C2.7) |
| F17 | hard link `ws/hl` → `outside/secret.txt` | **allowed**. A normal passing test `test_limitation_hardlink_not_detected` asserts this, so the documented limitation is proven real and any future fix must update the test deliberately |
| F18 | grant prefix that does not exist, or is a file | `ConfigurationError` at registration (C2.1) |
| F19 | empty prefix list for a path tool | every call DENY `RESTRICTED_PATH`; registration logs a warning (C2.2) |
| F20 | path-constrained tool registered when `os.name == "nt"` (simulated by monkeypatch) | `ConfigurationError` (C2, D-21) |

**C-04 evidence (rev. 8, 2026-11-08):** every case above is in `tests/unit/test_path_guard.py`, named `test_f<N>_…`. Passing locally on macOS (Python 3.11.14) and in GitHub Actions run 42456322322 (`fb4be1b`) on `ubuntu-latest` and `macos-latest`, Python 3.11–3.13, no skips (so F17 ran on Linux too). Function level only, pending later increments: F7, F8, F9 assert `InvalidRequestError` (rev. 9: also refused by the gateway, `test_invalid_paths_are_refused` in `test_gateway.py`; reporting them as `decision=None`, `INVALID_REQUEST` is the pipeline, C-11); F14 and F16 assert `reverify(...) is False` (rev. 11: also at proxy level, `test_path_outside_the_proxys_grant_is_refused` and `test_changed_path_target_is_refused_before_invocation`, with `execution="not_started"` and spy 0; the separate `integration/test_proxy_filesystem.py` file is not written, as the unit tests use a real temporary filesystem); F19 asserts that an empty prefix set contains nothing and that registration warns (the policy DENY `RESTRICTED_PATH` is C-08). F15 is `xfail(strict=True)` and was confirmed to fail on its content assertion (`'outside' == 'inside'`). F17 passes (hard link not detected). F20 simulates Windows by patching `os` inside `sentinel.paths` only, since patching the global `os.name` switches `pathlib` to Windows semantics.

## 6. Failure-injection matrix (`security/test_fault_injection.py`)

Each row injects an exception into one component via a fake or monkeypatch, and runs a request that would otherwise be ALLOW.

Result fields follow C1.6: `decision` / `reason` / `execution` / `output_released` / `audit_complete` / `error_code`. `evaluate_request` raises in **no** row (FR-016).

| Injected failure | decision / reason | execution | output_released | audit_complete | error_code | Spy |
|---|---|---|---|---|---|---|
| Audit write: REQUEST_RECEIVED | **null** / `AUDIT_UNAVAILABLE` *(rev. 7: operational refusal; was deny)* | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Gateway raises unexpectedly | **null** / `INTERNAL_ERROR` *(rev. 6, Q-03c; was deny)* | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Identity raises | **null** / `INTERNAL_ERROR` *(rev. 6, Q-03c; was deny)* | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Detector raises | **null** / `INTERNAL_ERROR` *(rev. 6, Q-03c; was deny)* | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Policy raises | **null** / `INTERNAL_ERROR` *(rev. 6, Q-03c; was deny)* | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Audit write: IDENTITY_RESOLVED / FINDING (before policy) | **null** / `AUDIT_UNAVAILABLE` *(rev. 7: operational refusal; was deny)* | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Audit write: DECISION (policy decided **allow**) | **allow** (preserved) / `AUDIT_UNAVAILABLE` *(rev. 7; was deny)* | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Audit write: DECISION (policy decided **deny**) | **deny** (preserved, a real policy decision) / the policy reason | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Audit write: EXECUTION_STARTED | **allow** (preserved) / `AUDIT_UNAVAILABLE` *(rev. 7; was deny)* | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Registry lookup fails in proxy | **null** / `INTERNAL_ERROR` *(rev. 6, Q-03c; was deny)* | not_started | F | T | `INTERNAL_ERROR` | 0 |
| Action digest mismatch (mutated action) | **null** / `ACTION_MISMATCH` *(rev. 7: operational refusal; was deny)* | not_started | F | T | `ACTION_MISMATCH` | 0 |
| Proxy path re-resolution differs | **null** / `RESTRICTED_PATH` *(rev. 7: operational refusal; was deny)* | not_started | F | T | `RESTRICTED_PATH` | 0 |
| Tool raises | allow / `TOOL_FAILED` | failed | F | T | `TOOL_FAILED` | 1 |
| Output filter raises | allow / `OUTPUT_FILTER_FAILED` | succeeded | F | T | `OUTPUT_FILTER_FAILED` | 1 |
| Audit write: REQUEST_COMPLETED after success | allow / `AUDIT_UNAVAILABLE` | **succeeded** | F | F | `AUDIT_UNAVAILABLE` | 1 |
| Audit write: REQUEST_COMPLETED after a DENY | deny (unchanged reason) | not_started | F | F | `AUDIT_UNAVAILABLE` | 0 |
| Process killed after EXECUTION_STARTED (simulated: abort the pipeline in the spy, e.g. with a `BaseException` subclass) | — (exception propagates) | audit reconstruction ⇒ **unknown** | — | — | — | 1 |
| Invalid `SecurityPolicy` / non-existent prefix at construction | `ConfigurationError`; no client | — | — | — | — | — |

Proxy-stage blocks (digest mismatch, re-resolution): the DECISION audit event records policy's `allow`. *(Rev. 2–6: "the **effective** decision returned … is `deny`".)* **Rev. 7:** the result and REQUEST_COMPLETED carry `decision=None` with the refusal's code (C1.4, C1.6 rev. 6 table). The audit therefore shows both what policy decided and what was enforced.

**Rev. 6 (Q-03c):** unexpected internal errors (the gateway, identity, detector and policy rows, and the registry-lookup row) are **not** denials. The result has `decision=None`, `reason`/`error_code="INTERNAL_ERROR"`, `execution="not_started"`, `output_released=False`. REQUEST_COMPLETED records a NULL decision, with D-29 diagnostics on an ERROR event (no message text). Every such row additionally asserts that `decision != "deny"`.

Every row also asserts: no exception message, file path or SQL appears in `reason`, `error_code` or any audit field.

## 7. Negative security invariants

**Rev. 13 (C-11):** NI-01 to NI-19 are implemented in `tests/security/test_invariants.py` (shared helper over 20 scenarios), with NI-06 in `test_audit_ordering.py`, NI-11 in `test_secret_canary.py`, NI-15 in `test_audit_reconstruction.py`, NI-16 at proxy level (C-10). NI-13 at pipeline level is `test_action_digest_mismatch_is_an_operational_refusal`. *Original text:* These are the non-negotiable invariants. Each one **will be** implemented in `tests/security/test_invariants.py` (planned; no such tests exist yet) and checked across **every** E2E scenario through a shared assertion helper.

| ID | Invariant | Requirement |
|---|---|---|
| NI-01 | decision = DENY ⇒ spy count = 0 | SEC-002 |
| NI-02 | decision = REQUIRE_APPROVAL ⇒ spy count = 0 | SEC-003 |
| NI-03 | `authorized = False` ⇒ spy count = 0 | SEC-004 |
| NI-04 | any pre-execution audit write fails ⇒ spy count = 0 | SEC-005 |
| NI-05 | any security-critical stage raises before execution ⇒ `decision is None` ∧ `error_code = "INTERNAL_ERROR"` ∧ `execution = "not_started"` ∧ spy count = 0 *(rev. 6, Q-03c; rev. 1–5: "⇒ DENY `INTERNAL_ERROR`")* | SEC-009, SEC-033 |
| NI-06 | spy count = 1 ⇒ committed DECISION(allow) **and** EXECUTION_STARTED events with the same `request_id` and `action_digest` existed **before** the call (checked from inside the spy through a separate DB connection) | SEC-005, SEC-010 |
| NI-07 | spy count = 0 ⇔ `execution == "not_started"`; spy count = 1 ⇔ `execution ∈ {succeeded, failed}` (the in-process pipeline never returns `unknown` in v1) | SEC-022 |
| NI-08 | the kwargs received by the spy equal `decision.action.arguments` (path arguments canonical), and mutating them inside the tool does not change the audited values | SEC-010 |
| NI-09 | proxy given a non-ALLOW decision, or a decision for another `request_id` ⇒ spy count = 0 | SEC-010 |
| NI-10 | ALLOW ⇒ tool ∈ agent grants | SEC-001 |
| NI-11 | the canary secret appears in no audit row, log record, exception string or serialised result | SEC-008 |
| NI-12 | when the audit store is available, every request produces exactly one REQUEST_COMPLETED event (last) and **at most one** DECISION event, which exists iff policy reached a decision *(rev. 7; rev. 1–6: "exactly one DECISION")* | FR-012 |
| NI-13 | any mutation of `decision.action` after policy (top-level or nested argument values) ⇒ spy count = 0, `error_code="ACTION_MISMATCH"` | SEC-021 |
| NI-14 | `decision ≠ allow ⇒ execution = not_started`; `output_released ⇒ execution = succeeded ∧ audit_complete`; a post-invocation failure never yields `decision = deny` | SEC-022 |
| NI-15 | the C4.4 reconstruction of each request from audit rows alone matches the spy truth (not executed / executed); a run aborted after EXECUTION_STARTED reconstructs as **unknown** | SEC-023 |
| NI-16 | **(rev. 3)** for every decision, the number of invocations is ≤ 1, under any interleaving of threads and asyncio tasks (atomic single-use claim) | SEC-024 |
| NI-17 | **(rev. 3)** a `BaseException` after `entered` is re-raised unchanged, is never reported as `not_started` or DENY, and leaves the request reconstructable as **unknown** | SEC-027 |
| NI-19 | **(rev. 6)** `error_code = "INTERNAL_ERROR" ⇒ decision ≠ "deny"`; serialized decision values ⊆ {`"allow"`, `"deny"`, `"require_approval"`}; `decision is None ⇒ ¬output_released ∧ execution = "not_started"` | SEC-033, SEC-022 |
| NI-18 | **(rev. 3)** for a claimed request, no Sentinel code path invokes the tool a second time, whatever fails afterwards (filter, audit, mapping); at the adapter, a framework retry of the same `tool_call_id` does not execute again | SEC-026, SEC-025 |

## 8. Minimal end-to-end acceptance scenario ("walking skeleton")

This is the first E2E suite. It must pass before any detection, output-filter, rate-limit or framework work begins (gate G-M1 in `implementation_plan.md`).

**Setup (fixture):**
- File-backed SQLite audit DB in `tmp_path`.
- Workspace `tmp_path/ws/` containing `data.txt` (`"hello"`), and `tmp_path/outside/secret.txt`.
- Tools, each with a strict `arg_schema` (D-08): `read_file(path)` (path_args=`("path",)`, `destructive=False`); `delete_file(path)` (path_args=`("path",)`, `destructive=True`); `send_email(to, body)` (`destructive=False`, registered, not granted). Each tool is wrapped in a spy.
- Agent `research_agent` (enabled, no credential, so the fixture constructs identity with `require_credentials=False` explicitly: the default is `True`, D-04; rev. 9 correction), grants: `read_file` and `delete_file`, each with `allowed_path_prefixes=(<tmp_path>/ws,)`.
- `SecurityPolicy(version="test-1")`; detector = stub (no Tool-Abuse detector, D-15).

Audit abbreviations: RR = REQUEST_RECEIVED, IR = IDENTITY_RESOLVED, DEC = DECISION, ES = EXECUTION_STARTED, RC = REQUEST_COMPLETED (C4.3). Paths are absolute under `tmp_path`.

| ID | Request | decision / reason | execution · released · audit_complete | Spy counts | Audit sequence for the request |
|---|---|---|---|---|---|
| E2E-01 | `research_agent` `read_file(<ws>/data.txt)` | allow | succeeded · T · T; output `"hello"` | read=1 | RR, IR, DEC(allow), ES, RC(succeeded) |
| E2E-02 | `read_file(<ws>/../outside/secret.txt)` | deny `RESTRICTED_PATH` | not_started · F · T | read=0 | RR, IR, DEC(deny), RC(not_started) |
| E2E-03 | `send_email(...)` | deny `UNAUTHORIZED_TOOL` | not_started · F · T | email=0 | RR, IR, DEC(deny), RC |
| E2E-04 | agent `unknown_agent` `read_file(<ws>/data.txt)` | deny `UNAUTHORIZED_AGENT` | not_started · F · T | read=0 | RR, IR, DEC(deny), RC |
| E2E-05 | `delete_file(<ws>/data.txt)` | require_approval | not_started · F · T; file still exists | delete=0 | RR, IR, DEC(require_approval), RC |
| E2E-06 | `{"agent_id": "research_agent"}` (missing fields) | **null** `INVALID_REQUEST` *(rev. 7: operational refusal; was deny)* | not_started · F · T | all 0 | RR, RC(decision NULL) *(rev. 7; was RR, DEC(deny), RC)* |
| E2E-07 | E2E-01 with the audit store failing on DECISION | **allow** (policy decision preserved) `AUDIT_UNAVAILABLE` *(rev. 7; was deny)* | not_started · F · F | read=0 | RR, IR (then store down) |
| E2E-08 | E2E-01 with `arguments` containing `agent_id: "admin"` | **null** `INVALID_REQUEST` *(rev. 7: operational refusal; was deny)* | not_started · F · T | read=0 | RR, RC(decision NULL) *(rev. 7; was RR, DEC(deny), RC)* |
| E2E-09 | E2E-01 with the audit store failing on RC | allow `AUDIT_UNAVAILABLE` | **succeeded** · F · F | read=1 | RR, IR, DEC(allow), ES (RC missing; masked fallback log present) |

**Rev. 13 (C-11):** all nine scenarios pass in `integration/test_audit_ordering.py`. The executed scenarios (E2E-01, E2E-09) also write OUTPUT_FILTERED between EXECUTION_STARTED and REQUEST_COMPLETED: the filter stage runs on every executed call (FR-015; C4.3 `[OUTPUT_FILTERED | OUTPUT_WITHHELD]`), which these sequences did not list.

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

**Rev. 3:** executed as C-02 and extended by C-02b (reports in `docs/aidlc/02-construction/`). The production adapter tests derived from them are listed in §15.

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

## 14. Contract → acceptance-test map (rev. 4)

Every security contract in `decision_record.md` has at least one acceptance test. A contract becomes testable only once its decision is Approved; until then, the tests are specified but not yet authoritative.

| Contract | Decision(s) | Acceptance tests |
|---|---|---|
| C1.1 request identity | — | FR-002 tests; NI-12 |
| C1.2 trusted identity, reserved keys, credentials, tool-level grants | D-04, D-24b | identity suite (`unit/test_identity.py`, rev. 9: implemented in C-07: unknown, disabled, missing and wrong credential → `authorized=False`; `require_credentials` default `True`; digest-only storage; `compare_digest`; exact-name grants; prefixes through C-04); E2E-04, E2E-08 (pending C-11/C-12); adapter identity-injection test (M5) |
| C1.3 tool metadata | D-06, D-08, D-15 | registry suite; policy truth table P1–P8 |
| C1.4 action binding | D-07 | NI-08, NI-09, NI-13; fault rows "digest mismatch", "registry lookup" |
| C1.5 policy outcomes | D-06, D-24a/c, D-15 | truth table and precedence pairs (`unit/test_policy.py`); NI-01, NI-02, NI-10; E2E-02–05 |
| C1.6 execution outcomes | D-14 | NI-07, NI-14; all §6 rows |
| C1.7 audit pre/post | D-03, D-09 | NI-04, NI-06; §6 audit rows; E2E-07, E2E-09 |
| C1.8 errors | D-03, D-24d | §6 matrix (no row raises); NI-11 canary |
| C2 filesystem | D-05, D-18, D-21 | §5 F1–F20; E2E-02 |
| C3 identity and integration | D-04, D-12 | E1–E8 (experiment evidence); M5 regression tests |
| **C1.4 rule 5** atomic single-use claim (rev. 3) | D-25 | NI-16; AT-01–AT-03, AT-22 |
| **C1.6/C1.7** interruption → unknown (rev. 3) | D-14 amendment | NI-17; AT-08–AT-10 |
| **C3.5** adapter execution contract (rev. 3) | D-12, D-26, D-27, D-29–D-31 | NI-18; AT-04–AT-07, AT-11–AT-21, AT-23–AT-27, AT-32–AT-39 |
| **C1.4 rule 6** exact-action binding, canonical digest (rev. 4) | D-07 | AT-23, AT-28–AT-31 |
| **C1.8 / D-29** diagnostics (rev. 4) | D-29 | AT-12, AT-32, AT-33 |
| **D-30** internal async entry (rev. 4) | D-30 | AT-02, AT-08, AT-34 |
| **D-31** guard expiry, capacity, session rule (rev. 4) | D-31 | AT-26, AT-35, AT-36 |
| **C1.6/C1.8 Q-03c** internal errors distinct from denials (rev. 6) | Q-03c | NI-05, NI-19; AT-40–AT-43 |
| **C1.6 rev. 6** operational refusals are not policy decisions (rev. 7) | owner, §12 rev. 6 | NI-12 (revised); AT-44–AT-47 |
| C4 persistence | D-09, D-11 | NI-12, NI-15; `test_audit_storage_default.py` (FR-024); repository introspection (SEC-018); schema-version mismatch test (C4.6 item 4) |

## 15. Adapter and concurrency acceptance tests (rev. 3)

These tests implement the C-02/C-02b decisions against **production** code (pipeline, proxy, adapter). Status columns:

- **Spike evidence:** `SPIKE-RAN` = the scenario passed in a spike against stand-ins (it shows feasibility, not that Sentinel works); `NOT-RUN` = never demonstrated anywhere.
- **Production:** `PROD-TODO` unless marked otherwise. *(Rev. 3–4: "No production test below exists yet.")* **Rev. 5:** AT-28 and AT-29 are fully implemented; AT-30 and AT-31 are implemented at model level (C-03a). **Rev. 8 (C-03):** the model-level parts of AT-36, AT-40, AT-41, AT-44 and AT-46 are implemented in `tests/unit/test_models.py` (result-invariant table: 17 valid and 20 invalid rows) and pass. Their pipeline, gateway and adapter parts remain `PROD-TODO`. All others remain `PROD-TODO`.

Framework-dependent tests live in `tests/integrations/`, are marked `integration_framework`, and run against the pinned baseline (NFR-019). Concurrency tests use a barrier (threads) or `asyncio.gather` (tasks) and **must** include a deliberately non-atomic test double, to prove the test can fail.

| ID | Requirement | Test (production) | Expected | Spike evidence | Production | Increment |
|---|---|---|---|---|---|---|
| AT-01 | SEC-024 | 8 threads released by a barrier try to consume one ALLOW decision; 100 trials | Exactly 1 invocation and 7 `DECISION_ALREADY_USED` refusals per trial | SPIKE-RAN (C-02b B5/D3: 100/100) | **IMPLEMENTED (C-10), PASS**: `test_concurrent_consumption_executes_exactly_once` (8 threads, 100 trials) | C-10 |
| AT-02 | SEC-024, FR-026 | Same with 8 asyncio tasks via the async path | Same | SPIKE-RAN (C-02b B5/D3: 100/100) | **Proxy part IMPLEMENTED (C-10), PASS**: `test_concurrent_async_consumption_executes_exactly_once` (8 tasks, 100 trials); the async pipeline entry is C-11 | C-10/C-11 |
| AT-03 | SEC-024 (test power) | Run AT-01/AT-02 against a non-atomic claim test double | Duplicates observed in ≥ 1 trial (the suite must detect a race) | SPIKE-RAN (racy control: 50/50 trials duplicated) | **IMPLEMENTED (C-10), PASS**: `test_the_concurrency_test_detects_a_non_atomic_claim` | C-10 |
| AT-04 | SEC-025 | Tool fails after its side effect; adapter in "propagate" fault mode with the guard on; framework retries the same `tool_call_id` via `ToolRetryMiddleware(max_retries=2)` and via `RetryPolicy(max_attempts=3)` | 1 invocation; retries end as `DUPLICATE_TOOL_CALL` (not executed) | SPIKE-RAN (C-02b A10, B7, C5) | PROD-TODO | C-16 |
| AT-05 | SEC-025 | Agent loop re-issues the same tool with a **new** `tool_call_id` | Second call is independently evaluated (new decision) and executes if allowed. Documents that the guard does not stop new ids | SPIKE-RAN (C-02b A10 agent-loop: 2 decisions, 2 executions) | PROD-TODO | C-16 |
| AT-06 | SEC-025, D-31 | Same `tool_call_id`, different `session_id` (and different `agent_id`) | Not blocked: the key includes agent and session | NOT-RUN | **IMPLEMENTED (C-10), PASS**: `test_guard_key_includes_agent_and_session` | C-10 |
| AT-07 | SEC-025 | First attempt with id X is **denied**; a later attempt with id X is allowed | The denied attempt did not consume X; the later attempt executes once | NOT-RUN | **Proxy part IMPLEMENTED (C-10), PASS**: `test_refused_attempt_does_not_consume_the_call_id` (a refusal before the guard creates no entry). A policy DENY never reaches the proxy; that end-to-end case is C-11 | C-10 |
| AT-08 | SEC-027 | Cancel an async-native tool mid-execution (caller timeout) | Started 1, completed 0, `CancelledError`/`TimeoutError` reaches the caller, no re-execution for ≥ 2× the tool duration; audit has REQUEST_COMPLETED(`unknown`) or reconstructs as unknown | SPIKE-RAN for proxy state and no-retry (C-02b B6); audit part NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_cancel_async_tool_mid_execution` (started 1, `CancelledError` reaches the caller, REQUEST_COMPLETED(`unknown`) with `detail.interruption`, reconstructs unknown, no re-execution) | C-10/C-11 |
| AT-09 | SEC-027 | Cancel while the pipeline is still evaluating (before `entered`) | Spy 0; the `BaseException` propagates. Reconstruction from audit = not executed if no EXECUTION_STARTED was committed; = **unknown** (conservative, never "executed") if cancellation landed between EXECUTION_STARTED and `entered` | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_cancel_while_still_evaluating_never_runs_the_tool` (spy 0; the claimed run is abandoned and completed as `not_started`, more precise than the conservative unknown, I-29) | C-11 |
| AT-10 | SEC-027 | Interruption after `entered` while the audit store raises on every write | The original `BaseException` propagates (not replaced); reconstruction from committed rows = unknown | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_kill_with_the_store_down_still_reconstructs_unknown` (the original `BaseException` propagates; reconstruction = unknown, `no_completion`) | C-11 |
| AT-11 | SEC-026, NI-18 | Tool fails after its side effect; adapter in normal mode; under `RetryPolicy(max_attempts=3)` and `ToolRetryMiddleware(max_retries=2)`; sync, async-native, `Command` tools | Exactly 1 invocation in every combination; model sees `"tool failed (execution may have occurred)"` | SPIKE-RAN (C-02b retry matrix; naive propagation → 3) | PROD-TODO | C-16 |
| AT-12 | SEC-026, SEC-008, D-29 | Same, with a canary in the exception message | Canary absent from model-visible text and from the graph caller's exception; audit row has type, module, stage and location, and no message text (default config) | SPIKE-RAN for model-visible text; audit part NOT-RUN | **Audit part IMPLEMENTED (C-09), PASS**: `test_tool_exception_from_a_module_at_an_absolute_path_leaks_nothing` (D-29 fields only, no message text). Model-visible text is C-16 | C-09/C-16 |
| AT-13 | SEC-028 | `Command(update=…)` and `Command(goto=…)` tools, sync and async, via `ToolNode` and `create_agent`: original vs wrapped | Identical final state, messages and routing | SPIKE-RAN (C-02b C1–C2, C6) | PROD-TODO | C-16 |
| AT-14 | SEC-028, SEC-002/003 | Denied and approval-required `Command` tools | 0 invocations; routing target ran 0 times; no state update; error `ToolMessage`, never a `Command` | SPIKE-RAN (C-02b C3–C4) | PROD-TODO | C-16 |
| AT-15 | SEC-028 | `InjectedToolCallId` tool | Id forwarded to the original (framework validation passes); model-facing schema and evaluated action exclude it | SPIKE-RAN (C-02b C1–C2) | PROD-TODO | C-16 |
| AT-16 | SEC-029 | Tools with `InjectedState`, `InjectedStore`, `ToolRuntime` parameters | Refused at wrap time | SPIKE-RAN for `InjectedState`; NOT-RUN for `InjectedStore`, `ToolRuntime` | PROD-TODO | C-16 |
| AT-17 | SEC-029 | `dict` provider tool; class-based `BaseTool`; tool without Sentinel metadata | Refused at wrap time | SPIKE-RAN (C-02b A5–A6) | PROD-TODO | C-16 |
| AT-18 | SEC-030 | Model emits an unknown tool name; contrast with a denied tool | Unknown: 0 evaluations, 0 invocations, framework message. Denied: 1 evaluation | SPIKE-RAN (C-02b A4) | PROD-TODO | C-16 |
| AT-19 | FR-025, SEC-031 | Coverage report on: mixed agent (wrapped + unwrapped); middleware-supplied tool; unrecognised structure | `{wrapped: true, unwrapped: false}`; middleware tool `false`; "not inspectable" | SPIKE-RAN for the first two (C-02b A5–A6); third NOT-RUN | PROD-TODO | C-16 |
| AT-20 | SEC-002/003, SEC-016 | Deny/approval matrix: tool kind (sync, async-native, `Command`) × entry point (`create_agent`/`ToolNode`, sync and async) | 0 invocations everywhere; explicit evaluation where the adapter is reached | SPIKE-RAN (C-02b D4–D5: 20 rows, 0 invocations) | PROD-TODO | C-16 |
| AT-21 | SEC-016, SEC-030 | Sync entry into an async-only wrapped tool | Framework rejects; 0 evaluations, 0 invocations | SPIKE-RAN (C-02b B4, D4–D5) | PROD-TODO | C-16 |
| AT-22 | SEC-024 | Sequential replay of one decision (sync and async paths) | First executes; second refused | SPIKE-RAN (C-02b D1–D2) | **IMPLEMENTED (C-10), PASS**: `test_second_use_of_a_decision_is_refused` (sync), `test_second_use_of_a_decision_is_refused_async`, `test_copied_or_reconstructed_decision_cannot_replay` | C-10 |
| AT-23 | SEC-010, SEC-021 | Forged decision: args A used for args B; tool X for tool Y; DENY decision; args mutated after evaluation (sync and async) | Not executed in every case | SPIKE-RAN (C-02 B4; C-02b D1–D2) | **IMPLEMENTED (C-10, sync path), PASS**: `test_forged_decision_for_other_arguments_is_refused`, `test_decision_for_another_tool_is_refused`, `test_deny_decision_never_executes`, `test_tampered_action_arguments_are_refused`, `test_request_arguments_differing_from_the_action_are_refused`. Binding is checked in `claim`, shared by both paths | C-10 |
| AT-24 | NFR-016 | Parallel tool calls in one model turn (thread pool and asyncio) with the real SQLite audit store | No errors; expected rows; no lost or interleaved events | NOT-RUN | PROD-TODO | C-11/C-16 |
| AT-25 | SEC-025, FR-012 | Audit rows for a duplicate `tool_call_id` attempt | DECISION(allow) recorded, then REQUEST_COMPLETED(decision NULL, `DUPLICATE_TOOL_CALL`, not_started) (rev. 7; was "deny `DUPLICATE_TOOL_CALL`"); no EXECUTION_STARTED; reconstructs as not executed | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_duplicate_tool_call_id_is_audited_as_a_refusal` | C-10/C-11 |
| AT-26 | SEC-025, D-31 | **Rev. 4:** guard filled to capacity with **unexpired** entries (in flight and terminal-within-TTL), then a new guarded invocation | New invocation → `decision=None`, `GUARD_CAPACITY_EXHAUSTED` (rev. 7; was effective DENY), 0 invocations; **no existing entry is evicted** (a repeat of every existing key is still refused); a call without a `tool_call_id` is unaffected; after the injected clock passes TTL for one terminal entry, exactly one new guarded call is admitted. *Rev. 3 text ("Oldest keys evicted per D-31") superseded: eviction rejected by the owner* | NOT-RUN | **IMPLEMENTED (C-10), PASS**: `test_capacity_fails_closed_without_eviction`, `test_capacity_refusal_through_the_proxy_and_calls_without_id_unaffected` | C-10 |
| AT-27 | SEC-031 | Documentation review: README, docstrings and log messages never describe unwrapped, middleware-supplied or provider built-in tools, or `Command` downstream effects, as protected | Checklist passes | NOT-RUN | PROD-TODO | C-16, C-18 |
| AT-28 | SEC-032, D-07 | Compute the digest of the same action in ≥ 3 separate interpreter processes with different `PYTHONHASHSEED` values and different dict insertion orders | Identical digests | NOT-RUN (the spike digest was a stand-in, never tested across processes) | **IMPLEMENTED (C-03a), PASS**: `test_digest_is_identical_across_processes_and_hash_seeds` (4 seeds × 2 insertion orders, separate interpreters) | C-03 |
| AT-29 | SEC-032, D-07 | Table-driven nested changes: a leaf value deep in a dict; list order; `int` → `str` type change; `1` vs `1.0` vs `True`; added or removed key; a canonical path that differs by one component; a Unicode composed vs decomposed string | Every case changes the digest; unchanged inputs keep it | NOT-RUN | **IMPLEMENTED (C-03a), PASS**: `test_every_nested_change_alters_the_digest` (14 cases), `test_identity_fields_alter_the_digest` | C-03 |
| AT-30 | SEC-032, D-07, D-31 | Two requests differing only in `tool_call_id` | Identical action content (`agent_id`, `tool`, `arguments`), with `tool_call_id` absent from the digest input; the guard still distinguishes them by `tool_call_id` | SPIKE-RAN for exclusion from the evaluated args (C-02b C1–C2); digest part NOT-RUN | **Model part IMPLEMENTED (C-03a), PASS**: `test_tool_call_id_is_not_part_of_an_action`, `test_digest_input_is_exactly_the_four_action_fields`; guard part PROD-TODO (C-10) | C-03 (model), C-10 (guard) |
| AT-31 | SEC-032, D-07 | Argument values that are not JSON-native (`set`, `bytes`, `datetime`, custom object, `NaN`, `inf`, non-`str` dict keys) | Rejected (`INVALID_REQUEST` at the gateway; a validation error at model level); never encoded with `repr` | NOT-RUN | **Model part IMPLEMENTED (C-03a), PASS**: `test_unsupported_values_are_rejected_nested_and_top_level` (19 value kinds, top-level and nested, error text without values), `test_arguments_must_be_a_dict`, `test_identity_fields_must_be_non_empty_str`; **gateway part IMPLEMENTED (C-06), PASS**: `test_non_json_native_values_are_refused` (set, tuple, NaN, inf, bytes, datetime through a `dict[str, Any]` field), `test_nan_in_a_float_field_is_refused` → `InvalidRequestError`; the pipeline reporting `decision=None`, `INVALID_REQUEST` is C-11 | C-03, C-06 |
| AT-32 | SEC-026, SEC-008, D-29 | Tool raises an exception whose message and a frame-local variable contain a canary, from a module at an absolute path | The audit `detail` has exception type, module, function, line, stage, `request_id`, tool, `error_code`; the canary, the message text, traceback text and any absolute path are **absent** from every audit row and log record | NOT-RUN | **IMPLEMENTED at unit level (C-09 with C-10 diagnostics), PASS**: `test_tool_exception_from_a_module_at_an_absolute_path_leaks_nothing`: canary in message and frame-local, module at an absolute path; the stored row and every log record (including the fallback) hold only exception type, module, function, line, stage, `request_id`, tool and error code. End-to-end through the pipeline is C-11 | C-09, C-10 |
| AT-33 | D-29 | Configuration surface | No configuration option enables storage of exception message text in v1 (introspection of the config model and its documentation) | NOT-RUN | **IMPLEMENTED (C-09), PASS**: `test_no_configuration_enables_exception_message_storage` (no store or logger option stores message text) | C-09 |
| AT-34 | FR-026, D-30 | API surface | The async pipeline entry is not in `sentinel.__all__` or any `sentinel.integrations.*.__all__`, is not a public `SentinelClient` attribute, and is marked internal in docs; the adapter uses it | NOT-RUN | **C-11 part IMPLEMENTED, PASS**: `test_async_entry_is_internal` (nothing exported). `SentinelClient` (C-12) and the adapter (C-16) parts remain | C-11, C-12, C-16 |
| AT-35 | SEC-025, D-31 | Guard expiry with an injected monotonic clock | An in-flight entry never expires (clock advanced beyond TTL while the tool is running → a repeat is still refused); a terminal entry is purged only after terminal time + TTL; after purge a repeat with the same key is treated as new (documented limitation) | NOT-RUN | **IMPLEMENTED (C-10), PASS**: `test_in_flight_entry_never_expires`, `test_in_flight_entry_does_not_expire_during_a_long_tool_call` | C-10 |
| AT-36 | SEC-025, D-31 | Request carrying a `tool_call_id` but no `session_id` | `decision=None`, `INVALID_REQUEST` (rev. 7; was DENY), 0 invocations, no guard entry created | NOT-RUN | **Gateway part IMPLEMENTED (C-06), PASS**: `test_tool_call_id_without_session_id_is_refused` (the model requires `session_id`). "No guard entry created" is C-10; result mapping is C-11 | C-03 (model rule), C-06 |
| AT-37 | SEC-013, FR-022 (carried from C-17) | Through `create_agent`, the model emits a tool call whose arguments include `agent_id` / `session_id` / `tool_call_id` | Evaluated as the bound agent, or rejected per the D-04 outcome; never as the model-supplied identity; 0 executions under a foreign identity | NOT-RUN | PROD-TODO | C-16 |
| AT-38 | FR-022, SEC-016 (carried from C-17 / E2) | `create_agent` with wrapped tools driven via `invoke`, `ainvoke`, `stream`, `astream`, `batch` | Every entry point evaluates before execution; denied tool never executes; sync entry into an async-only tool rejected by the framework | SPIKE-RAN for `invoke`/`ainvoke` (C-02b A, B); `stream`/`astream`/`batch` via `create_agent` NOT-RUN (via `ToolNode` SPIKE-RAN, C-02 B8) | PROD-TODO | C-16 |
| AT-39 | FR-022 (carried from C-17 / C-16 "example") | Runnable example: a `create_agent` agent with one allowed and one denied wrapped tool, offline scripted model | Example exits 0; allowed tool runs once; denied tool 0 times; output shows the fixed-text denial | NOT-RUN | PROD-TODO | C-16 |
| AT-40 | SEC-033, SEC-009 | Force an unexpected exception in each pre-invocation stage (gateway, identity, detector, policy, registry lookup, proxy checks), with a canary in the exception message | `decision is None` (never `"deny"`), `reason`/`error_code="INTERNAL_ERROR"`, `execution="not_started"`, `output_released=False`, spy 0; audit has ERROR with D-29 fields and REQUEST_COMPLETED with NULL decision; canary absent everywhere | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_unexpected_errors_before_execution_are_internal_errors` (gateway, identity, detector, policy, with a canary and a path in the message), `test_registry_lookup_failure_in_the_proxy_is_an_internal_error` | C-03 (model), C-11 |
| AT-41 | SEC-033, D-24i | Decision value set and fault matrix | `Decision` serializes only to `"allow"`, `"deny"`, `"require_approval"` (no `"error"`); across all §6 rows, `INTERNAL_ERROR` is never paired with `"deny"` | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_invariants_hold_in_every_scenario` (NI-19 across 20 scenarios) | C-03, C-11 |
| AT-42 | SEC-033, SEC-026 | Framework adapter receives an internal-error result, under `RetryPolicy` and `ToolRetryMiddleware` | Model sees exactly `"not executed: INTERNAL_ERROR"` (not `"blocked: …"`); no diagnostics in model-visible text; no exception escapes; 0 executions | NOT-RUN | PROD-TODO | C-16 |
| AT-43 | SEC-033, D-03 | Unexpected internal error **after** the tool ran (e.g. in result mapping) | `decision="allow"` kept, `execution` truthful (`succeeded`/`failed`), output withheld, `error_code="INTERNAL_ERROR"`, never `"deny"`, no re-execution | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_internal_error_after_execution_keeps_allow_and_truth` | C-11 |
| AT-44 | SEC-034 | Each operational refusal: invalid request (shape, unregistered tool, schema, reserved key, `tool_call_id` without session), action mismatch, path changed after authorization, decision already used, duplicate `tool_call_id`, guard capacity exhausted | `decision is None`; the specific `error_code`; `execution="not_started"`; spy 0; REQUEST_COMPLETED decision NULL; never `"deny"` | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_e2e_06…`, `test_e2e_08…`, `test_action_digest_mismatch_is_an_operational_refusal`, `test_path_changed_after_execution_started_is_refused`, `test_duplicate_tool_call_id_is_audited_as_a_refusal`; capacity and already-used at proxy level (C-10) | C-03 (model), C-06, C-10, C-11 |
| AT-45 | SEC-034, SEC-005 | Pre-execution audit failure at each write: REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING (before policy) vs DECISION, EXECUTION_STARTED (after policy) | Before policy → `decision=None`; after policy → the actual decision preserved (`allow` or `deny`); `AUDIT_UNAVAILABLE`; never executed | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_pre_execution_audit_failure_never_invokes` (5 events), `test_decision_write_failure_after_a_deny_keeps_the_policy_reason` | C-11 |
| AT-46 | SEC-034, SEC-033 | Whole §6 fault matrix plus the E2E suite | `decision == "deny"` only with C1.5 policy reasons; every operational-refusal or internal-error code appears only with `decision` None (or a preserved real decision for `AUDIT_UNAVAILABLE`) | NOT-RUN | **IMPLEMENTED (C-11), PASS**: `test_invariants_hold_in_every_scenario` | C-03, C-11 |
| AT-47 | SEC-034, SEC-026 | Framework adapter receives each refusal | Fixed text `"not executed: <ERROR_CODE>"`, never `"blocked: …"`; no diagnostics; no escape; 0 executions; direct-caller exception mapping never uses `ActionDenied` for refusals | NOT-RUN | PROD-TODO | C-16 (C-03 for the exception classes) |

**Also not demonstrated anywhere (no test can be claimed):** real provider `tool_call_id` behaviour; checkpoint resume/replay; `Send` / `Command.PARENT`; human-in-the-loop middleware; retry mechanisms other than the two tested. These are documented limitations (decision record C3.6), not acceptance tests.
