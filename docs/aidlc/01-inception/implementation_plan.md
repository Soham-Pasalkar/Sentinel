# Implementation Plan — Sentinel v1 Construction (rev. 2)

| | |
|---|---|
| Phase | Inception, revised in Phase 1.5 (plan only; **nothing is implemented**) |
| Date | 2026-10-28 |
| Status | Draft rev. 2 — pending owner review. Contracts and decisions: [`decision_record.md`](decision_record.md) |

## 1. Shape of the plan

- Small, dependency-ordered increments (C-01 … C-18). Each is one reviewable unit and, if D-13 is approved, one local commit after its evidence is produced.
- **M1 (C-01 … C-12)** delivers the walking skeleton: E2E-01 … E2E-09 and NI-01 … NI-15 (`testing_strategy.md` §7–8).
- **The LangGraph experiment (C-02) runs straight after the scaffold and before any contract is coded**, so that a negative E1 or E2 result can still change C1.
- **Rev. 2 changes from rev. 1:**
  - The gateway (C-06) now depends on the path guard (C-04), because canonicalisation moved before policy (C2.4).
  - Policy (C-08) uses only the pure containment function.
  - C-03 adds `AuthorizedAction`, the digest, and the C1.6 result fields.
  - C-09 implements the C4.3 lifecycle, durable default storage and the C4.4 reconstruction helper.
  - C-10 adds digest verification and re-resolution.
  - C-16 implements `wrap_tools`, not `protect`.
  - Every increment lists the decisions that must be **Approved** before it starts.
- No placeholder modules: each module is created by the increment that implements it.

## 2. Gate G-0 — Construction entry (from `decision_record.md` §8)

**Required before C-01:**

| # | Item | Evidence |
|---|---|---|
| G0-1 | D-01 (Python floor) Approved | Status in `decision_record.md` |
| G0-2 | D-02: provisional names accepted, or final names chosen | Status recorded (may remain "Pending verification" if provisional names are explicitly accepted) |
| G0-3 | D-13 (commit policy) Approved | Status |
| G0-4 | D-22 (dev dependencies, build backend) Approved | Status |
| G0-5 | D-23 (decision register location) Approved | Status |
| G0-6 | Explicit owner instruction to begin C-01 | Owner message |

**May stay provisional at C-01:** D-10, D-12, D-17, D-19 (M3 mode), D-20 (final form), D-21 (CI OS matrix adjustable), D-24 items not used by C-01.

**Security contracts that must be Approved before the increment that encodes them** (see "Blocked by" in each increment): C-03 ← D-03, D-04, D-06, D-07, D-08, D-14, D-15, D-24c, D-24d; C-04 ← D-05, D-18, D-21; C-09 ← D-09, D-11, D-24f; C-11 ← D-16, D-20. **Implementing first and deciding later is not permitted** for these.

## 3. Increments

### C-01 — Project scaffold and development tooling
- **Objective:** an installable package with lint, type, test and CI wiring, and no security logic.
- **Scope:** `pyproject.toml` (name per D-02, `requires-python` per D-01, deps Pydantic v2 and SQLAlchemy 2.x with bounds, `[dev]` per D-22, build backend per D-22); `src/sentinel/__init__.py` (`__version__` only); `.gitignore` (`.DS_Store`, `.venv/`, `spikes/**/.venv/`, `*.db`, `*.db-wal`, `*.db-shm`, `.env`, `__pycache__/`, `.coverage`, `dist/`); `.env.example` (names only); `README.md` (status table "not started", limitations placeholder that links to `decision_record.md`); `.github/workflows/ci.yml` (ruff, mypy, pytest matrix per D-01/D-21); `tests/unit/test_import_hygiene.py`.
- **Dependencies:** G-0. **Blocked by:** D-01, D-02, D-13, D-22, D-23.
- **Acceptance:** in a fresh venv, `pip install -e ".[dev]"` succeeds; `pytest` runs ≥ 1 test and passes; `ruff check`, `ruff format --check` and `mypy src` are clean; `git status` shows no `.DS_Store`, `*.db` or venv files staged.
- **Tests:** NFR-003 import hygiene.
- **Security invariants:** secrets and DB files are ignored by git.
- **Evidence:** command transcript; `git show --stat` of the local commit. Push only if the owner asks.
- **Execution notes (2026-10-28), per the owner's C-01 instruction, where it differs from the scope above:**
  - Runtime `dependencies = []`: Pydantic and SQLAlchemy are deferred to the increments that use them.
  - Dev tools are pytest and Ruff only (D-22 partly approved). mypy is **not** configured.
  - No `.env.example`, since nothing reads configuration yet.
  - `constraints-dev.txt` was added for reproducible tool versions.
  - Ruff excludes `SENTINEL_BUILD_BRIEF.md` and `docs/`, because Ruff 0.17 formats Markdown code blocks and would otherwise propose rewriting the brief.
  - CI runs on `ubuntu-latest` only (D-21 still Proposed).
  - Because mypy is not approved, the `mypy src` acceptance item above does not apply to C-01.
  - **Status: complete locally.** Committed as `8a5a993` on branch `c01-project-scaffold`. Local checks pass (pytest, Ruff lint and format, editable install on 3.11, wheel install on 3.12). GitHub Actions has **not** run, so it is unverified. Not pushed.

### C-02 — LangGraph interception experiment (isolated, throwaway)
- **Objective:** produce evidence for E1–E8 (`decision_record.md` §3.4).
- **Scope:** `spikes/langgraph_interception/` with its own git-ignored venv. Stand-in gate function only; no product code. Report at `docs/aidlc/02-construction/spike_framework_interception.md`.
- **Dependencies:** C-01 (repo conventions, `.gitignore`).
- **Blocked by:** owner approval to install LangGraph/LangChain in the spike venv (D-12 prerequisite).
- **Timebox:** ½ day (extendable to 1 day with approval).
- **Acceptance:** the report has evidence (commands and output, `pip freeze`, Python version) for every experiment, a recommended adapter design, and stated impacts on D-04, D-12 and D-20.
- **Stop condition:** if E1 or E2 fails, stop and escalate to the owner before C-03.
- **Evidence:** the report. The owner then sets D-12 status.

### C-03 — Exceptions and core models / contracts
- **Objective:** encode C1 in types.
- **Scope:** `exceptions.py` (FR-018); `models.py`: `Decision` (lowercase values), `Severity`, `SecurityRequest` (frozen, `SecretStr`), `ToolGrant`, `RateLimit`, `CapabilityEnvelope`, `SecurityContext`, `SecurityFinding`, `ToolSpec` (metadata only), `AuthorizedAction` (with digest function), `SecurityDecision` (with `action`), `PipelineResult` (C1.6 fields), reason and error code constants.
- **Dependencies:** C-01; C-02 report reviewed.
- **Blocked by:** D-03, D-04, D-06, D-07, D-08, D-14, D-15, D-24c, D-24d.
- **Acceptance:** model validation; frozen models reject attribute assignment; the digest is stable across runs and differs for any change in a nested argument; `SecretStr` is absent from `repr` and JSON; enum ordering.
- **Tests:** `unit/test_models.py`, `unit/test_action_digest.py`, `unit/test_exceptions.py`.
- **Security invariants:** SEC-008 (models); digest sensitivity (basis for SEC-021).
- **Evidence:** pytest and mypy output.

### C-04 — Path guard (canonicalisation and pure containment)
- **Objective:** C2 as two functions: `canonicalise(path) -> str` (I/O, used by the gateway and the proxy) and `is_contained(canonical, prefixes) -> bool` (pure, used by policy and the proxy).
- **Scope:** one small module (`paths.py`, or inside `policy.py` if the owner prefers); prefix registration helper (exists, is a directory, `strict` realpath).
- **Dependencies:** C-03. **Blocked by:** D-05, D-18, D-21.
- **Acceptance:** F1–F20 as specified (F15 strict xfail; F17 limitation test), on macOS locally and Linux in CI.
- **Tests:** `unit/test_path_guard.py`; optional Hypothesis property test (accepted ⇒ contained by component).
- **Security invariants:** SEC-007.
- **Evidence:** pytest output from both OSes.

### C-05 — Tool registry
- **Scope:** `registry.py`: register (unique; `arg_schema` and `destructive` required; `path_args` ⊆ schema `str` fields; refuses path tools on Windows), lookup of `(ToolSpec, callable)`, read-only spec listing.
- **Dependencies:** C-03. **Blocked by:** D-06, D-08, D-21.
- **Acceptance:** duplicate, missing-flag, missing-schema and bad-`path_args` registrations raise `RegistrationError`.
- **Tests:** `unit/test_registry.py`. **Invariants:** SEC-014. **Evidence:** pytest output.

### C-06 — Gateway: validation, strict arguments, canonicalisation
- **Objective:** raw dict → frozen `SecurityRequest` plus the `AuthorizedAction` candidate.
- **Scope:** `gateway.py`: shape validation; tool registered; reserved keys; strict `arg_schema` validation (extra forbidden); path arguments validated (C2.3) and canonicalised (C2.4); sanitised error rendering (no input values).
- **Dependencies:** C-03, C-04, C-05. **Blocked by:** D-04 (reserved keys), D-08, D-18.
- **Acceptance:** FR-001, FR-003, FR-004; relative, `~`, NUL and empty paths → `INVALID_REQUEST`; the canonical path appears in the action; the canary from an invalid field is absent from the error.
- **Tests:** `unit/test_gateway.py`. **Invariants:** SEC-008 (validation errors), SEC-013 (reserved keys). **Evidence:** pytest output.

### C-07 — Identity and capability lookup
- **Scope:** `identity.py`: in-memory agent and envelope repositories; `register_agent` support (hash only); `require_credentials`.
- **Dependencies:** C-03; C-04 (prefix registration helper for grants). **Blocked by:** D-04, D-05.
- **Acceptance:** FR-005–007; grant with a non-existent prefix → `ConfigurationError`; empty prefixes allowed at registration with a warning.
- **Tests:** `unit/test_identity.py`. **Invariants:** identity never decides. **Evidence:** pytest output.

### C-08 — Policy engine
- **Scope:** `policy.py`: `SecurityPolicy`; `PolicyEngine.evaluate(request, context, findings, tool_spec)` rows 1–4, 6, 7; pure; embeds the action in the decision.
- **Dependencies:** C-03, C-04 (`is_contained`), C-07. **Blocked by:** D-05, D-06, D-15, D-24a/b/c.
- **Acceptance:** truth table P1–P8 and precedence pairs; determinism (1,000 iterations); evaluation succeeds with file and socket access patched to raise.
- **Tests:** `unit/test_policy.py`. **Invariants:** SEC-001, SEC-012, SEC-019. **Evidence:** pytest output.

### C-09 — Audit store and logger
- **Scope:** `store.py` (`audit_events` table per C4.2, insert and read only, `schema_version` check, WAL + `synchronous=FULL`, default `sentinel_audit.db` resolved at construction); `audit.py` (`AuditLogger.record`, masking, truncation, commit per event, masked `logging` fallback); `reconstruct()` helper implementing C4.4 (also used by tests).
- **Dependencies:** C-03. **Blocked by:** D-09, D-11, D-20, D-24f.
- **Acceptance:** a committed row is visible through a second connection on return; no update/delete; masking and truncation; schema-version mismatch → writes refused; default path created at construction (not import) and logged; `:memory:` → warning; 8-thread inserts consistent.
- **Tests:** `unit/test_audit_repository.py`, `unit/test_masking.py`, `integration/test_audit_storage_default.py`, `unit/test_reconstruction.py`.
- **Invariants:** SEC-018, SEC-008 (audit sink), FR-024. **Evidence:** pytest output.

### C-10 — Tool proxy with output-filter stage
- **Scope:** `proxy.py`: binding checks (ALLOW, matching `request_id`s, digest); proxy re-resolution (C2.7); `entered` flag; invoke `fn(**deepcopy(action.arguments))`; tool-error containment; output-filter stage (pass-through) with fail-closed handling. Returns a `ToolResult`-level outcome the pipeline maps to C1.6.
- **Dependencies:** C-03, C-04, C-05, C-08. **Blocked by:** D-07, D-14, D-19 (failure rule).
- **Acceptance:** NI-08, NI-09, NI-13; F14, F16; tool error → `failed` with no message; filter error → withheld.
- **Tests:** `unit/test_proxy.py`, `security/test_action_integrity.py`, `integration/test_proxy_filesystem.py`.
- **Invariants:** SEC-002, SEC-003, SEC-010, SEC-011, SEC-017, SEC-021. **Evidence:** pytest output.

### C-11 — Pipeline orchestration
- **Scope:** `pipeline.py` (sole orchestrator and sole audit writer, C4.3 order, C1.7 behaviour, C1.8 error mapping); `config.py`; `detector.py` stub (`[]`).
- **Dependencies:** C-06 … C-10. **Blocked by:** D-03, D-16, D-20.
- **Acceptance:** E2E-01 … E2E-09 at pipeline level; full §6 fault-injection matrix; NI-01 … NI-15; canary test.
- **Tests:** `integration/test_audit_ordering.py`, `integration/test_audit_reconstruction.py`, `security/test_fault_injection.py`, `security/test_invariants.py`, `security/test_secret_canary.py`.
- **Invariants:** SEC-005, SEC-006, SEC-009, SEC-022, SEC-023. **Evidence:** pytest output including the security-suite summary.

### C-12 — Public client, quickstart, README (closes M1)
- **Scope:** `client.py` (`SentinelClient`, `register_tool`, `register_agent`, `evaluate_request`, `audit_events`); `__all__` (no proxy); `examples/quickstart.py`; README (status table, limitations from `decision_record.md` §2/§4.6/§6, decisions link).
- **Dependencies:** C-11. **Blocked by:** D-17, D-24i.
- **Acceptance:** E2E-01 … E2E-09 through `SentinelClient`; the quickstart exits 0 and its subprocess test passes; `__all__` test.
- **Tests:** `e2e/test_client.py`, `e2e/test_quickstart.py`. **Evidence:** pytest, ruff, mypy and coverage outputs; quickstart output.

#### Gate G-M1
C-01 … C-12 complete; NFR-006 coverage met; README accurate; threat model revisited; owner review before M2.

### C-13 — Detection heuristics (M2)
Recursive argument scanning, injection and sensitive-data rules, benign corpus, alert manager. **Blocked by:** D-24e, D-24h, the owner's review of the rule and severity table. **Acceptance:** table-driven tests; measured corpus counts; documented evasion test. **Invariants:** SEC-012, SEC-020.

### C-14 — Output filtering (M3)
Redaction across nested containers; `redact`/`block`; unsupported types withheld. **Blocked by:** D-19 (mode). **Acceptance:** canary redaction and blocking tests.

### C-15 — Rate limits (M4)
Atomic per-agent counters with an injected clock; policy row 5. **Blocked by:** D-20; the cross-agent constraint mechanism (brief §12). **Acceptance:** FR-019 tests.

### C-16 — LangGraph adapter `wrap_tools` (M5)
Design from the C-02 report; identity bound by parameter; async fails closed; `[langgraph]` extra with a tested version range. **Blocked by:** D-12, D-04. **Acceptance:** FR-021, SEC-013 (adapter), SEC-016; E1/E2/E4 regression tests; example graph.

### C-17 — LangChain wrapping (M5, COULD)
As C-16 (FR-022).

### C-18 — Documentation, packaging, release readiness
README final pass; performance measurement (NFR-011); wheel and fresh-venv smoke test; threat-model and security review. **Blocked by:** D-02 verified; owner approval before any publication. **Acceptance:** every MUST requirement traced to passing tests or completed inspections; open decisions closed or explicitly deferred.

## 4. Dependency graph

```text
G-0 → C-01 → C-02 (experiment; stop if E1/E2 fail)
                │
                ▼
              C-03 ─┬─► C-04 ─┬─────────────► C-06 (also needs C-05) ─┐
                    ├─► C-05 ─┘                                       │
                    ├─► C-07 (needs C-04) ─► C-08 (needs C-04) ───────┤
                    ├─► C-09 ─────────────────────────────────────────┼─► C-11 ─► C-12 ─► [G-M1]
                    └─► C-10 (needs C-04, C-05, C-08) ────────────────┘
[G-M1] → C-13 | C-14 | C-15 (any order) → C-16 → C-17 → C-18
```

## 5. Definition of done (every increment)

1. Scope implemented; no placeholder modules; nothing outside scope.
2. The listed tests exist and fail without the code under test (where meaningful).
3. `pytest`, `ruff check` and `ruff format --check` are clean, plus `mypy src` once D-22 approves mypy, with **actual output** in the increment report.
4. README status updated in the same commit.
5. Every decision the increment relies on is **Approved** in `decision_record.md`. New decisions or deviations are recorded there first.
6. One local conventional commit (D-13). No push unless the owner asks.

## 6. Change log

| Rev. | Change |
|---|---|
| 1 | Initial Inception plan |
| 2 | Phase 1.5: G-0 per decision record §8; per-increment "Blocked by" lists use D-IDs; C-06 depends on C-04 (gateway canonicalisation); C-03 adds `AuthorizedAction` and the C1.6 result; C-09 lifecycle, durable default and reconstruction; C-10 digest and re-resolution; C-16 `wrap_tools`; E2E-09 and NI-13–15 added to gates. Rev. 1's spike questions S1–S7 are superseded by E1–E8 (mapping in `testing_strategy.md` §10) |
