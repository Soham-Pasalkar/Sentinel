# Implementation Plan — Sentinel v1 Construction (rev. 8)

| | |
|---|---|
| Phase | Inception, revised in Phase 1.5 and after the C-02/C-02b review (rev. 3). Implemented and committed: **C-01** (`8a5a993`), **C-03a and C-03** (`153df80`). C-02/C-02b were throwaway experiments (evidence committed in `2bd5ec4`) |
| Date | 2026-10-28; 2026-11-08 (rev. 8) |
| Status | Draft rev. 8 — pending owner review. **Rev. 8:** D-05, D-18, D-21 Approved; C-04 unblocked. *Rev. 7 status, kept as history:* C-03 approved by the owner but **blocked on the Pydantic dependency** (no C-03 code written). **C-03a authorized and implemented (uncommitted); full C-03 not authorized** (gate: `decision_record.md` §8.6, rev. 4 update). Contracts and decisions: [`decision_record.md`](decision_record.md) |

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
- **Rev. 3 changes (after the owner approved D-12, D-25–D-28 and the D-14 amendment):**
  - C-02 and the new C-02b are recorded as **done**.
  - C-03 adds the optional `tool_call_id` field (D-31) and the in-process `unknown` semantics.
  - C-05 registers sync and/or async callables.
  - C-09 records interruption and diagnostics (D-29).
  - C-10 adds the atomic single-use claim (D-25), the `tool_call_id` guard (D-27), the async execution path and the interruption state machine.
  - C-11 adds the async entry (D-30) and best-effort `unknown` records.
  - C-16 becomes the Design B adapter for sync, async-native and `Command` tools, with `ToolNode` and `create_agent` as callers.
  - C-17 is folded into C-16 (`create_agent` is in D-12 scope).
  - Production acceptance tests AT-01–AT-27 (`testing_strategy.md` §15) are assigned to increments.
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

**Security contracts that must be Approved before the increment that encodes them** (see "Blocked by" in each increment). Rev. 3 list, updated in rev. 4 (D-07, D-29, D-30, D-31 now Approved):
- C-03 ← D-03, D-04, D-06, D-08, D-14 (remainder), D-15, D-24c, D-24d, **D-24i** (added in rev. 4; D-24b too if `ToolGrant` stays in C-03). Authoritative checklist: `decision_record.md` §8.6;
- C-04 ← D-05, D-18, D-21 (**all Approved, rev. 8**);
- C-09 ← D-09, D-11, D-24f (D-29 Approved); **rev. 18: D-09, D-11, D-24f, D-20 (audit writes) and the D-24i module names Approved; no SQLAlchemy (NFR-002).**
- C-10 ← D-14, D-19, **D-31 default values** (TTL, capacity) (D-07, D-25, D-27, D-31 Approved); **rev. 16: D-19 failure rule and D-31 defaults Approved (TTL 300 s after the terminal state, 10,000 entries).**
- C-11 ← D-16, D-20 (D-30 Approved: internal entry);
- C-16 ← D-04 (D-12, D-26, D-30, D-31 and FR-022 Approved). **Implementing first and deciding later is not permitted** for these.

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
  - Ruff excludes `SENTINEL_BUILD_BRIEF.md` and `docs/`, because Ruff 0.17 formats Markdown code blocks and would otherwise propose rewriting the brief. *(Rev. 3: `spikes` added to the same `extend-exclude` list under D-28; the file-wide `# ruff: noqa` headers in spike files were removed.)*
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
- **Rev. 3 status: done (2026-10-28).** Report `docs/aidlc/02-construction/spike_framework_interception.md`; 97 checks against stand-ins; E1/E2 passed; Design B recommended. Evidence kept in `spikes/langgraph_interception/`.

### C-02b — LangChain `create_agent`, async-native and `Command` compatibility experiment (isolated, throwaway)
- **Status: done (2026-10-28).** Report `docs/aidlc/02-construction/spike_langchain_compatibility.md`; 120 checks against stand-ins; evidence in `spikes/langchain_compatibility/`. Its findings produced the owner approvals D-12 (expanded), D-14 amendment, D-25, D-26, D-27 and D-28.

### C-03 — Exceptions and core models / contracts
- **Objective:** encode C1 in types.
- **Entry gate (rev. 4):** `decision_record.md` §8.6. *Rev. 4 open list:* D-03, D-04, D-06, D-08, D-14 (remainder), D-15, D-24c, D-24d, D-24i (and D-24b if `ToolGrant` stays here).
- **Rev. 5:** D-03, D-04, D-06, D-08, D-14, D-24c, D-24d are Approved; D-24i is Approved for lowercase values. **Full C-03 remains NOT AUTHORIZED** (owner). Remaining blockers before it can be requested: **Q-03c**; D-24b only if `ToolGrant` stays in C-03. The D-15 remainder affects C-08, not C-03 models. C-03 builds on the C-03a module rather than re-implementing it.
- **Scope (unchanged in intent; exact content fixed by the open decisions):**
  - `exceptions.py` (FR-018; per D-03, D-24d);
  - `models.py`:
    - `Decision` (values per D-24i), `Severity` (per D-24c);
    - `SecurityRequest` (frozen; `SecretStr` per D-04; optional adapter-supplied `tool_call_id`; a `tool_call_id` without a `session_id` is rejected, D-31);
    - `SecurityFinding`. *(Rev. 7: `ToolGrant`, `RateLimit`, `CapabilityEnvelope`, `SecurityContext` moved to C-07 per the owner's `ToolGrant` exclusion.)*
    - `ToolSpec` (metadata only, per D-06, D-08, D-15);
    - `AuthorizedAction` and `SecurityDecision` (D-07, Approved);
    - `PipelineResult` (per D-14, D-03);
  - reason and error-code constants: `INVALID_REQUEST`, `ACTION_MISMATCH`, `DECISION_ALREADY_USED`, `DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED`, `AUDIT_UNAVAILABLE`, `INTERNAL_ERROR`, …
  - **Rev. 6 (Q-03c):**
    - `PipelineResult.decision: Decision | None` (`None` only for internal errors);
    - `Decision` values stay `allow`/`deny`/`require_approval`;
    - a distinct `SentinelError` subclass for internal errors (never `ActionDenied`).

    Acceptance adds **AT-40 (model part), AT-41**.
- **Approved contract C-03 must implement (rev. 4):** C1.4 rule 6 (D-07):
  - canonical JSON (`sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=False`, `allow_nan=False`, UTF-8);
  - SHA-256 over `request_id`, `agent_id`, tool name and canonical arguments (including resolved paths);
  - only JSON-native values accepted;
  - `tool_call_id` excluded.
- **Dependencies:** C-01; C-02 and C-02b reports reviewed (done).
- **Rev. 7 (2026-10-28):**
  - **Owner approval: given** for the C-03 model and exception increment.
  - **`ToolGrant` out of scope** until D-24b is resolved. Exclusion analysis: clean, but it takes `RateLimit`, `CapabilityEnvelope` and `SecurityContext` with it, since they depend on `ToolGrant` and nothing else in C-03 depends on them. These four move to **C-07**.
  - Result semantics now include the owner's operational-refusal table (decision record C1.6 rev. 6). Acceptance adds **AT-44 (model part), AT-46**.
  - **❌ Blocked:** the approved contract requires **Pydantic v2** (C1.3 `arg_schema` as a Pydantic model class; D-08 strict mode; `SecretStr`; brief §2 [DOC]). It is not installed and not declared, adding it is NFR-002 (Proposed), and this task prohibits installs.
  - **Unblocks with:** owner option A (approve `pydantic>=2.14,<3` as a runtime dependency, pin it, authorize installing it into the project `.venv`) or option B (a stdlib-only contract change). See decision record §8.6 rev. 6.
- **Rev. 8 status: implemented (2026-10-28); committed in `153df80`.**
  - Pydantic approved and installed (2.14.1).
  - Code: `src/sentinel/exceptions.py`, `src/sentinel/models.py`; C-03a `ActionEncodingError` re-parented.
  - Tests: `tests/unit/test_models.py`, `tests/unit/test_exceptions.py`.
  - Evidence: `pytest` 137 passed; `ruff check .` clean; `ruff format --check .` clean.
- *Rev. 7:* **Blocked by:** the Pydantic dependency decision and installation (resolved). *(Rev. 6 list: the owner's explicit gate approval, now given; D-24b, now excluded.)*
- *Superseded (rev. 6):* the owner's explicit review and approval of the full implementation gate; D-24b (conditional). *(Rev. 5 list also had Q-03c, resolved in rev. 6.)* *(Rev. 4 list: D-03, D-04, D-06, D-08, D-14 (remainder), D-15, D-24c, D-24d, D-24i.)*
- **Acceptance:**
  - model validation;
  - frozen models reject attribute assignment;
  - `SecretStr` is absent from `repr` and JSON; enum ordering;
  - `tool_call_id` inside `arguments` → `INVALID_REQUEST` (reserved key, subject to the Q-04b outcome);
  - **AT-28** (digest identical across processes and hash seeds), **AT-29** (nested changes alter the digest), **AT-30** (`tool_call_id` excluded), **AT-31** (non-JSON-native values rejected), **AT-36** (`tool_call_id` without `session_id` rejected).
- **Tests:** `unit/test_models.py`, `unit/test_action_digest.py` (including a subprocess-based determinism test), `unit/test_exceptions.py`.
- **Security invariants:** SEC-008 (models); SEC-032 (digest); basis for SEC-010 and SEC-021.
- **Evidence:** pytest and Ruff output (mypy only if D-22 is extended).

### C-03a — Action identity and digest — **AUTHORIZED (rev. 5)**
- **Authorization:** owner, 2026-10-28 ("The owner has authorized a narrow C-03a increment only. Full C-03 remains unauthorized."). Recorded in decision record §12.
- **Scope as authorized (narrower than the rev. 4 proposal):**
  - the frozen action record;
  - canonical action encoding and the stable action digest;
  - tests for encoding, digest stability, nested argument changes and rejection of unsupported values.

  *Rev. 4 also listed reason-code constants; they are **not** in the authorized scope and stay in C-03.*
- **Contracts used:** D-07 (incl. tool identity = registered name), D-25, D-27, D-31 (`tool_call_id` excluded from the digest; its guard role is untouched and lives in C-10).
- **Prohibited (unchanged):** full C-03 models and exceptions, result models, public API changes, credentials, policy, execution, adapters, new dependencies.
- **Implementation (done 2026-10-28):** `src/sentinel/action.py` (stdlib only):
  - `canonical_json`, `action_digest`, the immutable `AuthorizedAction`;
  - an interim `ActionEncodingError(ValueError)`, to be integrated into the exception hierarchy by C-03.
  - It is **internal**: not exported from `sentinel`; `sentinel.__all__` is unchanged.
- **Implementation choices made within the contracts (no new rules):**
  - exact-type checks, so subclasses of the accepted types (e.g. `IntEnum`, `str` subclasses) are rejected;
  - cycles, lone surrogates, integers beyond Python's digit limit and over-deep nesting are rejected as unencodable;
  - identifiers must be non-empty `str` (FR-001);
  - arguments are stored in canonical form and decoded fresh on each read (deep immutability);
  - `repr` omits argument values (SEC-008);
  - error messages never contain the rejected values.
- **Tests:** `tests/unit/test_action.py`, 52 tests covering AT-28, AT-29, AT-30 (model part), AT-31 (model part).
- **Evidence (2026-10-28, project `.venv`, Python 3.11.14):** `pytest`: 55 passed (52 new + 3 scaffold); `ruff check .`: all checks passed; `ruff format --check .`: 5 files already formatted.
- **Status: complete; committed in `153df80`** (together with C-03).
- **Not covered by C-03a:** the gateway mapping of `ActionEncodingError` to `INVALID_REQUEST` (C-06); reserved-key rejection (C-06); `SecurityDecision`, the proxy's digest re-check and replay protection (C-10); the guard (C-10).

### C-04 — Path guard (canonicalisation and pure containment)
- **Objective:** C2 as two functions: `canonicalise(path) -> str` (I/O, used by the gateway and the proxy) and `is_contained(canonical, prefixes) -> bool` (pure, used by policy and the proxy).
- **Scope:** one small module (`paths.py`, or inside `policy.py` if the owner prefers); prefix registration helper (exists, is a directory, `strict` realpath).
- **Dependencies:** C-03. **Blocked by:** D-05, D-18, D-21 — **all Approved (rev. 8)**; C-04 may start.
- **Acceptance:** F1–F20 as specified (F15 strict xfail; F17 limitation test), on macOS locally and Linux in CI.
- **Tests:** `unit/test_path_guard.py`; optional Hypothesis property test (accepted ⇒ contained by component).
- **Security invariants:** SEC-007.
- **Evidence:** pytest output from both OSes.
- **Rev. 8 status: implemented (2026-11-08); Linux and macOS verified in CI (rev. 10).**
  - Code: `src/sentinel/paths.py` (internal, not exported): `canonicalise`, `is_contained`, `register_prefixes` (the prefix registration helper; warns on empty or missing prefixes and on the root prefix), `reverify` (the C2.7 re-resolution used by the proxy in C-10), `require_path_support` (D-21 Windows refusal, used by the registry in C-05).
  - Tests: `tests/unit/test_path_guard.py`, 57 tests (56 pass, F15 strict xfail). The tests were also run against deliberately broken copies of the module (string-prefix containment, relative paths resolved, no re-resolution equality, no warnings, chained `OSError`, no Windows refusal, single string accepted as a prefix list, and others): every mutant fails at least one test.
  - Evidence (macOS, Python 3.11.14, project `.venv`): full suite 193 passed, 1 xfailed; `ruff check .` clean; `ruff format --check .` clean; `pip check` clean.
  - CI: `ubuntu-latest` and `macos-latest` added to the test matrix (D-21). The workflow triggers only on pushes to `main` and on pull requests, so **no CI run exists yet**; Linux evidence remains outstanding.
  - **Rev. 10 update: Linux evidence obtained.** After the trigger fix (`fb4be1b`), GitHub Actions run 42456322322 on that commit passed every job: Ruff (lint and format), and pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13, each "193 passed, 1 xfailed" with no skips.
  - Function-level only (callers come later): F7/F8/F9 raise `InvalidRequestError` (C-06 maps it to `decision=None`, `INVALID_REQUEST`); F14/F16 via `reverify` (proxy wiring and spy counts in C-10); F19 as "contains nothing" plus the warning (policy DENY in C-08). The optional Hypothesis test is not written (Hypothesis not approved, D-22).

### C-05 — Tool registry
- **Scope:** `registry.py`: register (unique; `arg_schema` and `destructive` required; `path_args` ⊆ schema `str` fields; refuses path tools on Windows), lookup of `(ToolSpec, callable)`, read-only spec listing. **Rev. 3:** a registration holds a sync callable, an async callable, or both, and the registry reports which entry points a tool supports.
- **Dependencies:** C-03. **Blocked by:** D-06, D-08, D-21 (all Approved; D-21 in rev. 8).
- **Acceptance:** duplicate, missing-flag, missing-schema and bad-`path_args` registrations raise `RegistrationError`.
- **Tests:** `unit/test_registry.py`. **Invariants:** SEC-014. **Evidence:** pytest output.
- **Rev. 10 status: implemented (2026-11-08).**
  - Code: `src/sentinel/registry.py` (internal, not exported): `ToolRegistry.register(name, *, arg_schema, destructive, path_args=(), sync_fn=None, async_fn=None) -> ToolSpec`, `lookup(name) -> RegisteredTool | None`, `specs()`; `RegisteredTool(spec, sync_fn, async_fn)` reports `supports_sync` / `supports_async`.
  - Rules: unique, non-replaceable names (no replace or remove API; thread-safe check-and-insert); missing `arg_schema` or `destructive` → `RegistrationError` (not a Python `TypeError`); `ToolSpec` validation errors re-raised as a fixed-text `RegistrationError` without chaining; at least one entry point; the sync entry point must not be a coroutine, generator or async-generator function (calling those would not run the tool body); the async entry point must be a coroutine function; a path-constrained tool on Windows → `ConfigurationError` via `paths.require_path_support()` (D-21), while tools without `path_args` register normally; nothing is called at registration.
  - Not in C-05 (by the contracts): allowed path prefixes belong to grants (C-07, blocked by D-24b), so empty-grant and root-prefix behaviour stays covered by the C-04 tests (F19, explicit root); strict validation of request arguments is the gateway (C-06); a signature-vs-schema compatibility check at registration is **not** a documented rule and is not implemented.
  - Tests: `tests/unit/test_registry.py`, 52 tests. Also run against 14 deliberately broken registries: 13 fail at least one test; the survivor (removing the explicit missing-`arg_schema` check) is behaviour-equivalent, because `ToolSpec` rejects the missing value with the same `RegistrationError`.
  - Evidence: local macOS, Python 3.11.14: 245 passed, 1 xfailed; Ruff and format clean; `pip check` clean. Remote CI: see the C-05 commit's run.

### C-06 — Gateway: validation, strict arguments, canonicalisation
- **Objective:** raw dict → frozen `SecurityRequest` plus the `AuthorizedAction` candidate.
- **Scope:** `gateway.py`: shape validation; tool registered; reserved keys; strict `arg_schema` validation (extra forbidden); path arguments validated (C2.3) and canonicalised (C2.4); sanitised error rendering (no input values).
- **Dependencies:** C-03, C-04, C-05. **Blocked by:** D-04 (reserved keys), D-08, D-18. **Rev. 4 acceptance additions:** AT-31 (gateway part: non-JSON-native values → `INVALID_REQUEST`), AT-36 (gateway part).
- **Acceptance:** FR-001, FR-003, FR-004; relative, `~`, NUL and empty paths → `INVALID_REQUEST`; the canonical path appears in the action; the canary from an invalid field is absent from the error.
- **Tests:** `unit/test_gateway.py`. **Invariants:** SEC-008 (validation errors), SEC-013 (reserved keys). **Evidence:** pytest output.
- **Rev. 11 status: implemented (2026-11-08).**
  - Code: `src/sentinel/gateway.py` (internal, not exported): `validate_request(raw, *, registry, request_id, received_at) -> ValidatedRequest(request, action, spec)`. `request_id` and `received_at` are supplied by the caller (the pipeline assigns them before validation, C1.1); every refusal raises `InvalidRequestError`, which the pipeline (C-11) reports as `decision=None`, `INVALID_REQUEST`. The gateway builds no `PipelineResult`, because `audit_complete` is the pipeline's.
  - Rules: `raw` must be a mapping with exactly the FR-001 keys plus optional `auth_token` and `tool_call_id` (unknown keys refused, as by the `SecurityRequest` model); `arguments` must be a `dict`; `auth_token` must be a `str` (the model's lenient `auth_token` would also decode `bytes`); the tool must be registered; arguments validated once with `model_validate(..., strict=True)`; every `path_args` field must be **present** (a tool-side default path would escape every path check) and is replaced by `paths.canonicalise(...)`; the `AuthorizedAction` is built over the caller's validated values (no model dump, so schema defaults are not added and nothing is converted); the `SecurityRequest` (types, non-empty strings, UTC, reserved keys) is built from the same canonical arguments. Pydantic errors are replaced by fixed text and not chained.
  - Not in C-06: containment of canonical paths (C-08), grants and identity (C-07), the guard part of AT-36 (C-10), result and audit mapping (C-11).
  - Spec note for C-16: FR-021 gives `wrap_tools` a `session_id=None` default, while FR-001 and the C-03 `SecurityRequest` require `session_id`; C-06 follows FR-001. The adapter must supply a session id or the contracts must be reconciled at C-16.
  - Tests: `tests/unit/test_gateway.py`, 108 tests. Also run against 15 deliberately broken gateways plus one with the model's reserved-key check removed: every behaviour change fails a test; two survivors are behaviour-equivalent (taking the tool name from `raw` instead of the spec, since lookup is exact; and an early shape check that duplicated the final model build, which was then removed).
  - Evidence: local macOS, Python 3.11.14: 353 passed, 1 xfailed; Ruff and format clean; `pip check` clean. Remote CI: see the C-06 commit's run.

### C-07 — Identity and capability lookup
- **Rev. 7:** also defines the models moved out of C-03: `ToolGrant` (shape per D-24b, which must be Approved first), `RateLimit`, `CapabilityEnvelope`, `SecurityContext`. **Blocked by D-24b** in addition to D-04 and D-05. **Rev. 12: D-24b Approved (tool-level grants); D-04 and D-05 Approved. C-07 may start.** The gaps the contracts leave open are recorded as interpretations I-1 to I-7 under D-24 in the decision record.
- **Scope:** `identity.py`: in-memory agent and envelope repositories; `register_agent` support (hash only); `require_credentials`.
- **Dependencies:** C-03; C-04 (prefix registration helper for grants); C-05 (the registry, used to check grants name registered tools and whether a tool takes paths; interpretation I-1, I-2). **Blocked by:** D-04, D-05 (both Approved), D-24b (Approved, rev. 12).
- **Acceptance:** FR-005–007; grant with a non-existent prefix → `ConfigurationError`; empty prefixes allowed at registration with a warning.
- **Tests:** `unit/test_identity.py`. **Invariants:** identity never decides. **Evidence:** pytest output.
- **Rev. 13 status: implemented (2026-11-08).**
  - Models in `src/sentinel/models.py` (frozen, strict, extra fields refused): `RateLimit{max_calls, window_seconds}` (positive ints), `ToolGrant{tool, allowed_path_prefixes=(), rate_limit=None}`, `CapabilityEnvelope{agent_id, grants=()}` (at most one grant per tool; `grant_for(name)` is an exact-name lookup), `SecurityContext{agent_id, user_id=None, authorized, envelope=None}` (an envelope only when authorized, and only the agent's own).
  - `src/sentinel/identity.py` (internal): `IdentityStore(registry, *, require_credentials=True)` with `register_agent(agent_id, *, credential=None, user_id=None, disabled=False, grants=())` and `authenticate(request) -> SecurityContext`. Applies D-04, FR-006 and interpretations I-1 to I-7 (decision record D-24): SHA-256 digest only, `hmac.compare_digest` on every call (also against a fixed digest), unknown, disabled or unauthenticated → `authorized=False` with no envelope or `user_id`; grants checked against the registry; path prefixes through `paths.register_prefixes`; prefixes on non-path tools refused; rate-limited grants refused until C-15; no replace, remove or read API.
  - Not in C-07: DENY `UNAUTHORIZED_AGENT` / `UNAUTHORIZED_TOOL` / `RESTRICTED_PATH` (policy rows 1–3, C-08); path containment (C-08); rate-limit enforcement (C-15); `SecurityPolicy` (C-08; `require_credentials` is passed in, I-6).
  - Tests: `tests/unit/test_identity.py`, 97 tests. Also run against 26 deliberately broken versions of `identity.py` and the models (credential checks, grant matching, envelope invariants, registration rules). The first run left 2 survivors, both real gaps: a missing-token path that could match a credential equal to the placeholder's input, and unknown agents with `require_credentials=False`. Tests were added; both are now caught.
  - Evidence: local macOS, Python 3.11.14: 450 passed, 1 xfailed; Ruff and format clean; `pip check` clean. Remote CI: see the C-07 commit's run.

### C-08 — Policy engine
- **Scope:** `policy.py`: `SecurityPolicy`; `PolicyEngine.evaluate(request, context, findings, tool_spec)` rows 1–4, 6, 7; pure; embeds the action in the decision.
- **Dependencies:** C-03, C-04 (`is_contained`), C-07. **Blocked by:** D-05, D-06, D-15, D-24a/b/c. *(Rev. 12: D-05, D-06, D-24b, D-24c Approved; still open: D-15 remainder, D-24a.)* **Rev. 14: D-15 (complete) and D-24a Approved; C-08 may start.** Gaps filled by interpretations I-8 to I-11 (decision record, D-24): reason codes `DESTRUCTIVE_TOOL` and `ALLOWED`, the action as a keyword-only input, inconsistent inputs raised (not decided), `risk_score` not computed.
- **Acceptance:** truth table P1–P8 and precedence pairs; determinism (1,000 iterations); evaluation succeeds with file and socket access patched to raise.
- **Tests:** `unit/test_policy.py`. **Invariants:** SEC-001, SEC-012, SEC-019. **Evidence:** pytest output.
- **Rev. 15 status: implemented (2026-11-08).**
  - Code: `src/sentinel/policy.py` (internal): `SecurityPolicy(version, deny_at_severity=HIGH, require_approval_for_destructive=True)` (invalid → `ConfigurationError`; no `require_credentials`, I-6) and `PolicyEngine(policy).evaluate(request, context, findings, tool_spec, *, action) -> SecurityDecision`. Reason constants `DESTRUCTIVE_TOOL` and `ALLOWED` were added to `models.py` (I-8).
  - Behaviour: C1.5 rows 1, 2, 3, 4, 6 and 7 in that order, first match wins. Row 3 checks every `path_args` value with `paths.is_contained` against the grant's prefixes. Row 4 takes the highest severity ≥ `deny_at_severity`, ties broken by the smallest code. `finding_codes` are sorted the same way. The decision embeds the exact action. Inputs that do not belong to one request (types, tool, ids, agent, arguments compared by digest, missing path argument) raise instead of deciding (I-10).
  - Not in C-08: row 5 (rate limits, C-15); `CAPABILITY_EXCEEDED` (no source in v1, I-11); `risk_score` (no formula, I-11); proxy re-verification (C-10); mapping to `PipelineResult` and audit (C-11); detection (C-13; no Tool-Abuse detector, D-15).
  - Tests: `tests/unit/test_policy.py`, 96 tests: truth table P1–P8, every precedence pair, the D-24c tie-break and threshold cases, path cases (prefix directory, sibling prefix, empty and root prefixes, several prefixes and arguments), destructive and approval, finding permutations, binding, input consistency, 1,000-iteration determinism, and evaluation with file, socket, clock, `realpath` and environment access patched to raise.
  - Also run against 25 deliberately broken policy engines plus one broken `grant_for` (grant bypass, order swaps, path bypass, string-prefix paths, threshold, tie-break, approval bypass, input checks). The first run left 3 survivors. One was a real gap (case-insensitive name matching, now tested). Two are behaviour-equivalent (a request-id check and the decision's `request_id` source, both already implied by the digest check).
  - Evidence: local macOS, Python 3.11.14: 546 passed, 1 xfailed; Ruff and format clean; `pip check` clean. Remote CI: see the C-08 commit's run.

### C-09 — Audit store and logger
- **Scope:** `store.py` (`audit_events` table per C4.2, insert and read only, `schema_version` check, WAL + `synchronous=FULL`, default `sentinel_audit.db` resolved at construction); `audit.py` (`AuditLogger.record`, masking, truncation, commit per event, masked `logging` fallback); `reconstruct()` helper implementing C4.4 (also used by tests). **Rev. 3:** failure diagnostics per D-29 (type, module, stage, location; no message text by default); `REQUEST_COMPLETED(execution="unknown")` support; `reconstruct()` handles `unknown`.
- **Dependencies:** C-03. **Blocked by:** D-09, D-11, D-20, D-24f, D-29. **Rev. 18: all Approved (D-20 for audit writes); C-09 may start.** Persistence uses the standard-library `sqlite3` (NFR-002, rev. 16). Interpretations I-18 to I-23 (decision record, D-24) fill the remaining gaps.
- **Acceptance:** a committed row is visible through a second connection on return; no update/delete; masking and truncation; schema-version mismatch → writes refused; default path created at construction (not import) and logged; `:memory:` → warning; 8-thread inserts consistent.
- **Tests:** `unit/test_audit_repository.py`, `unit/test_masking.py`, `integration/test_audit_storage_default.py`, `unit/test_reconstruction.py`.
- **Invariants:** SEC-018, SEC-008 (audit sink), FR-024. **Rev. 3 acceptance:** AT-12 (audit part). **Rev. 4 (D-29 Approved):** structured diagnostics only (type, module, function, line, stage, `request_id`, tool, `error_code`); no message text, traceback text, locals, argument values or absolute paths; no opt-in in v1 → **AT-32, AT-33**. **Evidence:** pytest output.

### C-10 — Tool proxy with output-filter stage
- **Scope:** `proxy.py`: binding checks (ALLOW, matching `request_id`s, digest); proxy re-resolution (C2.7); `entered` flag; invoke `fn(**deepcopy(action.arguments))`; tool-error containment; output-filter stage (pass-through) with fail-closed handling. Returns a `ToolResult`-level outcome the pipeline maps to C1.6.
- **Rev. 3 scope additions:**
  - **atomic single-use claim** shared by sync and async paths (D-25);
  - **`(agent_id, session_id, tool_call_id)` guard** claimed after ALLOW and before EXECUTION_STARTED (D-27, D-31 Approved). **Rev. 4:**
    - in-flight entries never expire; TTL starts at the terminal state;
    - deterministic purge before each claim, with an injectable monotonic clock;
    - **no eviction of unexpired entries**; full → `decision=None`, `GUARD_CAPACITY_EXHAUSTED` (rev. 7; was DENY);
    - default TTL and capacity must be Approved before C-10 starts;
  - **async execution path** awaiting the original coroutine;
  - state machine `claimed → entered → completed | failed | interrupted`;
  - `BaseException` after `entered` → `interrupted`, re-raised;
  - forwarding of `InjectedToolCallId` outside the evaluated action.
- **Dependencies:** C-03, C-04, C-05, C-08. **Blocked by:** D-14 (remainder), D-19 (failure rule), D-31 default values (D-07 and D-31 Approved in rev. 4). **Rev. 16: all Approved (D-14 complete; D-19 failure rule; D-31 defaults); C-10 may start.** Interpretations I-12 to I-17 (decision record, D-24) fill the remaining gaps, the main one being the two-phase `claim` / `execute` split required by the C4.3 event order.
- **Acceptance:** NI-08, NI-09, NI-13; F14, F16; tool error → `failed` with no message; filter error → withheld. **Rev. 3:** NI-16; AT-01, AT-02, AT-03 (including the non-atomic test double that must fail), AT-06, AT-07, AT-22, AT-23, AT-25 (proxy part), AT-26 (capacity fails closed, no eviction), **AT-30 (guard part), AT-35** (rev. 4).
- **Tests:** `unit/test_proxy.py`, `security/test_action_integrity.py`, `integration/test_proxy_filesystem.py`, **`security/test_claim_concurrency.py`, `unit/test_tool_call_guard.py`** (rev. 3).
- **Invariants:** SEC-002, SEC-003, SEC-010, SEC-011, SEC-017, SEC-021, **SEC-024, SEC-025**. **Evidence:** pytest output, including repeated runs of the concurrency tests.
- **Rev. 17 status: implemented (2026-11-08).**
  - Code: `src/sentinel/proxy.py` (internal). `ExecutionProxy(registry, *, output_filter, guard=None)`; `claim(request, decision, context, *, mode="sync"|"async") -> ProxyRun`; `ProxyRun.execute()` / `await ProxyRun.execute_async()` / `abandon()`, with `state` and `outcome`; `ToolCallGuard(*, ttl_seconds=300.0, capacity=10_000, clock=time.monotonic)` with `claim(key)` and `retire(key)`; `ProxyOutcome(error_code, execution, output_released, output, diagnostics)`; `Diagnostics` (D-29 fields); `pass_through_filter`.
  - Order: in `claim`, the registry lookup and entry-point check (`INTERNAL_ERROR`), the binding checks (`ACTION_MISMATCH`), the single-use claim keyed by the action digest (`DECISION_ALREADY_USED`), and the guard claim on `(agent_id, session_id, tool_call_id)` (`DUPLICATE_TOOL_CALL`, `GUARD_CAPACITY_EXHAUSTED`). In `execute`, `paths.reverify` for every registry `path_args` value (`RESTRICTED_PATH`), the `entered` flag, the call with a fresh copy of the action's arguments, tool errors (`TOOL_FAILED`, `failed`), the output filter (`OUTPUT_FILTER_FAILED` with `succeeded`, output withheld, D-19), and guard retirement on every terminal state (completed, failed, interrupted, not started after the claim). A `BaseException` after entry sets `interrupted` and propagates.
  - Tests are in one file, `tests/unit/test_proxy.py`, not the separate files listed above; the content they name (action integrity, claim concurrency, guard, real-filesystem path checks) is covered there.
  - Tests: 89, covering NI-08, NI-09, NI-13, NI-16, F14, F16, AT-01–AT-03, AT-06, AT-07 (proxy part), AT-22, AT-23 (sync), AT-26, AT-35, D-19, interruption and cancellation. They were also run against 36 deliberately broken versions (binding, single use, guard key, expiry, eviction, purge, clock rollback, configuration, path re-check, filter, execution states, interruption, run lifecycle, diagnostics). Results:
    - one real gap closed: no test covered the async path's re-check;
    - one hanging test fixed: the cancellation test could wait forever;
    - three survivors are behaviour-equivalent: the request-id and tool checks are implied by the digest comparison, and the `authorized` check by the model rule that an unauthorized context has no envelope.
  - Evidence: local macOS, Python 3.11.14: 635 passed, 1 xfailed (also with `RuntimeWarning` as an error, so no coroutine is left un-awaited); Ruff and format clean; `pip check` clean. Remote CI: see the C-10 commit's run.
  - Not in C-10: audit events, `PipelineResult` mapping, the worker-thread placement of blocking stages for the async entry (C-11, D-30); real output filtering (C-14); the adapter's use of `tool_call_id` (C-16).

### C-11 — Pipeline orchestration
- **Scope:** `pipeline.py` (sole orchestrator and sole audit writer, C4.3 order, C1.7 behaviour, C1.8 error mapping); `config.py`; `detector.py` stub (`[]`). **Rev. 3:** the async entry (FR-026; name and visibility D-30) with blocking stages in a worker thread; interruption handling (best-effort `REQUEST_COMPLETED(unknown)`, re-raise); no re-invocation of a claimed request (C1.7).
- **Dependencies:** C-06 … C-10. **Blocked by:** D-03, D-16, D-20 (D-30 Approved in rev. 4: the async entry is **internal**, not in any `__all__`; acceptance adds **AT-34**).
- **Acceptance:** E2E-01 … E2E-09 at pipeline level; full §6 fault-injection matrix; NI-01 … NI-15; canary test. **Rev. 3:** NI-17, NI-18; AT-02 (async path), AT-08, AT-09, AT-10, AT-24 (pipeline part), AT-25. **Rev. 6:** NI-05 (revised), NI-19; AT-40, AT-41, AT-43.
- **Tests:** `integration/test_audit_ordering.py`, `integration/test_audit_reconstruction.py`, `security/test_fault_injection.py`, `security/test_invariants.py`, `security/test_secret_canary.py`.
- **Invariants:** SEC-005, SEC-006, SEC-009, SEC-022, SEC-023. **Evidence:** pytest output including the security-suite summary.

### C-12 — Public client, quickstart, README (closes M1)
- **Scope:** `client.py` (`SentinelClient`, `register_tool`, `register_agent`, `evaluate_request`, `audit_events`); `__all__` (no proxy); `examples/quickstart.py`; README (status table, limitations from `decision_record.md` §2/§4.6/§6, decisions link).
- **Dependencies:** C-11. **Blocked by:** D-17, D-24i.
- **Acceptance:** E2E-01 … E2E-09 through `SentinelClient`; the quickstart exits 0 and its subprocess test passes; `__all__` test. **Rev. 4:** AT-34 (no public async entry on `SentinelClient`).
- **Tests:** `e2e/test_client.py`, `e2e/test_quickstart.py`. **Evidence:** pytest, ruff, mypy and coverage outputs; quickstart output.

#### Gate G-M1
C-01 … C-12 complete; NFR-006 coverage met; README accurate; threat model revisited; owner review before M2.

### C-13 — Detection heuristics (M2)
Recursive argument scanning, injection and sensitive-data rules, benign corpus, alert manager. **Blocked by:** D-24e, D-24h, the owner's review of the rule and severity table. **Acceptance:** table-driven tests; measured corpus counts; documented evasion test. **Invariants:** SEC-012, SEC-020.

### C-14 — Output filtering (M3)
Redaction across nested containers; `redact`/`block`; unsupported types withheld. **Blocked by:** D-19 (mode). **Acceptance:** canary redaction and blocking tests.

### C-15 — Rate limits (M4)
Atomic per-agent counters with an injected clock; policy row 5. **Blocked by:** D-20; the cross-agent constraint mechanism (brief §12). **Acceptance:** FR-019 tests.

### C-16 — Framework adapter `wrap_tools`, Design B (M5) — rev. 3
- **Scope:** replacement `StructuredTool`s for:
  - sync function tools;
  - async-native tools (async entry points);
  - `Command` tools whose only injected parameter is `InjectedToolCallId`.
- **Behaviour:**
  - refusal list at wrap time (SEC-029);
  - identity bound by parameter;
  - the hidden `tool_call_id` parameter for the guard;
  - fixed-text in-tool `ToolException`s for non-ALLOW and post-execution failures (D-26);
  - ALLOW return values passed through unchanged (SEC-028);
  - best-effort coverage report (FR-025);
  - framework packages only in an optional extra with the pinned test baseline (NFR-019).
- **Module placement** is settled here (proposal: `integrations/langchain.py`).
- **Callers covered by tests:** LangGraph `ToolNode` (sync and async) and `langchain.agents.create_agent`.
- *Rev. 2 text:* "Design from the C-02 report; identity bound by parameter; async fails closed; `[langgraph]` extra …". "Async fails closed" is superseded by D-12.
- **Blocked by:** D-04 (D-12, D-26, D-30, D-31 and FR-022 Approved).
- **Rev. 4, FR-022 scope (owner-approved, narrowed):** `create_agent` is a MUST **only** for the documented patterns (sync function tools; async-native tools through async entry points; `Command` tools whose only injected parameter is `InjectedToolCallId`), all as tools returned by `wrap_tools`. The docs must not imply support for provider built-in tools, unwrapped tools, middleware-supplied tools or unsupported injected parameters.
- **Acceptance:** FR-021, FR-022, FR-025, SEC-013 (adapter), SEC-016, SEC-025, SEC-026, SEC-028–SEC-031; **AT-04, AT-05, AT-11–AT-21, AT-24 (framework part), AT-27, AT-37, AT-38, AT-39** (rev. 4: AT-37–AT-39 carry the C-17 obligations); **AT-42** (rev. 6: internal-error text distinct from denial); an example agent.
- **Evidence:** pytest output of the `integration_framework` job against the pinned baseline.

### C-17 — LangChain wrapping (M5, COULD) — *folded into C-16 (owner-approved in rev. 4, conditional)*
*Rev. 2 text:* "As C-16 (FR-022)." *Rev. 3:* folded into C-16.

**Rev. 4 condition check.** The owner approved the fold **only if every C-17 acceptance criterion and test obligation remains explicitly represented**.
- At rev. 2, C-17 = "As C-16 (FR-022)".
- C-16's rev. 2 acceptance was "FR-021, SEC-013 (adapter), SEC-016; E1/E2/E4 regression tests; example graph", plus the scope items "identity bound by parameter" and "extra with a tested version range".
- FR-022's rev. 2 acceptance was "As FR-021": "A scripted (offline) graph: allowed spy = 1, denied spy = 0; all invocation APIs covered or fail closed (E2 as a regression test)".

Each obligation, applied to the LangChain (`create_agent`) path, is now explicit in C-16:

| # | C-17 obligation (applied to LangChain / `create_agent`) | Represented in C-16 by | Status |
|---|---|---|---|
| O1 | FR-022 acceptance: scripted offline run, allowed spy = 1, denied spy = 0 | AT-20 (`create_agent` rows), AT-39 | represented |
| O2 | All invocation APIs covered or fail closed (E2 regression) | **AT-38** (`invoke`, `ainvoke`, `stream`, `astream`, `batch`) | represented (new in rev. 4) |
| O3 | SEC-013 (adapter): identity bound, model cannot inject it | **AT-37** | represented (new in rev. 4) |
| O4 | SEC-016 async behaviour | AT-21; AT-38 (sync entry into async-only); AT-20 async rows | represented |
| O5 | E1 regression (denied → original never entered) | AT-20, AT-14 | represented |
| O6 | E4 regression (async path; old numbering) | AT-20 async rows; AT-38 `ainvoke`/`astream` | represented |
| O7 | Example graph | **AT-39** (`create_agent` example) | represented (new in rev. 4) |
| O8 | Identity bound by parameter (design) | C-16 scope ("identity bound by parameter"); AT-37 | represented |
| O9 | Framework extra with a tested version range | C-16 scope (optional extra, pinned baseline including `langchain` 1.4.7); NFR-019 | represented |
| O10 | "Async fails closed" (rev. 2 C-16 scope inherited by C-17) | Superseded by D-12 (owner-approved). Its safety intent, that an async-only tool is never executed via a sync entry, is kept as AT-21 | represented (as superseded intent) |

Condition satisfied; C-17 is retired.

### C-18 — Documentation, packaging, release readiness
README final pass; performance measurement (NFR-011); wheel and fresh-venv smoke test; threat-model and security review. **Blocked by:** D-02 verified; owner approval before any publication. **Acceptance:** every MUST requirement traced to passing tests or completed inspections; open decisions closed or explicitly deferred.

## 4. Dependency graph

```text
G-0 → C-01 → C-02 → C-02b (experiments: done)
                │
                ▼
              C-03 ─┬─► C-04 ─┬─────────────► C-06 (also needs C-05) ─┐
                    ├─► C-05 ─┘                                       │
                    ├─► C-07 (needs C-04) ─► C-08 (needs C-04) ───────┤
                    ├─► C-09 ─────────────────────────────────────────┼─► C-11 ─► C-12 ─► [G-M1]
                    └─► C-10 (needs C-04, C-05, C-08) ────────────────┘
[G-M1] → C-13 | C-14 | C-15 (any order) → C-16 → C-18        (rev. 3: C-02b done; C-17 folded into C-16)
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
| 3 | After the C-02/C-02b review: C-02 and C-02b done; C-03, C-05, C-09, C-10, C-11 and C-16 updated for D-12, D-14 amendment, D-25–D-27 and D-29–D-31; C-17 folded into C-16; AT-01–AT-27 assigned; Ruff `spikes` exclusion noted (D-28). Rev. 2 text is preserved in git (commit `bde7265`) |
| 4 | Final contract gate: C-03 entry gate (not yet authorized) with the open decisions listed; optional C-03a (approved-only subset); D-07, D-29, D-30, D-31 reflected in C-03, C-06, C-09, C-10, C-11, C-12; FR-022 narrowed in C-16; C-17 obligations table (O1–O10) with new AT-37–AT-39 |
| 5 | Owner answers recorded; C-03a authorized (scope narrowed to the owner's list: no reason-code constants) and implemented locally with evidence; C-03 gate updated (full C-03 unauthorized; Q-03c open) |
| 6 | Q-03c resolved (internal errors → `decision=None`, `INTERNAL_ERROR`; not denials): C-03 scope and blockers, C-11 and C-16 acceptance updated. Full C-03 still requires the owner's explicit gate approval. C-03a unchanged |
| 7 | Owner: operational refusals are not policy decisions; C-03 approved with `ToolGrant` excluded (four models moved to C-07); C-03 blocked on the Pydantic runtime dependency (options A/B in decision record §8.6); C-10 guard wording |
| 8 | D-05, D-18, D-21 Approved (decision record rev. 8); C-04 and C-05 gates updated; stale C-01-only and "not committed" status lines corrected (C-03a and C-03 are in `153df80`) |
| 9 | C-04 implemented: `paths.py`, 57 tests; CI matrix adds `macos-latest`; Linux evidence outstanding |
| 10 | C-04 remote CI evidence (run on `fb4be1b`: Ruff and pytest on Linux and macOS × Python 3.11–3.13 all passed); C-05 implemented: `registry.py`, 52 tests |
| 11 | C-06 implemented: `gateway.py`, 108 tests |
| 12 | D-24b Approved; C-07 gate and dependencies updated (C-05 added as a dependency for grant checks); C-08 open blockers narrowed to D-15 remainder and D-24a |
| 13 | C-07 implemented: four models in `models.py`, `identity.py`, 97 tests |
| 14 | D-24a and D-15 Approved, I-1 to I-7 confirmed; C-08 unblocked |
| 15 | C-08 implemented: `policy.py`, 96 tests |
| 16 | D-19 failure rule and D-31 defaults Approved; C-10 unblocked |
| 17 | C-10 implemented: `proxy.py`, 89 tests |
| 18 | NFR-002 (no SQLAlchemy), D-09, D-11, D-20 (audit writes), D-24f and D-24i module names Approved; C-09 unblocked |
