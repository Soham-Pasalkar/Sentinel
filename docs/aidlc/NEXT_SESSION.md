# Sentinel — Project Checkpoint and Resume Note

Checkpoint of 2026-11-18, after the G-M1 owner review and closure (before that: the I-28 async-cancellation remediation of C-11; the C-12 independent review and remediation; first written 2026-11-08, after C-12). This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

> **2026-11-18: development resumed by the owner for the C-12 remediation only.** That work is done (§2a). **Later on 2026-11-18 the owner approved the I-28 remediation decisions and authorized their implementation as C-11 remediation evidence for the G-M1 review** (decision record §12, rev. 16). That work is done (§2b). **The owner then reviewed M1 (decision record §12, rev. 17): every interpretation I-1 to I-35 is now confirmed. G-M1 is CLOSED (2026-11-18, §5)**, after the documentation correction `8300360` passed CI. **C-13 stays blocked even after closure**: it needs D-24e, D-24h and the owner's review of the rule and severity table. No other implementation is authorized.

## 1. Purpose and architecture

Sentinel is an in-process Python library that sits between AI agents and their tools. For every tool call it decides `allow` / `deny` / `require_approval`; a call that is not allowed never executes, and every step is audited.

**What is implemented (M1):** `SentinelClient` (the only public entry point) owns one long-lived pipeline. Each `evaluate_request(raw)` goes through:

1. **gateway** (C-06): shape, registered tool, reserved identity keys, strict schema validation, canonical paths, and the exact `AuthorizedAction` candidate;
2. **identity** (C-07): authentication facts and tool-level grants;
3. **detector**: a stub that finds nothing until C-13;
4. **policy** (C-08): deterministic, default deny, bound to the exact action;
5. **proxy** (C-10): the sole invoker of tools, with binding re-check, single-use decisions, the `tool_call_id` guard, path re-verification and the output-filter stage (a pass-through until C-14).

The pipeline (C-11) is the only audit writer. It commits every C4.3 event to SQLite (C-09) before the next stage runs, and maps outcomes to `PipelineResult` (C1.6). `audit_events` gives bounded, read-only access to the audit (D-17). Everything outside `sentinel.__all__` is internal, including the async pipeline entry (D-30).

**Not implemented:** heuristic detection (C-13), real output filtering (C-14), rate limits (C-15), framework adapters for LangGraph and LangChain (C-16), and release readiness (C-18).

## 2. Increment status and commits

| Increment | Status | Commit |
|---|---|---|
| C-01 scaffold | complete | `8a5a993` |
| C-02, C-02b framework experiments | complete (evidence only) | `2bd5ec4` |
| C-03a action digest; C-03 models and exceptions | complete | `153df80` |
| C-04 path guard | complete | `847c337` |
| C-05 tool registry | complete | `95a11c5` |
| C-06 gateway | complete | `124fb2e` |
| C-07 identity and tool-level grants | complete | `25dad4f` |
| C-08 policy engine | complete | `cc27883` |
| C-09 audit store, logger, reconstruction | complete | `8379e47` |
| C-10 execution proxy and `tool_call_id` guard | complete (narrow fix I-30 in C-11) | `708745d` |
| C-11 pipeline (sync and internal async) | complete; **I-28 async lifecycle remediated 2026-11-18** (§2b) | `625970a` + I-28 remediation commit |
| C-12 public client, quickstart, README | implemented `53955f9`; **independently reviewed and remediated 2026-11-18** (§2a) | `53955f9` + remediation commit |

Decision and documentation commits, in order: `bde7265`, `6c1ef3e`, `f64c8f6`, `fb4be1b`, `0794336`, `7efb7f2`, `deab308`, `65a4550`, `5d6ce77`, `eebfcc4`, `1292974` (the C-12 decisions).

### 2a. C-12 independent review and remediation (2026-11-18)

**Findings:**
- FR-023 was not met: the quickstart showed only allow and an ungranted-tool deny.
- AT-30's guard part had no test: the checkpoint cited `test_guard_key_includes_agent_and_session`, which is the AT-06 test.
- `pyproject.toml` still described the package as having "no security functionality".
- `audit_events` could return a naive timestamp, or raise a bare `TypeError`, for a row altered outside Sentinel's API.
- Required registration keywords showed an `<object object at …>` default.
- No defect was found in the C-01 … C-11 security path.

**Fixed in one commit:**
- the FR-023 quickstart;
- strict validation of audit rows on read (`AuditIntegrityError`);
- the AT-30 guard test;
- eight pipeline fault-path tests;
- the package metadata and the readable placeholder;
- D-22 (coverage.py) with the NFR-006 gate in CI;
- reconciled documentation.

Details: implementation plan rev. 24 (C-12).

### 2b. I-28 async-cancellation remediation of C-11 (2026-11-18)

**Defect (found in the owner's M1 review of I-24 to I-31, then five design-review rounds):** the async entry's clean-up after a cancelled caller ran as event-loop callbacks, which never ran when the loop was torn down. Claimed runs kept their guard entries in flight forever and requests had no REQUEST_COMPLETED; a completion awaited without a shield was lost on cancellation; a finalized pending task could deadlock on the store or guard lock.

**Owner decisions (decision record §12, rev. 16):** K3 (C1.6 amendment: finalization writes nothing and takes no blocking lock), K4 (deferred guard retirement with `queue.SimpleQueue` and `ProxyRun.abandon_deferred()`), K1 and K1b (`INTERNAL_ERROR` mappings), K2 (the record before entry is written by a worker), D-BOUND, D-LOG, C1.6-I, and the new I-28 and I-29 texts.

**Implemented** (`pipeline.py`, `proxy.py`; no dependency, no public API): executor jobs that return values and never raise; a per-request handoff lock deciding who closes a claimed run; the in-step check for finalization; deferred guard retirement. 149 new tests, including subprocess finalization tests and a seeded stress test; mutation checks in testing strategy §16. Details: implementation plan rev. 25.

## 3. Repository state (verified 2026-11-08; updated 2026-11-18)

- **Current (2026-11-18, G-M1 review):** before this documentation correction, HEAD was `5072f20bd5144b8a616d074f5840340bb35ae803` (the I-28 CI record), clean and in sync with the remote, with CI run 44289005189 green on it. The correction is `8300360` (CI run [44291157573](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/44291157573) on exactly `83003601ab625d5e686c3aff3a465cebeeb206b6`, green); the G-M1 closure record is committed on top of it. Both hold documentation only.

*The bullets below are earlier checkpoints, kept as history; each names the HEAD at its own date.*

- **2026-11-18 (I-28 remediation):** before it, HEAD was `4946b027c137d60e4823215eee102301c394a3b5`, clean and in sync with the remote; the remediation commit is `0499de9` (CI in §4), followed by a documentation commit recording its CI run.
- **2026-11-18:** before the remediation, HEAD was `2c37035c6dab7b23ca5c5e0173ff2b18285c85ed` (this note's earlier version), local and remote matched, and the working tree was clean. The remediation commit sits on top; see §4 for its CI run.

- *2026-11-08 (historical):* **Branch:** `c01-project-scaffold`. **HEAD then:** `53955f9a47b3e6425fe55c2edb908e0aa3e1bfd4` (C-12), with the C-12 decision commit `1292974` directly below it. That checkpoint note was committed on top as documentation only.
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold`; local and remote matched at `53955f9` before this checkpoint commit.
  - The repository is **public**.
  - GitHub made `c01-project-scaffold` the **default branch** (the repository was empty at the first push).
  - No `main` branch exists; nothing has been merged; no release has been made.

## 4. Test evidence

**G-M1 documentation correction (2026-11-18):** CI run [44291157573](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/44291157573) on exactly `83003601ab625d5e686c3aff3a465cebeeb206b6` (push event): all 7 jobs succeeded; Ruff passed (49 files); **1,207 passed, 1 xfailed** in each of the six test jobs (ubuntu and macOS × Python 3.11, 3.12, 3.13). This is the closure evidence for G-M1.

**I-28 remediation (2026-11-18), local (macOS, Python 3.11.14, project `.venv`):**
- 1,207 passed, 1 xfailed (also with `RuntimeWarning` as an error); Ruff and format clean; `pip check` clean.
- Branch coverage: `pipeline.py` 124/132 (93.94%), `proxy.py` 105/110 (95.45%), overall 640/660 (96.97%); NFR-006 check passed. The subprocess finalization tests are not measured by coverage.py.
- **CI for the remediation commit `0499de974d4019d79fa1bd2d157563c9b64efbc0`:** run [44288674120](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/44288674120) (push event) tested exactly that SHA. All 7 jobs succeeded:
  - Ruff: lint passed; format check passed (49 files).
  - pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13: **1,207 passed, 1 xfailed** in each job; the six subprocess finalization tests ran and passed in every job (first execution of this design on 3.12 and 3.13).
  - The NFR-006 gate passed in each job with the same figures as locally (`pipeline.py` 124/132, `proxy.py` 105/110, overall 640/660 = 96.97%).

**C-12 remediation (2026-11-18), local (macOS, Python 3.11.14, project `.venv`):**
- 1,058 passed, 1 xfailed (also with `RuntimeWarning` as an error); Ruff and format clean; `pip check` clean.
- Branch coverage (coverage.py 7.17.3):

  | Module | Branch coverage |
  |---|---|
  | `policy.py` | 34/34 (100%) |
  | `proxy.py` | 89/94 (94.68%) |
  | `pipeline.py` | 76/82 (92.68%) |
  | `paths.py` | 28/28 (100%) |
  | `audit.py` | 121/126 (96.03%) |
  | `store.py` | 53/54 (98.15%) |
  | **Overall** | **576/594 (96.97%)** |

- **CI for the remediation commit `4e00c39fa843389ac93e3f358d95c1e08411b079`:** run [44256518479](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/44256518479) (push event) tested exactly that SHA. All 7 jobs succeeded:
  - Ruff: lint passed; format check passed (45 files).
  - pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13: **1,058 passed, 1 xfailed** in each job.
  - The NFR-006 gate passed in each job with the same figures as locally (overall 576/594 = 96.97%; every guarded file ≥ 90%).

**Checkpoint commit `2c37035`:** CI run [42477135779](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/42477135779) tested exactly that SHA. Ruff passed, and all six pytest jobs passed with 991 passed, 1 xfailed each. *(The 2026-11-08 text below said the checkpoint push did not wait for CI; a run did happen.)*

**C-12 CI run:** [42475826810](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/42475826810), on exactly `53955f9a47b3e6425fe55c2edb908e0aa3e1bfd4` (push event). Every job succeeded:
- Ruff: lint passed; format check passed (42 files).
- pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13: **991 passed, 1 xfailed** in each of the six jobs.

**Local (macOS, Python 3.11.14, project `.venv`):** 991 passed, 1 xfailed (also with `RuntimeWarning` as an error); Ruff and format clean; `pip check` clean. The xfail is F15, the documented path race (`xfail(strict=True)`).

**Per file (historical: the 991-test suite at the C-12 commit `53955f9`, 2026-11-08; not updated since. The current suite is 1,207 tests, see the I-28 remediation evidence above):**

| Area | Files and tests |
|---|---|
| Unit | action 52, models 70, exceptions 12, scaffold 3, path guard 57, registry 52, gateway 108, identity 97, policy 96, proxy 89, audit repository 71, masking 66, reconstruction 39, pipeline config 17 |
| Integration | audit storage default 7, audit ordering 22, audit reconstruction 10, async pipeline 13 |
| Security | fault injection 29, invariants 23, secret canary 2 |
| End to end | client 55, quickstart 2 |

**Earlier CI runs** (every job green):

| Run | Commit | Increment | Result per job |
|---|---|---|---|
| 42456322322 | `fb4be1b` | through C-04 | 193 passed, 1 xfailed |
| 42456612529 | `95a11c5` | C-05 | 245 passed, 1 xfailed |
| 42457691978 | `124fb2e` | C-06 | 353 passed, 1 xfailed |
| 42461535297 | `25dad4f` | C-07 | 450 passed, 1 xfailed |
| 42463102989 | `cc27883` | C-08 | 546 passed, 1 xfailed |
| 42465473430 | `708745d` | C-10 | 635 passed, 1 xfailed |
| 42467083583 | `8379e47` | C-09 | 817 passed, 1 xfailed |
| 42469205994 | `625970a` | C-11 | 933 passed, 1 xfailed |

**Mutation checks** (deliberately broken copies; details in the implementation plan, per increment): every behaviour change was caught after the gaps found were closed. The remaining survivors are behaviour-equivalent.

*2026-11-08:* "Not available: mypy (NFR-005) and coverage (NFR-006) output." **2026-11-18:** coverage is approved (D-22, coverage.py only) and measured; mypy is still not approved (NFR-005).

## 5. Gate G-M1: CLOSED (2026-11-18)

Closed by the owner's approval (decision record §12, rev. 17: "After the documentation corrections and successful CI verification, I approve closing G-M1."), effective once CI run [44291157573](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/44291157573) on exactly `83003601ab625d5e686c3aff3a465cebeeb206b6` passed. Closing G-M1 does not authorize C-13.


| G-M1 item (implementation plan) | State (2026-11-18) |
|---|---|
| C-01 … C-12 complete | ✅ C-12 independently reviewed; FR-023 fixed. C-11 async lifecycle remediated (I-28, §2b), as evidence for the owner's review |
| NFR-006 coverage met | ✅ enforced in every CI test job; latest: run 44288674120 on `0499de9` (`pipeline.py` 93.94%, `proxy.py` 95.45%, overall 96.97%); earlier run 44256518479 on `4e00c39` |
| README accurate | ✅ (updated in the C-12 remediation; interpretation status corrected in the G-M1 review, 2026-11-18) |
| Threat model revisited | ✅ (rev. 12; T-19 and T-21 updated in rev. 14) |
| Owner review before M2 | ✅ **done 2026-11-18** (decision record §12, rev. 17): I-24 to I-27 and I-30 to I-35 confirmed; I-28 and I-29 Approved (rev. 16). G-M1 closed 2026-11-18 after CI run 44291157573 on `8300360` |

mypy is not a G-M1 item (NFR-005 is a SHOULD and not in the gate); it stays unapproved.

## 6. Decisions

**Approved:**
- D-01, D-02 (provisional names), D-03, D-04, D-05, D-06, D-07, D-08, D-09, D-11, D-12;
- D-13, D-14, D-15 (complete), D-16, D-17, D-18, D-20 (audit writes and pipeline), D-21, D-23;
- D-24a, D-24b, D-24c, D-24d, D-24f, D-24i (complete), D-25 … D-31 (with the D-31 defaults);
- D-19 failure rule; Q-03c; the operational-refusal table; FR-022;
- NFR-002 (Pydantic only; no SQLAlchemy).

**Partly approved:** D-22 (pytest, Ruff, Hatchling; **coverage.py added 2026-11-18**; mypy, pytest-cov and Hypothesis not approved). **Approved 2026-11-18:** the NFR-006 thresholds (each guarded file ≥ 90% branch coverage; overall ≥ 85%).

**Open, with what each blocks:**

| Decision | Blocks |
|---|---|
| D-22 remainder (mypy, Hypothesis; pytest-cov not needed) | NFR-005; property tests (not G-M1) |
| D-24e (detector interface, recursive scan, detector failure), D-24h (advisory wording), owner review of the rule and severity table | C-13 |
| D-19 M3 mode (recorded: default `redact`; unsupported types withheld in `enforce`) | C-14 |
| D-20 rate-limit part; cross-agent constraint mechanism | C-15 |
| FR-021 `session_id=None` vs the required `session_id` (spec tension to reconcile) | C-16 |
| D-10 (out-of-scope extras), D-24g (limitations wording), D-02 name verification | later documentation, C-18 |

**Interpretations** (decision record, under D-24):
- I-1 to I-23: confirmed by the owner.
- *Earlier on 2026-11-18 (rev. 15, historical):* the owner was asked about I-24 to I-35 and chose to keep all of them pending. A resumption handover had claimed I-24 to I-31 were confirmed during the C-11 review; §12 had no such record.
- **2026-11-18 (rev. 16): I-28 and I-29 replaced and Approved by the owner** with the I-28 remediation decisions.
- **2026-11-18 (rev. 17, G-M1 review): I-24 to I-27, I-30 and I-31 (C-11) confirmed** (I-27, I-30 and I-31 with clarifications).
- **2026-11-18 (rev. 17): I-32 to I-35 (C-12) confirmed** (I-34 with a clarification):
  - **I-32:** a non-mapping `raw` raises `TypeError`, unaudited;
  - **I-33:** the public export set;
  - **I-34:** `audit_events` validation, first-`limit` semantics, the `AuditEvent` shape;
  - **I-35:** the client lifecycle.

## 7. Next task when work resumes

*2026-11-08 list (items 1 and 3's coverage part done 2026-11-18):* independent review of C-12; D-22; close G-M1.

1. ~~Owner review of M1~~: **done 2026-11-18** (decision record §12, rev. 17). **G-M1 closed 2026-11-18** (§5).
2. Only then: **C-13**, which also needs D-24e, D-24h and the owner's review of the rule and severity table.

**C-13 must not begin until G-M1 is closed and the owner has decided D-24e and D-24h and reviewed the rule and severity table.** Closing G-M1 does not authorize C-13.

## 8. Security constraints not to forget

- `decision` holds only an actual policy decision. Operational refusals and `INTERNAL_ERROR` carry `decision=None`; a reached decision is kept when an audit write fails (I-24).
- `RESTRICTED_PATH` is a policy DENY when the path is outside a grant, and a `decision=None` refusal when the path changed before invocation (C2.7).
- Paths are absolute-only, never expanded or resolved against the working directory; containment is component-wise; `"/"` is the only form of unrestricted access.
- The action digest excludes `tool_call_id`. Decisions are single-use (D-25). The `tool_call_id` guard is keyed by `(agent_id, session_id, tool_call_id)`, uses a TTL of 300 s from the terminal state, never expires in-flight entries, never evicts, and fails closed (D-27, D-31).
- Each audit event is committed before the next stage; the tool runs only after EXECUTION_STARTED is committed; the pipeline is the only audit writer (D-16).
- No input values or exception text in errors, logs or the audit (SEC-008, D-29). The async entry is internal (D-30).
- No dependency installs, merges into `main`, branch renames or history rewrites without explicit owner approval.

## 9. Known security limitations

- **Partial protection.** No detection (C-13), no real output filtering (C-14), no rate limits (C-15), no framework adapters (C-16).
- **In-process boundary.** Only calls routed through `SentinelClient` are controlled. Code in the same process can call tools directly, forge decisions or patch Sentinel.
- **Granted tools are trusted with their validated arguments** (whole-tool grants, D-24b; T-02).
- **Paths are authorized, not isolated:**
  - the race window after the final re-check (F15);
  - hard links (F17), paths a tool derives internally, and mount boundaries;
  - a difference in case fails closed;
  - path-constrained tools are refused on Windows.
- **Audit:**
  - append-only through Sentinel's API only; not tamper-proof (no hash-chaining in v1);
  - masking is heuristic;
  - durability depends on `fsync`; one process per database file; no migrations;
  - `:memory:` never releases output;
  - `audit_events` is not an access-control boundary for the file, and has no pagination (it returns the first ≤ 1,000 events).
- **Guards are process-local.** Single-use claims grow with executed requests. A `tool_call_id` repeat more than 300 s after the first call finished counts as new.
- **No exactly-once external side effects.** If a later step fails, the side effect is not undone; the result says so.
- **Credentials:** plain SHA-256 digests, which suit high-entropy tokens, not passwords. The constant-time comparison is best effort.
- **Async (I-28, rev. 16):** a sync tool reached through the internal async entry runs in a thread that cannot be cancelled; its job still audits it after the caller leaves. The C1.6 record after entry is the only SQLite write on the event loop; it is bounded in attempts, not in time (D-BOUND), and its failure warning may block on application logging handlers (D-LOG). A finalized request writes nothing and reads as unknown; a task never finalized while its loop is abandoned keeps its run claimed and its guard entry in flight.

## 10. Known documentation discrepancies

**Resolved 2026-11-18** (testing strategy rev. 15):
- AT-24 is marked from the inspected test (pipeline part PASS; framework part C-16).
- AT-30's guard part now has its own test (`test_at30_distinct_call_ids_in_one_session_execute_independently`).
- AT-34's C-12 part is PASS (adapter part C-16).
- The stale "Remote CI … through C-04" wording is corrected.
- The plan's mypy item does not apply (mypy not approved; not a gate item).

*2026-11-08 text, kept as history:*

- `testing_strategy.md` §15 still marks **AT-24** (pipeline part) and **AT-30** (guard part) as `PROD-TODO`. They are covered by `test_many_concurrent_requests_stay_consistent` (C-11) and `test_guard_key_includes_agent_and_session` (C-10). The other 20 `PROD-TODO` rows belong to C-16 or C-18, which is correct.
- The implementation plan's C-12 evidence list names mypy and coverage output, which cannot be produced until D-22 is decided (see §5).

## 11. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3     # expect the remediation commits on top of 2c37035
git fetch origin && git status -sb              # local and remote should match
source .venv/bin/activate                       # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                          # expect 1,058 passed, 1 xfailed
coverage run -m pytest && coverage json -q && python scripts/check_coverage.py coverage.json
python examples/quickstart.py                   # five scenarios with audit rows; calls: add=1, others 0
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI for the branch
```
