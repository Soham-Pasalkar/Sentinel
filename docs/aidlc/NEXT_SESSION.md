# Sentinel — Project Checkpoint and Resume Note

Checkpoint of 2026-11-08, after C-12. This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

> **Development is PAUSED by the owner. No implementation work is authorized during this pause.**
> When work resumes, the exact next task is the **independent review of C-12 and the closure of gate G-M1**. **C-13 must not begin until M1 has been reviewed and its gate is satisfied.**

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
| C-11 pipeline (sync and internal async) | complete | `625970a` |
| C-12 public client, quickstart, README | **implemented; independent review pending** | `53955f9` |

Decision and documentation commits, in order: `bde7265`, `6c1ef3e`, `f64c8f6`, `fb4be1b`, `0794336`, `7efb7f2`, `deab308`, `65a4550`, `5d6ce77`, `eebfcc4`, `1292974` (the C-12 decisions).

## 3. Repository state (verified 2026-11-08)

- **Branch:** `c01-project-scaffold`. **HEAD:** `53955f9a47b3e6425fe55c2edb908e0aa3e1bfd4` (C-12), with the C-12 decision commit `1292974` directly below it. This checkpoint note is committed on top as documentation only.
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold`; local and remote matched at `53955f9` before this checkpoint commit.
  - The repository is **public**.
  - GitHub made `c01-project-scaffold` the **default branch** (the repository was empty at the first push).
  - No `main` branch exists; nothing has been merged; no release has been made.

## 4. Test evidence

**C-12 CI run:** [42475826810](https://github.com/Soham-Pasalkar/Sentinel/actions/runs/42475826810), on exactly `53955f9a47b3e6425fe55c2edb908e0aa3e1bfd4` (push event). Every job succeeded:
- Ruff: lint passed; format check passed (42 files).
- pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13: **991 passed, 1 xfailed** in each of the six jobs.

**Local (macOS, Python 3.11.14, project `.venv`):** 991 passed, 1 xfailed (also with `RuntimeWarning` as an error); Ruff and format clean; `pip check` clean. The xfail is F15, the documented path race (`xfail(strict=True)`).

**Per file:**

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

**Not available:** mypy (NFR-005) and coverage (NFR-006) output. Neither tool is an approved development dependency (D-22 remainder).

## 5. Gate G-M1: NOT CLOSED

| G-M1 item (implementation plan) | State |
|---|---|
| C-01 … C-12 complete | implemented ✅ (C-12 independent review pending) |
| NFR-006 coverage met | ❌ **cannot be measured**: pytest-cov is not approved (D-22) |
| README accurate | ✅ (rewritten in C-12) |
| Threat model revisited | ✅ (rev. 12) |
| Owner review before M2 | ❌ pending |

The C-12 evidence list in the plan also names mypy and coverage output, which have the same dependency on D-22.

## 6. Decisions

**Approved:**
- D-01, D-02 (provisional names), D-03, D-04, D-05, D-06, D-07, D-08, D-09, D-11, D-12;
- D-13, D-14, D-15 (complete), D-16, D-17, D-18, D-20 (audit writes and pipeline), D-21, D-23;
- D-24a, D-24b, D-24c, D-24d, D-24f, D-24i (complete), D-25 … D-31 (with the D-31 defaults);
- D-19 failure rule; Q-03c; the operational-refusal table; FR-022;
- NFR-002 (Pydantic only; no SQLAlchemy).

**Partly approved:** D-22 (pytest, Ruff, Hatchling only).

**Open, with what each blocks:**

| Decision | Blocks |
|---|---|
| **D-22 remainder** (mypy, pytest-cov, Hypothesis) | **G-M1** (NFR-006 coverage); NFR-005; property tests |
| D-24e (detector interface, recursive scan, detector failure), D-24h (advisory wording), owner review of the rule and severity table | C-13 |
| D-19 M3 mode (recorded: default `redact`; unsupported types withheld in `enforce`) | C-14 |
| D-20 rate-limit part; cross-agent constraint mechanism | C-15 |
| FR-021 `session_id=None` vs the required `session_id` (spec tension to reconcile) | C-16 |
| D-10 (out-of-scope extras), D-24g (limitations wording), D-02 name verification | later documentation, C-18 |

**Interpretations** (decision record, under D-24):
- I-1 to I-23: confirmed by the owner.
- **I-24 to I-31 (C-11): pending owner confirmation.**
- **I-32 to I-35 (C-12): pending owner confirmation:**
  - **I-32:** a non-mapping `raw` raises `TypeError`, unaudited;
  - **I-33:** the public export set;
  - **I-34:** `audit_events` validation, first-`limit` semantics, the `AuditEvent` shape;
  - **I-35:** the client lifecycle.

## 7. Next task when work resumes

1. **Independent review of C-12** (commit `53955f9`, with `1292974`): the public API, `sentinel.__all__`, the audit read bounds, the quickstart and the README.
2. **Owner decisions:** D-22 (at least pytest-cov, for NFR-006); confirmation or amendment of I-24 to I-35.
3. **Close G-M1:** measure coverage once D-22 allows it, and complete the owner review of M1.

**C-13 must not begin until M1 has been reviewed and G-M1 is satisfied.** No implementation work is authorized during the pause.

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
- **Async:** a sync tool reached through the internal async entry runs in a thread that cannot be cancelled. The interruption record runs briefly on the event loop, as C1.6 prescribes.

## 10. Known documentation discrepancies (for the review; not fixed during the pause)

- `testing_strategy.md` §15 still marks **AT-24** (pipeline part) and **AT-30** (guard part) as `PROD-TODO`. They are covered by `test_many_concurrent_requests_stay_consistent` (C-11) and `test_guard_key_includes_agent_and_session` (C-10). The other 20 `PROD-TODO` rows belong to C-16 or C-18, which is correct.
- The implementation plan's C-12 evidence list names mypy and coverage output, which cannot be produced until D-22 is decided (see §5).

## 11. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3     # expect this checkpoint commit on top of 53955f9
git fetch origin && git status -sb              # local and remote should match
source .venv/bin/activate                       # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                          # expect 991 passed, 1 xfailed
python examples/quickstart.py                   # three lines: allow, deny, audit trail
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI for the branch
```
