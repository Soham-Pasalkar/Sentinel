# Sentinel — Next-Session Resume Note

Updated 2026-11-08 after C-04 (housekeeping commit). This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

## 1. Purpose and architecture (brief)

Sentinel is a planned in-process Python library that sits between AI agents and their tools. For every tool call it decides `allow` / `deny` / `require_approval`. A call that is not allowed must never execute, and every decision is to be audited.

Planned pipeline (decision record C1–C4): gateway → identity and grants → heuristic detection → deterministic policy → proxy (the sole executor) → output filtering. The pipeline is the sole audit writer. Framework integration is Design B, `wrap_tools` (D-12).

**What exists today is the contract layer plus the path guard. No runtime enforcement exists yet:** no gateway, policy, proxy, audit store, pipeline, client API or adapter calls any of it. Sentinel protects no tool call today. The only public attribute is `sentinel.__version__`.

## 2. Completed increments

| Increment | What | Commit |
|---|---|---|
| C-01 | Scaffold (Hatchling, pytest, Ruff, CI workflow) | `8a5a993` |
| C-02, C-02b | Throwaway framework experiments (stand-ins, isolated venvs) | `2bd5ec4` |
| C-03a, C-03 | Action digest (`action.py`); exceptions and strict Pydantic models | `153df80` |
| Docs | D-07 … D-31, Q-03c, refusal semantics | `6c1ef3e` |
| Decisions | **D-05, D-18, D-21 approved**; specs aligned | `f64c8f6` |
| C-04 | Path guard [`src/sentinel/paths.py`](../../src/sentinel/paths.py) (internal); 57 tests; CI adds `macos-latest` | `847c337` |

## 3. Repository state (verified 2026-11-08)

- **Branch:** `c01-project-scaffold`. Last code commit `847c337` (C-04); this note and the CI trigger fix are in the housekeeping commit on top of it (see `git log`).
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold` (pushed with owner authorization; local and remote agreed at `847c337` before the housekeeping commit).
  - The repository is **public**.
  - Because the repository was empty, GitHub made `c01-project-scaffold` the **default branch**.
  - No `main` exists on the remote or locally; nothing was merged.
- **Waiting on:** an independent review of the pushed code is pending, arranged by the owner.

## 4. Tests and quality checks (macOS, Python 3.11.14, project `.venv`)

| Command | Result |
|---|---|
| `pytest` | **193 passed, 1 xfailed** (F15, strict). Per file: action 52, models 70, exceptions 12, scaffold 3, path guard 57 |
| `ruff check .` / `ruff format --check .` | clean / 11 files formatted |
| `python -m pip check` | no broken requirements |

- **Mutation checks:** the path-guard tests were run against 16 deliberately broken copies of `paths.py`, and every copy failed at least one test.
- **GitHub Actions: pending.** Until the housekeeping commit, the workflow triggered only on pushes to `main` and on pull requests, so no run exists for `847c337`. The workflow now also triggers on pushes to `c01-project-scaffold`; the first run (Ruff; pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13) is the first remote evidence. Check it with `gh run list` before relying on Linux results.

## 5. Decisions

**Approved:** D-01, D-02 (provisional), D-03, D-04, D-05, D-06, D-07, D-08, D-12, D-13, D-14, D-18, D-21, D-22 (pytest, Ruff, Hatchling), D-23, D-24c, D-24d, D-25 … D-31 (D-31 default values still open), FR-022, Q-03c, the operational-refusal table, and NFR-002 (Pydantic part).

**Partly approved:** D-15 (remainder open), D-24i (names open).

**Unresolved, with what each blocks:**

| Decision | Blocks |
|---|---|
| **D-24b** (grant granularity) | C-07, and therefore C-08, C-10, C-11 and later |
| **NFR-002 SQLAlchemy part** | C-09 |
| D-09, D-11, D-20, D-24f, D-24i names | C-09 (D-20 also C-11; names also C-12) |
| D-15 remainder, D-24a | C-08 |
| D-19 failure rule, D-31 default TTL and capacity | C-10 |
| D-16 / D-17 | C-11 / C-12 |
| D-10, D-24e, D-24g, D-24h, D-02 verification | later increments or release |

## 6. Next increment: C-05, tool registry (entry criteria met)

- **Gate:** C-05 depends on C-03 (done) and is blocked by D-06, D-08 and D-21, all now Approved. After C-05, **C-06 (gateway)** is also unblocked: it needs C-03, C-04 and C-05, plus D-04, D-08 and D-18, all Approved.
- **Scope:** `registry.py`.
  - Register a tool: the name is unique and not replaceable, and `arg_schema` and `destructive` are required. A registration may hold a sync callable, an async callable, or both.
  - Validate `path_args` (already checked by `ToolSpec`).
  - Refuse path-constrained tools on Windows via `paths.require_path_support()`.
  - Look up `(ToolSpec, callable)`; list specs read-only.
- **Acceptance:** duplicate, missing-flag, missing-schema and bad `path_args` registrations raise `RegistrationError`. `ToolSpec`'s Pydantic `ValidationError` must be converted without echoing input values. Invariant SEC-014. Tests in `tests/unit/test_registry.py`.

## 7. Security constraints not to forget

- `decision` holds only an actual policy decision.
  - Operational refusals and `INTERNAL_ERROR` carry `decision=None`.
  - `RESTRICTED_PATH` is a policy DENY when the path is outside a grant (including empty grants, D-05), and a `decision=None` refusal when the path changed before invocation (C2.7).
- Paths are absolute-only and never expanded or resolved against the working directory. Containment is component-wise. The root prefix `"/"` is the only form of unrestricted access.
- The digest excludes `tool_call_id`. Decision claims are atomic and single-use (D-25). The duplicate-call guard fails closed and never evicts (D-27, D-31).
- No input values in errors, logs or the audit (SEC-008, D-29). The async entry is internal (D-30).
- No dependency installs, merges into `main`, branch renames or history rewrites without explicit owner approval.

## 8. Known limitations and gaps

- **No enforcement yet.** The path guard has no callers.
- **Function level only so far:**
  - F7–F9 at the gateway (C-06);
  - F14 and F16 at the proxy, with spy counts (C-10);
  - F19 as a policy DENY (C-08).
- **Path guard limits** (documented, not defended): the window after `reverify` (F15, strict xfail); hard links (F17); paths a tool derives internally; case differences, which fail closed; mount boundaries. It is not a sandbox.
- **Not yet in place:**
  - remote CI evidence pending (see §4); Linux unverified until then;
  - no mypy, coverage or Hypothesis (D-22 remainder).
- **Doc housekeeping still open:**
  - §15 of `testing_strategy.md` still shows PROD-TODO for the C-03 model parts of AT-36, AT-40, AT-41, AT-44 and AT-46. Trace each to a named test before marking it.
  - The `threat_model.md` header is at rev. 6 (its content needed no change for D-05, D-18 or D-21).

## 9. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3    # expect HEAD 847c337
git fetch origin && git status -sb             # compare with the remote branch
source .venv/bin/activate                      # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                         # expect 193 passed, 1 xfailed
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI result for the branch
```

