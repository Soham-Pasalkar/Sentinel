# Sentinel — Next-Session Resume Note

Updated 2026-11-08 after C-07. This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

## 1. Purpose and architecture (brief)

Sentinel is a planned in-process Python library that sits between AI agents and their tools. For every tool call it decides `allow` / `deny` / `require_approval`. A call that is not allowed must never execute, and every decision is to be audited.

Planned pipeline (decision record C1–C4): gateway → identity and grants → heuristic detection → deterministic policy → proxy (the sole executor) → output filtering. The pipeline is the sole audit writer. Framework integration is Design B, `wrap_tools` (D-12).

**What exists today is the contract layer, the path guard, the tool registry, the request gateway and identity with tool-level grants. No runtime enforcement exists yet:** no policy, proxy, audit store, pipeline, client API or adapter exists to use them. Sentinel protects no tool call today. The only public attribute is `sentinel.__version__`.

## 2. Completed increments

| Increment | What | Commit |
|---|---|---|
| C-01 | Scaffold (Hatchling, pytest, Ruff, CI workflow) | `8a5a993` |
| C-02, C-02b | Throwaway framework experiments (stand-ins, isolated venvs) | `2bd5ec4` |
| C-03a, C-03 | Action digest (`action.py`); exceptions and strict Pydantic models | `153df80` |
| Docs | D-07 … D-31, Q-03c, refusal semantics | `6c1ef3e` |
| Decisions | **D-05, D-18, D-21 approved**; specs aligned | `f64c8f6` |
| C-04 | Path guard [`src/sentinel/paths.py`](../../src/sentinel/paths.py) (internal); 57 tests; CI adds `macos-latest` | `847c337` |
| Housekeeping | CI also triggers on pushes to `c01-project-scaffold`; this note committed | `fb4be1b` |
| C-05 | Tool registry [`src/sentinel/registry.py`](../../src/sentinel/registry.py) (internal); 52 tests | `95a11c5` |
| Housekeeping | This note: C-05 CI recorded | `0794336` |
| C-06 | Gateway [`src/sentinel/gateway.py`](../../src/sentinel/gateway.py) (internal); 108 tests | `124fb2e` |
| Decisions | **D-24b approved** (tool-level grants); C-07 interpretations I-1–I-7 | `7efb7f2` |
| C-07 | Identity and grants [`src/sentinel/identity.py`](../../src/sentinel/identity.py), four models in `models.py`; 97 tests | the C-07 commit after `7efb7f2` (see `git log`) |

## 3. Repository state (verified 2026-11-08)

- **Branch:** `c01-project-scaffold`. HEAD is the C-07 commit on top of `7efb7f2` (see `git log -3`); compare with the remote before starting.
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold` (pushed with owner authorization; compare with `git fetch origin && git status -sb`).
  - The repository is **public**.
  - Because the repository was empty, GitHub made `c01-project-scaffold` the **default branch**.
  - No `main` exists on the remote or locally; nothing was merged.
- **Waiting on:** an independent review of the pushed code is pending, arranged by the owner.

## 4. Tests and quality checks (macOS, Python 3.11.14, project `.venv`)

| Command | Result |
|---|---|
| `pytest` | **450 passed, 1 xfailed** (F15, strict). Per file: action 52, models 70, exceptions 12, scaffold 3, path guard 57, registry 52, gateway 108, identity 97 |
| `ruff check .` / `ruff format --check .` | clean / 17 files formatted |
| `python -m pip check` | no broken requirements |

- **Mutation checks:** path guard: 16 of 16 broken copies caught. Registry: 13 of 14 caught. Gateway: every behaviour change caught. Identity: 26 of 26 after two gaps were closed. The remaining survivors are behaviour-equivalent (implementation plan, C-05 to C-07).
- **GitHub Actions (remote evidence):** every job passed in both runs, Ruff (lint and format) plus pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13, with no skips:
  - run 42456322322 on `fb4be1b` (through C-04): 193 passed, 1 xfailed per job;
  - run 42456612529 on `95a11c5` (C-05): 245 passed, 1 xfailed per job;
  - run 42457691978 on `124fb2e` (C-06): 353 passed, 1 xfailed per job;
  - **the C-07 commit's run must be checked** (`gh run list --branch c01-project-scaffold`).

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

## 6. Next increment: blocked on owner decisions

Every remaining increment needs at least one unapproved decision (implementation plan, §3):
- **C-08 (policy):** depends on C-03, C-04 and C-07 (all done). Blocked by **D-15 remainder** (whether metadata reaches policy as an explicit `tool_spec` parameter or by a registry lookup inside policy; and whether an informational-only Tool-Abuse detector exists in v1) and **D-24a** (default deny via explicit grant; recommendation "Adopt"). D-05, D-06, D-24b and D-24c are approved. C-08 also defines `SecurityPolicy` (FR-009).
- **C-09 (audit store):** independent. Needs the SQLAlchemy part of NFR-002 (a new runtime dependency), D-09, D-11, D-20, D-24f, and the D-24i module name.
- **C-10 (proxy):** needs C-08, plus D-19 (failure rule) and the D-31 default TTL and capacity.

**Also for the owner:** confirm or amend the C-07 interpretations I-1 to I-7 (decision record, under D-24).

**Most useful owner action:** decide D-24a and the D-15 remainder, which opens C-08.

## 7. Security constraints not to forget

- `decision` holds only an actual policy decision.
  - Operational refusals and `INTERNAL_ERROR` carry `decision=None`.
  - `RESTRICTED_PATH` is a policy DENY when the path is outside a grant (including empty grants, D-05), and a `decision=None` refusal when the path changed before invocation (C2.7).
- Paths are absolute-only and never expanded or resolved against the working directory. Containment is component-wise. The root prefix `"/"` is the only form of unrestricted access.
- The digest excludes `tool_call_id`. Decision claims are atomic and single-use (D-25). The duplicate-call guard fails closed and never evicts (D-27, D-31).
- No input values in errors, logs or the audit (SEC-008, D-29). The async entry is internal (D-30).
- No dependency installs, merges into `main`, branch renames or history rewrites without explicit owner approval.

## 8. Known limitations and gaps

- **No enforcement yet.** The path guard, registry, gateway and identity store have no pipeline calling them.
- **Function level only so far:**
  - F7–F9 are now refused by the gateway; reporting them as `decision=None` is the pipeline (C-11);
  - F14 and F16 at the proxy, with spy counts (C-10);
  - F19 as a policy DENY (C-08).
- **Path guard limits** (documented, not defended): the window after `reverify` (F15, strict xfail); hard links (F17); paths a tool derives internally; case differences, which fail closed; mount boundaries. It is not a sandbox.
- **Registry limits:** entry points are checked by kind only (sync vs coroutine function), not by signature against the schema, which is not a documented rule. A callable object with an `async __call__` is refused as an async entry point (fails closed). The registry is in-memory and per instance; "no mutation reachable from the tool-call path" (SEC-014) also depends on C-10 and C-11 passing it read-only use only.
- **Gateway limits:** schema validators see the original path, and the canonical path is not validated a second time (D-08: one validation). The action holds the caller's validated values, not a model dump, so a schema that transforms values cannot change what executes. Spec tension for C-16: FR-021 `session_id=None` vs the required `session_id` (FR-001, `SecurityRequest`).
- **Identity limits:** credentials are plain SHA-256 digests, which suits high-entropy tokens such as API keys, not passwords. The constant-time comparison is best effort (a dict lookup still precedes it). Grants are tool-level (D-24b), so a granted tool is trusted with everything its validated arguments allow (T-02). Rate-limited grants are refused until C-15. Agents are registered once, with no disable-later or rotation API.
- **Not yet in place:**
  - remote CI verified through C-06; confirm the C-07 run (see §4);
  - no mypy, coverage or Hypothesis (D-22 remainder).
- **Doc housekeeping still open:**
  - §15 of `testing_strategy.md` still shows PROD-TODO for the C-03 model parts of AT-36, AT-40, AT-41, AT-44 and AT-46. Trace each to a named test before marking it.
  - The `threat_model.md` header is at rev. 6 (its content needed no change for D-05, D-18 or D-21).

## 9. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3    # expect the C-07 commit (or later)
git fetch origin && git status -sb             # compare with the remote branch
source .venv/bin/activate                      # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                         # expect 450 passed, 1 xfailed at the C-07 commit
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI result for the branch
```

