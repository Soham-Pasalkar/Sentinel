# Sentinel — Next-Session Resume Note

Updated 2026-11-08 after C-10. This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

## 1. Purpose and architecture (brief)

Sentinel is a planned in-process Python library that sits between AI agents and their tools. For every tool call it decides `allow` / `deny` / `require_approval`. A call that is not allowed must never execute, and every decision is to be audited.

Planned pipeline (decision record C1–C4): gateway → identity and grants → heuristic detection → deterministic policy → proxy (the sole executor) → output filtering. The pipeline is the sole audit writer. Framework integration is Design B, `wrap_tools` (D-12).

**What exists today is the contract layer, the path guard, the tool registry, the request gateway, identity with tool-level grants, the policy engine and the execution proxy. They are not yet connected:** no pipeline (C-11) runs them in order, writes the audit (C-09) or returns a `PipelineResult`, and there is no client API or framework adapter. So Sentinel still protects no real tool call end to end. Sentinel protects no tool call today. The only public attribute is `sentinel.__version__`.

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
| C-07 | Identity and grants [`src/sentinel/identity.py`](../../src/sentinel/identity.py), four models in `models.py`; 97 tests | `25dad4f` |
| Decisions | **D-24a, D-15 approved**; I-1–I-7 confirmed; C-08 interpretations I-8–I-11 | `deab308` |
| C-08 | Policy engine [`src/sentinel/policy.py`](../../src/sentinel/policy.py); 96 tests | `cc27883` |
| Decisions | **D-19 failure rule, D-31 defaults approved**; D-31 contract reaffirmed; C-10 interpretations I-12–I-17 | `65a4550` |
| C-10 | Execution proxy [`src/sentinel/proxy.py`](../../src/sentinel/proxy.py); 89 tests | `708745d` |

## 3. Repository state (verified 2026-11-08)

- **Branch:** `c01-project-scaffold`. HEAD is the C-10 commit on top of `65a4550` (see `git log -3`); compare with the remote before starting.
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold` (pushed with owner authorization; compare with `git fetch origin && git status -sb`).
  - The repository is **public**.
  - Because the repository was empty, GitHub made `c01-project-scaffold` the **default branch**.
  - No `main` exists on the remote or locally; nothing was merged.
- **Waiting on:** an independent review of the pushed code is pending, arranged by the owner.

## 4. Tests and quality checks (macOS, Python 3.11.14, project `.venv`)

| Command | Result |
|---|---|
| `pytest` | **635 passed, 1 xfailed** (F15, strict). Per file: action 52, models 70, exceptions 12, scaffold 3, path guard 57, registry 52, gateway 108, identity 97, policy 96, proxy 89 |
| `ruff check .` / `ruff format --check .` | clean / 21 files formatted |
| `python -m pip check` | no broken requirements |

- **Mutation checks:** path guard: 16 of 16 broken copies caught. Registry: 13 of 14 caught. Gateway: every behaviour change caught. Identity: 26 of 26 after two gaps were closed. Policy: every behaviour change caught after one gap (case-sensitive matching) was closed. Proxy: 36 broken versions; every behaviour change caught after one gap (async path re-check) was closed and one hanging test was fixed. The remaining survivors are behaviour-equivalent (implementation plan, C-05 to C-07).
- **GitHub Actions (remote evidence):** every job passed in both runs, Ruff (lint and format) plus pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13, with no skips:
  - run 42456322322 on `fb4be1b` (through C-04): 193 passed, 1 xfailed per job;
  - run 42456612529 on `95a11c5` (C-05): 245 passed, 1 xfailed per job;
  - run 42457691978 on `124fb2e` (C-06): 353 passed, 1 xfailed per job;
  - run 42461535297 on `25dad4f` (C-07): 450 passed, 1 xfailed per job;
  - run 42463102989 on `cc27883` (C-08): 546 passed, 1 xfailed per job;
  - run 42465473430 on `708745d` (C-10): 635 passed, 1 xfailed per job.

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

The next increments, per implementation plan §3:
- **C-09 (audit store):** depends only on C-03. Blocked by the **SQLAlchemy part of NFR-002** (a new runtime dependency), **D-09** (v1 persistence model), **D-11** (audit storage default), **D-20** (concurrency), **D-24f** (audit wording) and the **D-24i** module name (`audit.py`). D-29 is approved.
- **C-11 (pipeline):** needs C-06 to C-10 (C-09 is the only one missing), plus **D-16** (orchestrator and sole audit writer) and **D-20**. D-30 is approved (internal async entry). C-11 connects gateway → identity → detector stub → policy → proxy → audit and maps outcomes to `PipelineResult`.
- C-12 (client) needs C-11, D-17 and the D-24i class name.

**Also for the owner:** confirm or amend the C-08 interpretations I-8 to I-11 and the C-10 interpretations I-12 to I-17 (decision record, under D-24).

**Most useful owner action:** decide the C-09 set (SQLAlchemy dependency, D-09, D-11, D-20, D-24f, D-24i module name). That unblocks C-09, and with D-16 also C-11, the first end-to-end enforcement.

## 7. Security constraints not to forget

- `decision` holds only an actual policy decision.
  - Operational refusals and `INTERNAL_ERROR` carry `decision=None`.
  - `RESTRICTED_PATH` is a policy DENY when the path is outside a grant (including empty grants, D-05), and a `decision=None` refusal when the path changed before invocation (C2.7).
- Paths are absolute-only and never expanded or resolved against the working directory. Containment is component-wise. The root prefix `"/"` is the only form of unrestricted access.
- The digest excludes `tool_call_id`. Decision claims are atomic and single-use (D-25). The duplicate-call guard fails closed and never evicts (D-27, D-31).
- No input values in errors, logs or the audit (SEC-008, D-29). The async entry is internal (D-30).
- No dependency installs, merges into `main`, branch renames or history rewrites without explicit owner approval.

## 8. Known limitations and gaps

- **No end-to-end enforcement yet.** The components exist but no pipeline (C-11) connects them or writes the audit.
- **Function level only so far:**
  - F7–F9 are now refused by the gateway; reporting them as `decision=None` is the pipeline (C-11);
  - F14 and F16 now also at the proxy, with spy counts (`test_proxy.py`);
  - F19 is now a policy DENY (`test_empty_prefix_list_denies_every_path`); end-to-end needs C-11.
- **Path guard limits** (documented, not defended): the window after `reverify` (F15, strict xfail); hard links (F17); paths a tool derives internally; case differences, which fail closed; mount boundaries. It is not a sandbox.
- **Registry limits:** entry points are checked by kind only (sync vs coroutine function), not by signature against the schema, which is not a documented rule. A callable object with an `async __call__` is refused as an async entry point (fails closed). The registry is in-memory and per instance; "no mutation reachable from the tool-call path" (SEC-014) also depends on C-10 and C-11 passing it read-only use only.
- **Gateway limits:** schema validators see the original path, and the canonical path is not validated a second time (D-08: one validation). The action holds the caller's validated values, not a model dump, so a schema that transforms values cannot change what executes. Spec tension for C-16: FR-021 `session_id=None` vs the required `session_id` (FR-001, `SecurityRequest`).
- **Identity limits:** credentials are plain SHA-256 digests, which suits high-entropy tokens such as API keys, not passwords. The constant-time comparison is best effort (a dict lookup still precedes it). Grants are tool-level (D-24b), so a granted tool is trusted with everything its validated arguments allow (T-02). Rate-limited grants are refused until C-15. Agents are registered once, with no disable-later or rotation API.
- **Policy limits:** rate limits (row 5) are not evaluated until C-15; `risk_score` is not computed (no approved formula); a `ToolSpec` with the right name but wrong metadata cannot be detected by policy, because the pipeline must pass the registry's spec (D-15). A decision is not enforcement until the proxy (C-10) executes only `decision.action` after re-verification.
- **Proxy limits:** both guards are process-local (not shared across workers or hosts); single-use claims are kept for the proxy's lifetime, so memory grows with executed requests; a `tool_call_id` repeat more than 300 s after the first call finished is treated as new; path re-checks narrow but do not close the race before the tool's own `open`; the output filter is a pass-through until C-14; the proxy cannot re-derive the destructive-approval requirement (policy's, with the registry spec). Sync tools run on the calling thread; nothing is offloaded.
- **Not yet in place:**
  - remote CI verified through C-10 (see §4);
  - no mypy, coverage or Hypothesis (D-22 remainder).
- **Doc housekeeping still open:**
  - §15 of `testing_strategy.md` still shows PROD-TODO for the C-03 model parts of AT-36, AT-40, AT-41, AT-44 and AT-46. Trace each to a named test before marking it.
  - The `threat_model.md` header is at rev. 6 (its content needed no change for D-05, D-18 or D-21).

## 9. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3    # expect the C-10 commit (or later)
git fetch origin && git status -sb             # compare with the remote branch
source .venv/bin/activate                      # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                         # expect 635 passed, 1 xfailed at the C-10 commit
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI result for the branch
```

