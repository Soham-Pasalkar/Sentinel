# Sentinel — Next-Session Resume Note

Updated 2026-11-08 after C-12. This is a pointer, not a source of truth: the canonical register is [`01-inception/decision_record.md`](01-inception/decision_record.md), and the increment plan is [`01-inception/implementation_plan.md`](01-inception/implementation_plan.md). Where this note and those documents disagree, they win.

## 1. Purpose and architecture (brief)

Sentinel is a planned in-process Python library that sits between AI agents and their tools. For every tool call it decides `allow` / `deny` / `require_approval`. A call that is not allowed must never execute, and every decision is to be audited.

Planned pipeline (decision record C1–C4): gateway → identity and grants → heuristic detection → deterministic policy → proxy (the sole executor) → output filtering. The pipeline is the sole audit writer. Framework integration is Design B, `wrap_tools` (D-12).

**M1 is implemented: `SentinelClient` is the public API.** It registers tools and agents, evaluates each tool call through the pipeline (gateway → identity → detector stub → policy → proxy, every audit event committed first), and reads the audit with `audit_events`. Still missing: heuristic detection (C-13), real output filtering (C-14), rate limits (C-15), framework adapters (C-16). Gate G-M1 is **not closed**: it needs a coverage measurement (pytest-cov, D-22 open) and an owner review.

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
| Decisions | **NFR-002 (no SQLAlchemy), D-09, D-11, D-20 (audit writes), D-24f, D-24i modules approved**; C-09 interpretations I-18–I-23 | `5d6ce77` |
| C-09 | Audit store [`src/sentinel/store.py`](../../src/sentinel/store.py) and logger [`src/sentinel/audit.py`](../../src/sentinel/audit.py); 182 tests | `8379e47` |
| Decisions | **D-16, D-20 approved**; I-8–I-23 confirmed; C-11 interpretations I-24–I-31 | `eebfcc4` |
| C-11 | Pipeline [`src/sentinel/pipeline.py`](../../src/sentinel/pipeline.py), `config.py`, `detector.py`; C-10 fix I-30; 116 tests | `625970a` |
| Decisions | **D-17, D-24i (`SentinelClient`) approved**; C-12 interpretations I-32–I-35 | `1292974` |
| C-12 | Client [`src/sentinel/client.py`](../../src/sentinel/client.py), public `__all__`, [`examples/quickstart.py`](../../examples/quickstart.py), README; 58 tests | the C-12 commit after `1292974` (see `git log`) |

## 3. Repository state (verified 2026-11-08)

- **Branch:** `c01-project-scaffold`. HEAD is the C-12 commit on top of `1292974` (see `git log -3`); compare with the remote before starting.
- **Remote:** `https://github.com/Soham-Pasalkar/Sentinel`, branch `c01-project-scaffold` (pushed with owner authorization; compare with `git fetch origin && git status -sb`).
  - The repository is **public**.
  - Because the repository was empty, GitHub made `c01-project-scaffold` the **default branch**.
  - No `main` exists on the remote or locally; nothing was merged.
- **Waiting on:** an independent review of the pushed code is pending, arranged by the owner.

## 4. Tests and quality checks (macOS, Python 3.11.14, project `.venv`)

| Command | Result |
|---|---|
| `pytest` | **991 passed, 1 xfailed** (F15, strict). Per file: action 52, models 70, exceptions 12, scaffold 3, path guard 57, registry 52, gateway 108, identity 97, policy 96, proxy 89, audit repository 70, masking 66, reconstruction 39, storage default (integration) 7, pipeline config 17, audit ordering 22, audit reconstruction (integration) 10, async pipeline 13, fault injection 29, invariants 23, secret canary 2, client (e2e) 55, quickstart (e2e) 2; audit repository now 71 |
| `ruff check .` / `ruff format --check .` | clean / 42 files formatted |
| `python -m pip check` | no broken requirements |

- **Mutation checks:** path guard: 16 of 16 broken copies caught. Registry: 13 of 14 caught. Gateway: every behaviour change caught. Identity: 26 of 26 after two gaps were closed. Policy: every behaviour change caught after one gap (case-sensitive matching) was closed. Proxy: 36 broken versions; every behaviour change caught after one gap (async path re-check) was closed and one hanging test was fixed. Audit: 39 broken versions; every behaviour change caught after four gaps were closed. Pipeline: 28 broken versions; every behaviour change caught after two gaps were closed. Client: 18 broken versions; all caught after one gap was closed. The remaining survivors are behaviour-equivalent (implementation plan, C-05 to C-07).
- **GitHub Actions (remote evidence):** every job passed in both runs, Ruff (lint and format) plus pytest on `ubuntu-latest` and `macos-latest` × Python 3.11, 3.12, 3.13, with no skips:
  - run 42456322322 on `fb4be1b` (through C-04): 193 passed, 1 xfailed per job;
  - run 42456612529 on `95a11c5` (C-05): 245 passed, 1 xfailed per job;
  - run 42457691978 on `124fb2e` (C-06): 353 passed, 1 xfailed per job;
  - run 42461535297 on `25dad4f` (C-07): 450 passed, 1 xfailed per job;
  - run 42463102989 on `cc27883` (C-08): 546 passed, 1 xfailed per job;
  - run 42465473430 on `708745d` (C-10): 635 passed, 1 xfailed per job;
  - run 42467083583 on `8379e47` (C-09): 817 passed, 1 xfailed per job;
  - run 42469205994 on `625970a` (C-11): 933 passed, 1 xfailed per job;
  - **the C-12 commit's run must be checked** (`gh run list --branch c01-project-scaffold`).

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

## 6. Next: close gate G-M1, then M2 (owner decisions needed)

**G-M1** (implementation plan): C-01 … C-12 complete ✅, README accurate ✅, threat model revisited ✅. Open:
- **NFR-006 coverage**: needs pytest-cov, part of the open **D-22** remainder (also mypy for NFR-005, and Hypothesis).
- **Owner review** before M2.

**After G-M1** (each needs decisions):
- **C-13 detection:** D-24e (detector interface, recursive scan, detector failure), D-24h (advisory wording), and the owner's review of the rule and severity table.
- **C-14 output filtering:** the D-19 M3 mode (recorded: default `redact`; unsupported types withheld in `enforce`).
- **C-15 rate limits:** the D-20 rate-limit part and the cross-agent constraint mechanism.
- **C-16 framework adapter:** the D-04 adapter part; reconcile FR-021 `session_id=None` with the required `session_id`.

**Also for the owner:** confirm or amend interpretations I-24 to I-35 (decision record, under D-24).

**Most useful owner action:** decide D-22 (pytest-cov at least) and review M1.

## 7. Security constraints not to forget

- `decision` holds only an actual policy decision.
  - Operational refusals and `INTERNAL_ERROR` carry `decision=None`.
  - `RESTRICTED_PATH` is a policy DENY when the path is outside a grant (including empty grants, D-05), and a `decision=None` refusal when the path changed before invocation (C2.7).
- Paths are absolute-only and never expanded or resolved against the working directory. Containment is component-wise. The root prefix `"/"` is the only form of unrestricted access.
- The digest excludes `tool_call_id`. Decision claims are atomic and single-use (D-25). The duplicate-call guard fails closed and never evicts (D-27, D-31).
- No input values in errors, logs or the audit (SEC-008, D-29). The async entry is internal (D-30).
- No dependency installs, merges into `main`, branch renames or history rewrites without explicit owner approval.

## 8. Known limitations and gaps

- **Public API exists; protection is partial.** `SentinelClient` enforces authorization, execution control and auditing. The output filter is a pass-through and the detector finds nothing until C-14 and C-13; there are no rate limits or framework adapters yet.
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
- **Audit limits:** append-only through Sentinel's API only. Anyone with write access to the file, or privileged in-process code, can change or delete rows; there is no tamper evidence (hash-chaining is post-v1). Masking is heuristic and cannot recognise every secret (for example, a token with an unexpected shape). Durability depends on the filesystem honouring `fsync`. Writes are serialized per store; several processes on one file rely only on SQLite's locking and are not supported. No migrations: a schema mismatch refuses the store.
- **Pipeline limits:** after a failed audit write no further events are written for that request (I-25). An in-memory store never reports a complete audit, so outputs are never released with `:memory:`. The best-effort interruption record runs synchronously and briefly on the event loop, as C1.6 prescribes. A sync tool reached through the async entry runs in a worker thread that cannot be cancelled; its audit completes when it ends. No exactly-once external side effects; no OS sandboxing.
- **Client limits:** `audit_events` returns the first `limit` events (at most 1,000) with no pagination; it reads the local file through Sentinel's own connection and is not an access-control boundary for that file. `evaluate_request` raises `TypeError` for a non-mapping `raw` (not audited). No public async method (D-30).
- **Not yet in place:**
  - remote CI verified through C-11; confirm the C-12 run (see §4);
  - no mypy, coverage or Hypothesis (D-22 remainder).
- **Doc housekeeping still open:**
  - §15 of `testing_strategy.md` still shows PROD-TODO for the C-03 model parts of AT-36, AT-40, AT-41, AT-44 and AT-46. Trace each to a named test before marking it.
  - The `threat_model.md` header is at rev. 6 (its content needed no change for D-05, D-18 or D-21).

## 9. Resume commands

```bash
cd /path/to/Sentinel
git status --short && git log --oneline -3    # expect the C-12 commit (or later)
git fetch origin && git status -sb             # compare with the remote branch
source .venv/bin/activate                      # recreate only with owner approval:
# python3.11 -m venv .venv && python -m pip install -e ".[dev]" -c constraints-dev.txt
pytest                                         # expect 991 passed, 1 xfailed at the C-12 commit
python examples/quickstart.py                    # three lines: allow, deny, audit trail
ruff check . && ruff format --check .
python -m pip check
gh run list --repo Soham-Pasalkar/Sentinel --branch c01-project-scaffold   # CI result for the branch
```

