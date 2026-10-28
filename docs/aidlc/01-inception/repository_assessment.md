# Repository Assessment — Sentinel (AI-DLC Inception)

| | |
|---|---|
| Phase | Inception |
| Date | 2026-10-28 |
| Project owner | Soham Pasalkar |
| Status | Draft — pending owner review |

> **Snapshot notice:** §1–§8 record the repository as observed at Inception (before any code existed), and §9 records the Phase 1.5 re-check. They are kept as historical evidence and are not updated. Current implementation status is in the [README](../../../README.md) and the C-01 notes in [`implementation_plan.md`](implementation_plan.md).

Evidence labels: **OBSERVED** (confirmed by a file or command output in this session), **INFERRED** (reasoned from evidence), **ASSUMPTION** (needs validation), **UNRESOLVED** (unknown or undecided).

---

## 1. Directory structure

**OBSERVED** (`find . -path ./.git -prune -o -print`):

```text
Sentinel/
├── .DS_Store                                   (macOS Finder metadata, untracked)
├── .git/
├── SENTINEL_BUILD_BRIEF.md                     (405 lines)
└── docs/
    ├── .DS_Store
    └── architecture/
        ├── AI Agent Data Security-2026-09-08-171413.png
        ├── AI Agent Data Security-2026-09-11-020746.svg
        ├── AI Agent Security Architecture-2026-10-26-163111.png
        ├── Core Security Pipeline-2026-09-11-015830.png
        ├── DataFlowDaigramLevel0.png
        ├── DataFlowDaigramLevel1.png
        ├── EntityRelationshipDaigram.png
        ├── Sentinel_ Secure Multi-Agent AI Workflows Overview CHATGPT.pdf   (13 pages)
        ├── UML-activityDaigram.png
        ├── UML-classDaigram.png
        ├── UML-sequenceDaigram.png
        └── UML-usecaseDaigram.png
```

`docs/aidlc/01-inception/` (this directory) was created during this phase and holds only Inception documents.

## 2. Git state

| Fact | Label | Evidence |
|---|---|---|
| Repository is initialised; current branch `main` | OBSERVED | `git status`: "On branch main" |
| No commits exist | OBSERVED | "No commits yet"; `git log` → "your current branch 'main' does not have any commits yet" |
| All files untracked: `.DS_Store`, `SENTINEL_BUILD_BRIEF.md`, `docs/` | OBSERVED | `git status` |
| Remote `origin` = `https://github.com/Soham-Pasalkar/Sentinel.git` | OBSERVED | `git config --get remote.origin.url` |
| Whether the remote exists or holds content | UNRESOLVED | Not queried; no network operations run |
| No custom git hooks | OBSERVED | `.git/hooks` contains only `*.sample` files |
| No `.gitignore`, so `.DS_Store` would be committed by `git add .` | OBSERVED / INFERRED | No `.gitignore` present |

## 3. Implementation status

| Area | Status | Label |
|---|---|---|
| Source code (`src/`, any `.py`) | None | OBSERVED |
| Tests | None | OBSERVED |
| `pyproject.toml` / packaging | None | OBSERVED |
| CI configuration (`.github/`) | None | OBSERVED |
| README | None | OBSERVED |
| `.gitignore`, `.env.example` | None | OBSERVED |
| Requirements / threat model / test plan (before this phase) | None | OBSERVED |

The project is pre-implementation. Nothing in the brief has been implemented. (OBSERVED)

## 4. Local development environment

Observed only; nothing was installed or changed.

| Item | Observation |
|---|---|
| Default `python3` | 3.12.2 (pyenv) |
| `python3.11` | Present (`/opt/homebrew/bin/python3.11`) |
| `python3.10`, `python3.13` | Not on PATH |
| `uv`, `ruff` | Not on PATH |
| pydantic, sqlalchemy, pytest, ruff, mypy, langgraph, langchain | Not installed in the default pyenv 3.12.2 environment (`pip3 list` grep returned nothing) |
| `os.path.realpath('/tmp')` | `/private/tmp`. On macOS `/tmp` is a symlink, which matters for path-prefix enforcement (see CF-13) |

## 5. Existing documentation — inventory and purpose

### 5.1 `SENTINEL_BUILD_BRIEF.md` (OBSERVED, read in full)

A build brief written for Claude Code. It describes itself as restating the PDF ("Source of truth: the architecture document…"), resolving its open points, and defining Milestone 1. Each statement is tagged `[DOC]`, `[REC]` or `[ASSUMPTION]`. It contains the scope, stack, repository layout, pipeline contract, data model, per-engine behaviour, policy evaluation order, a testing table, the M1 commit plan, later milestones (M2–M6), and decision log R1–R19. It is the most detailed and internally consistent design reference in the repository.

### 5.2 `Sentinel_ Secure Multi-Agent AI Workflows Overview CHATGPT.pdf` (OBSERVED, all 13 pages read)

This is the architecture document the brief calls its "source of truth". The page header and filename say it was generated with ChatGPT. Sections: problem/vision, system architecture, data flow, engine-by-engine breakdown, integration contracts, build order, conventions. Its citations (`【16†L221-L229】`, `【15†L125-L127】`, `【17†L324-L332】`) are ChatGPT browsing markers that resolve to no available source. Its quotations from a "Sentinel Gateway page" refer to an external website that is not part of this project. **INFERRED:** the cited research claims cannot be verified from this repository and should not be relied on as evidence.

### 5.3 Diagrams (OBSERVED, every image viewed; SVG text labels extracted)

| File | Date in name / mtime | Content summary |
|---|---|---|
| `AI Agent Security Architecture-2026-10-26` | 2026-10-26 | Six layers: Agent → Gateway (Session Manager, Request Interceptor) → Security Core (Identity, Policy, Threat Detection) → Execution (Tool Proxy, Output Filter) → Data (Audit Log Store, Agent & Policy Store) → Monitoring (Alert Manager, **Security Dashboard**). |
| `UML-classDaigram` | 2026-10-26 | `Agent{agentId,status; requestTool()}` → `Gateway{handleRequest()}`, which calls `IdentityModule.authenticate()`, `DetectionModule.analyze()`, `PolicyEngine.evaluate()`, `ToolProxy.execute()` and `AuditLogger.log()`. **The Gateway is the orchestrator.** |
| `UML-sequenceDaigram` | 2026-10-26 | Gateway calls Identity ("Verified"), Detection (returns a **risk score**), then Policy; alt [Allowed] → Proxy → filtered output; alt [Denied] → "Access denied". A single "Log event" appears **after** the alt block. No REQUIRE_APPROVAL branch. |
| `UML-activityDaigram` | 2026-10-26 | Authenticated? No → "Reject and log". Yes → detection → "Policy allows?" No → "Deny and alert"; Yes → execute → filter → return. All branches end with "Write audit log" **after** execution. No approval branch. |
| `UML-usecaseDaigram` | 2026-10-26 | Actors: AI Agent (Submit Tool Call ⟶ include Authenticate, Evaluate Policy), Security Admin (Manage Agents and Policies, Handle Alerts), **Auditor (View Audit Logs)**. |
| `DataFlowDaigramLevel0` | 2026-10-26 | Context: Agent ↔ Sentinel; Security Admin (policies/setup in, alerts/reports out); External Tools (approved invocation out, output in). |
| `DataFlowDaigramLevel1` | 2026-10-26 | 1.0 Authenticate → 2.0 Detect Threats → 3.0 Evaluate Policy → Deny → 5.0 Log and Alert; Allow → 4.0 Execute and Filter → 5.0. No separate Gateway process. |
| `EntityRelationshipDaigram` | 2026-10-26 | Entities: **USER**, AGENT, POLICY, CAPABILITY_ENVELOPE, TOOL, **REQUEST** (risk_score), **DECISION**, **ALERT**. **No AuditEvent entity.** Relations: User registers Agents; Agent has one Envelope; Policy governs Envelopes; Envelope permits Tools (M:N); Agent issues Requests; Tool receives Requests; Request results_in one Decision and may_raise Alerts. |
| `Core Security Pipeline-2026-09-11` | 2026-09-11 | An older, broader design: parallel "Data Security (Provenance, Anti-Injection, Trust)", "Action Authorization (Scope, Privilege, Delegation)" and "Behavior Monitoring (Drift & Anomaly)" feed a **Cross-Domain Risk Engine** (Approved / High Risk). |
| `AI Agent Data Security-2026-09-08` (PNG) and `-2026-09-11` (SVG) | 2026-09 | The detailed version of the above, with 133 labels extracted from the SVG: provenance tagging, RAG trust defense, QUARANTINE, task capability envelope (tool/operation/resource/target/params checks), **agent delegation validation**, **privilege drift check**, live execution graph, risk engine with LOW/MEDIUM/HIGH → ALLOW/CONFIRM/BLOCK, human decision, **scoped credential**, tool gateway, post-action check, security dashboard. The PNG is too wide (8192×1113) to read at display resolution. **INFERRED:** from file dates and shared titles, it is an earlier render of the same diagram as the SVG. |

## 6. Discrepancies between the repository and the build brief

| ID | Discrepancy | Label | Impact | Tracked in |
|---|---|---|---|---|
| RA-01 | Brief §5.2/R13: "The doc refers to an ER diagram that is not included". The ER diagram **is** present (`EntityRelationshipDaigram.png`, dated 2026-10-26, after the brief's design work). | OBSERVED | R13 rests on a stale premise. | OD-01 |
| RA-02 | The ER diagram models `REQUEST`, `DECISION`, `ALERT` and `USER` entities and has **no `AuditEvent`**. The brief and the PDF model `AuditEvent` and reject a `Request` table. | OBSERVED | Persistence schema conflict. | OD-01 |
| RA-03 | Class and sequence diagrams make **Gateway the orchestrator**. Brief §6.1 says Gateway only validates, and §3/R15 adds `pipeline.py` as the orchestrator. | OBSERVED | Ownership of the enforcement path. | Arch. assessment §3; OD-02 |
| RA-04 | Sequence and activity diagrams write the audit log **after** execution. Brief R12 requires the DECISION event **before** execution, failing closed if the write fails. | OBSERVED | Directly affects SEC-005. | CF-09 |
| RA-05 | No diagram has a REQUIRE_APPROVAL branch. The PDF and the brief do. | OBSERVED | Diagrams are incomplete, not contradictory. | CF-04 |
| RA-06 | The sequence diagram returns a "Risk score" from Detection. The brief makes the risk score informational and drives policy from findings (R7). | OBSERVED | Policy input contract. | CF-03 |
| RA-07 | The September diagrams describe a far larger system (provenance, RAG trust, delegation, privilege drift, risk engine, scoped credentials, dashboard). The PDF and the brief exclude or never mention most of it. | OBSERVED | Scope ambiguity. | OD-03 |
| RA-08 | The layered architecture diagram includes a Security Dashboard. The brief lists UI/dashboard as out of scope for v1 (optional M6). | OBSERVED | Scope, minor. | OD-03 |
| RA-09 | The use-case diagram has an **Auditor → View Audit Logs** use case. The brief's M1 public API has no audit-retrieval method. | OBSERVED | Missing functional requirement. | FR-012; OD-04 |
| RA-10 | Brief §0.3 says "`git init` on day one". The repository is already initialised and `origin` already points to GitHub. | OBSERVED | Step already done; the brief's "push once the user provides the remote" is satisfied in principle. Pushing still needs explicit owner approval. | — |
| RA-11 | Brief §0.4 requires a README "Open decisions" section. No README exists, and the AI-DLC process now keeps decisions in `open_decisions.md`. | OBSERVED | Two places to keep in sync. | OD-05 |
| RA-12 | The brief requires Python ≥3.10. Under the CPython 5-year support schedule (PEP 619), 3.10 reaches end of life in **October 2026**, which is the current month. | INFERRED (schedule-based; verify against python.org) | R1's rationale ("3.9 is EOL") now applies to 3.10 as well. | CF-17 / OD-06 |
| RA-13 | Untracked `.DS_Store` files exist and there is no `.gitignore`. | OBSERVED | Risk of committing OS junk on the first commit. | Implementation plan C-01 |
| RA-14 | The PDF ("source of truth") is a ChatGPT-generated document with unresolvable citations. | OBSERVED | Treat its factual claims about external research as unverified. Its design content stays the baseline. | — |

## 7. Missing prerequisites for Construction

| # | Prerequisite | Label |
|---|---|---|
| P-1 | Owner decisions on the blocking items in `open_decisions.md` (the "Blocks" column) | UNRESOLVED |
| P-2 | Python version floor (3.10 vs 3.11) | UNRESOLVED |
| P-3 | A project virtual environment. None exists, and the dev tools (pytest, ruff, pydantic, sqlalchemy) are not installed | OBSERVED |
| P-4 | `.gitignore` before the first commit (`.DS_Store`, `.venv`, `*.db`, `.env`, `__pycache__`) | OBSERVED as missing |
| P-5 | Owner permission to commit (the brief expects one commit per increment) and, separately, to push to `origin` | UNRESOLVED |
| P-6 | Verified availability of PyPI name `sentinel-ai` and possible clash of import name `sentinel` with an existing PyPI distribution | ASSUMPTION (not checked; see CF-17) |
| P-7 | Versions of LangGraph/LangChain to target, and their minimum Python version | UNRESOLVED (not researched in this phase) |
| P-8 | Whether the remote `origin` repository exists and whether it is empty | UNRESOLVED |

## 8. Commands run in this phase

All commands were read-only. Nothing was installed, committed or pushed.

| Command (summary) | Observed result |
|---|---|
| `pwd; ls -la; find … ; git status; git branch -a; git log` | Structure in §1; branch `main`, no commits, 3 untracked entries |
| `wc -l` on the brief and docs | Brief: 405 lines |
| `file *` in `docs/architecture` | 10 PNGs, 1 SVG, 1 PDF v1.7; dimensions recorded |
| `pdfinfo` / `pdftotext` presence check | Neither installed. The PDF was read with the Read tool instead (13 pages) |
| Python one-off (isolated `-I`) to extract SVG text labels | 133 labels (§5.3) |
| `command -v` for python3.10–3.13, uv, ruff, pip3 | See §4 |
| `git config --get remote.origin.url`; `git remote -v`; `ls .git/hooks` | `origin` set; only sample hooks |
| `python3 -c "os.path.realpath('/tmp')"` | `/private/tmp` |
| `pip3 list \| grep …` | No matching packages (grep exit 1) |

## 9. Phase 1.5 re-verification (2026-10-28)

| Fact | Label | Evidence |
|---|---|---|
| Repository state unchanged since Inception: still no commits, same untracked entries (`.DS_Store`, `SENTINEL_BUILD_BRIEF.md`, `docs/`) | OBSERVED | `git status --short` |
| No file other than the seven Inception documents was created or modified after Inception began | OBSERVED | `find . -newer docs/aidlc/01-inception/repository_assessment.md` listed only Inception documents |
| Original references (brief, PDF, diagrams) predate the Inception reading; not modified | OBSERVED | `stat` modification times: latest original is the brief at 2026-10-28 20:15:25 |
| No dependency installed, no network call, no commit or push during Phase 1.5 | OBSERVED (by construction of this session) | Command log in `decision_record.md` §11 |
| PyPI name availability (`sentinel-ai`, `sentinel`) and LangGraph behaviour | UNRESOLVED | Network checks and installs were excluded from Phase 1.5; tracked as D-02 and D-12 |

Phase 1.5 added `decision_record.md` and revised the other Inception documents in place. See `decision_record.md` §9.
