# Sentinel — Build Brief for Claude Code

Source of truth: the architecture document "Sentinel: Secure Multi-Agent AI Workflows". This brief restates it, resolves its open points, and defines the first milestone.

**Tags used throughout**
- **[DOC]** stated in the source document.
- **[REC]** my recommendation where the document is silent, ambiguous, or self-contradictory. Implement unless the user rejects it.
- **[ASSUMPTION]** an interpretation I had to make. Record it in the README under "Open decisions".

---

## 0. Working rules

1. Read this whole brief before writing code.
2. Do not add features, services, or scope not listed here. If something is undefined, choose the smallest option, record it in the README "Open decisions" section, and continue. Do not invent answers for things the document marks open.
3. **Git/GitHub**
   - `git init` on day one. Commit locally; push to `origin` once the user provides the remote. Do not create remotes or repos unless asked.
   - Small, logically scoped commits: one concern each, code and its tests together, never a "misc" commit.
   - Conventional-style messages: `type(scope): imperative summary` (types: `chore`, `ci`, `feat`, `test`, `docs`, `fix`, `refactor`). Body explains *why* when non-obvious.
   - The **first commit is the project scaffold**. Planned M1 sequence is in §11.
   - Never commit secrets, `.env` files, or SQLite database files.
4. **README is a living document.** Any commit that changes behavior updates the README in the same commit. It must always contain: current status table (each component: `not started / stub / implemented`), quickstart that actually runs, architecture summary, "Known limitations", and "Open decisions".
5. Run `pytest` before every commit. Do not commit with failing tests.

---

## 1. Purpose and scope

**Purpose [DOC]:** a runtime security library for agentic AI workflows. It is a middleware control plane that intercepts every agent-to-tool request, applies identity, detection, and policy checks, then allows, blocks, or logs it, leaving an audit trail. Developers wrap an existing workflow (LangGraph/LangChain) and get enforcement without per-agent security code.

**Core invariant [DOC]:** no action executes unless explicitly allowed; a denied request never reaches the tool; every decision is audited.

**In scope for v1 [DOC]:** the six-stage pipeline, tool registry/proxy, rule-based detection, output filtering, append-only audit log, SQLite-backed persistence, Python API.

**Explicitly out of scope for v1 [DOC]:** ML-based anomaly detection; complex policy representation beyond a simple policy-as-code format; human-approval workflow (only *record* that approval is needed); UI/dashboard; distributed/multi-instance deployment (assume a single process).

**Also deferred [REC]:** async APIs, `RESTRICT` decision, alert delivery channels (log only), LLM-based classifier, registry signing, audit hash-chaining, Alembic migrations, plan-splitting in the Gateway.

**Known limitations to state in README [REC]:**
- Sentinel is an in-process library. It constrains LLM-driven tool calls routed through it. It cannot stop malicious in-process code that calls tool functions directly, and `agent_id` is caller-asserted unless a token is verified.
- Prompt-injection and sensitive-data detection are heuristic (keyword/regex); they reduce risk, they do not eliminate it.
- Content inside an agent's LLM context (e.g. a retrieved document) is invisible to Sentinel unless it appears in tool-call arguments or tool output.
- v1 [ASSUMPTION]: one tool call = one request; "action" granularity = tool name (no sub-actions).

---

## 2. Language and framework choices

| Choice | Basis |
|---|---|
| Python, `src/` layout | [DOC] |
| Python **≥3.10** (develop/test on 3.11 and 3.12) | [REC] doc says 3.9+, but 3.9 is end-of-life; verify LangGraph's current minimum before the integration milestone |
| Pydantic **v2** `BaseModel` for all inter-module objects | [DOC] Pydantic; [REC] v2 |
| SQLAlchemy **2.x** ORM, SQLite for v1 | [DOC] SQLAlchemy "or similar", SQLite "fine" for now |
| pytest | [DOC] |
| Linting/formatting: ruff (lint + format), mypy optional | [REC] doc requires PEP8 and lint/CI but names no tool |
| CI: GitHub Actions running ruff + pytest | [DOC] CI requirement; [REC] GitHub Actions |
| Minimal dependencies | [DOC] |
| Package name `sentinel-ai` on PyPI, import name `sentinel` | [DOC]. [ASSUMPTION] availability unverified; do not publish without checking |

---

## 3. Repository layout

[DOC] layout, with labelled additions:

```
sentinel/
├── pyproject.toml
├── README.md
├── .gitignore                 # [REC] ignores .env, *.db, __pycache__, .venv
├── .env.example               # [REC] variable names only (see §9)
├── .github/workflows/ci.yml   # [REC]
├── examples/
│   └── quickstart.py          # [REC] runnable demo for M1
├── src/sentinel/
│   ├── __init__.py            # exports SentinelClient, SecurityPolicy, errors
│   ├── client.py              # public SentinelClient API
│   ├── policy.py              # SecurityPolicy + PolicyEngine
│   ├── gateway.py             # request parsing, session store
│   ├── identity.py            # auth + capability lookup
│   ├── detector.py            # threat detection
│   ├── proxy.py               # tool execution + output filter
│   ├── audit.py               # AuditLogger, alerts   [REC] renamed from doc's logging.py (avoids shadowing stdlib name)
│   ├── models.py              # Pydantic models, enums
│   ├── exceptions.py          # SentinelError hierarchy
│   ├── pipeline.py            # [REC] orchestrates the stages; client.py is a thin facade over it
│   ├── registry.py            # [REC] ToolRegistry (doc names the component but not a file)
│   ├── store.py               # [REC] SQLAlchemy ORM models + repository layer (doc: "ORM or repository layer")
│   ├── config.py              # [REC] SentinelConfig object (doc: modules take config objects, no global env reads)
│   └── integrations/
│       ├── __init__.py
│       ├── langgraph.py       # empty stub in M1
│       └── langchain.py       # empty stub in M1
└── tests/                     # mirrors modules: test_gateway.py, test_identity.py, ...
```

Conventions [DOC]: snake_case modules, CamelCase classes, PEP8, small single-purpose functions, docstrings on all public functions/classes, custom `SentinelError`, no global env reads, no side effects at import time. Each term (SecurityContext, CapabilityEnvelope, …) is documented at its first definition.

---

## 4. Architecture and data flow

### 4.1 Pipeline [DOC]

```
Agent request
  → Gateway (validate, normalize, session)
  → Identity (authenticate, load capability envelope) → SecurityContext
  → Detection (findings, optional risk score)
  → Policy (deterministic decision)
  → Tool Proxy (execute if ALLOW, then output filter)
  → return result to agent
Audit Logger observes every stage.
```

Linear flow, branching at Policy. Detection depends on the SecurityContext, so Identity runs before Detection (the doc's 4.1 "feeds into Identity and Detection" is read as sequential [ASSUMPTION]).

### 4.2 Orchestration contract [REC]

`Pipeline.evaluate_request(raw: dict) -> PipelineResult` where `PipelineResult(request_id, decision, reason, tool_result | None)`.

- `evaluate_request` **does not raise on DENY/REQUIRE_APPROVAL**; it returns the decision. This satisfies the doc's test (`result.decision == "deny"` and tool execution count == 0).
- The framework-facing wrappers built later (`protect`) translate DENY into `ActionDenied` and REQUIRE_APPROVAL into `ApprovalRequired` (both `SentinelError` subclasses) raised to the agent, matching the doc's "returns an error or exception to the agent".
- **Fail closed:** any unexpected exception inside the pipeline is caught at the top level, audited as `INTERNAL_ERROR`, converted to DENY, and never leaks internals or secrets.
- **Audit ordering:** write the DECISION audit event *before* the tool runs; write the outcome event after. If the decision event cannot be written, DENY.

### 4.3 Decision values [DOC/REC]
`ALLOW`, `DENY`, `REQUIRE_APPROVAL`. The doc also mentions `RESTRICT` once ("possibly"); **do not implement in v1** [REC].
`REQUIRE_APPROVAL` in v1: record the decision, do not execute, return it to the caller. No approval workflow [DOC out-of-scope].

---

## 5. Data model

### 5.1 Pydantic objects passed between engines [DOC names; fields are REC unless stated]

```python
class Decision(str, Enum):      ALLOW; DENY; REQUIRE_APPROVAL
class Severity(IntEnum):        LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4     # doc uses "high" and "critical" without defining a scale

class SecurityRequest(BaseModel):   # [DOC] fields: agent_id, session_id, tool, arguments; + request UUID, timestamp
    request_id: str; timestamp: datetime  # UTC, set by Gateway
    agent_id: str; session_id: str
    tool: str; arguments: dict[str, Any]
    auth_token: SecretStr | None = None   # [DOC] "possibly an authentication token"

class ToolGrant(BaseModel):          # [REC] concrete shape for the doc's "(tool, action) pairs + restrictions"
    tool: str
    allowed_path_prefixes: list[str] | None = None   # doc example: "only under /workspace"
    rate_limit: RateLimit | None = None              # doc example: "max 5 deletes per hour"

class RateLimit(BaseModel): max_calls: int; window_seconds: int

class CapabilityEnvelope(BaseModel): agent_id: str; grants: list[ToolGrant]   # [DOC] concept

class SecurityContext(BaseModel):    # [DOC]
    agent_id: str; user_id: str | None
    authorized: bool                 # False if unknown/disabled/bad credential
    envelope: CapabilityEnvelope | None

class SecurityFinding(BaseModel):    # [DOC] type, severity, evidence
    code: str                        # PROMPT_INJECTION | RESTRICTED_PATH | HIGH_RATE | SENSITIVE_DATA
    severity: Severity
    evidence: str                    # MUST be masked of secrets

class SecurityDecision(BaseModel):   # [DOC]
    decision: Decision; reason: str; policy_version: str
    risk_score: float | None = None  # [REC] informational only in v1 (see §6.3)

class ToolSpec(BaseModel):           # [DOC] registry entry: name, implementation, metadata (risk level / arg schema)
    name: str; fn: Callable
    arg_schema: type[BaseModel] | None
    destructive: bool = False        # [REC] drives REQUIRE_APPROVAL
    path_args: list[str] = []        # [REC] names of arguments treated as filesystem paths

class ToolResult(BaseModel): status: Literal["executed","blocked"]; output: Any | None
```

**Reason codes.** [DOC]: `UNAUTHORIZED_AGENT`, `UNAUTHORIZED_TOOL`, `CAPABILITY_EXCEEDED`, `RESTRICTED_PATH`, `PROMPT_INJECTION`, `RATE_LIMIT_EXCEEDED`. [REC] additions: `INVALID_REQUEST`, `INTERNAL_ERROR`. Use `UNAUTHORIZED_TOOL` for "tool not granted" and `CAPABILITY_EXCEEDED` for "tool granted but an argument/limit constraint violated, other than path"; document this split since the doc uses both without distinguishing.

### 5.2 Persisted entities [DOC]
`Agent`, `Policy`, `CapabilityEnvelope`, `Tool`, `AuditEvent` (ORM models in `store.py`).
- `Agent`: agent_id, user_id, name, role/group, credential_hash (nullable), disabled.
- `Policy`: id, version, rules (JSON).
- `CapabilityEnvelope`: agent_id → grants (JSON or child table).
- `Tool`: name + metadata only (risk/destructive, arg schema reference). **Functions live in the in-code `ToolRegistry`, never in the DB** [REC].
- `AuditEvent`: event_id, request_id, agent_id, session_id, timestamp, event_type, tool, arguments (masked), decision, reason, policy_version, outcome, detail (JSON).

The doc refers to an ER diagram that is not included and to a `Request` entity that appears nowhere else. [REC] No separate `Request` table: `AuditEvent` rows keyed by `request_id` carry that information.

[REC] M1 persistence: define ORM models for all five entities, but only `AuditEvent` is written to SQLite. Agents, envelopes, policy, and tools are supplied through in-memory repositories behind repository interfaces (doc build step 4 allows config/test-DB seeding). Session state is an in-memory dict.

### 5.3 Audit event types [REC]
`REQUEST_RECEIVED`, `IDENTITY_RESOLVED`, `FINDING`, `DECISION`, `TOOL_EXECUTED`, `TOOL_BLOCKED`, `OUTPUT_FILTERED`, `ERROR`. Required on every event [DOC]: request ID, agent ID, tool, decision, reason, timestamp.

---

## 6. Engines

### 6.1 Gateway & Session Manager (`gateway.py`)
- **Role [DOC]:** validate and normalize; attach request UUID/timestamp; load session context. Makes **no** security decisions.
- **In:** raw `dict`. **Out:** `SecurityRequest`.
- **Interface [DOC]:** `Gateway.handle(raw_request: dict) -> SecurityRequest`.
- **Logic:** Pydantic validation; reject missing/ill-typed fields with `InvalidRequestError`; confirm the tool name exists in the registry [DOC 4.1] (failure → pipeline records DENY `INVALID_REQUEST`); record the request in the in-memory session store (timestamps per agent/tool, used later for rate limits).
- **Not in v1:** splitting multi-step plans into requests (doc mentions it, defines no mechanism) [ASSUMPTION].

### 6.2 Identity & Access (`identity.py`)
- **Role [DOC]:** authenticate the agent; load its CapabilityEnvelope; set `authorized`.
- **In:** `SecurityRequest`. **Out:** `SecurityContext`.
- **Interface [DOC]:** `authenticate(request) -> SecurityContext`.
- **Logic:** look up agent; unknown or disabled → `authorized=False`. If the agent has a stored credential, require a matching token (compare hashes with `hmac.compare_digest`; never store plaintext) [REC]. If no credential is configured for the agent, identity is by `agent_id` alone (doc: token "if used"). Load the envelope; none → authorized agent with no grants (everything denied).
- **Never** touches tool execution or policy.

### 6.3 Threat Detection (`detector.py`)
- **Role [DOC]:** produce structured findings; no side effects beyond reporting.
- **Interface [REC]:** `analyze(request: SecurityRequest, context: SecurityContext) -> list[SecurityFinding]`. The doc's signature takes only `context`, but its own data-flow and 4.3 say the detector inspects request content; the context alone cannot carry that.
- **Detectors [DOC]:** Prompt-Injection, Tool-Abuse, Behavioral Anomaly, Sensitive-Data.
- **v1 content scope [REC]:** string values in `arguments` (and tool *output* via the proxy's output filter).
- **M1:** `Detector` returns `[]` (stub). Real heuristics arrive in a later milestone (§12).
- Prompt-injection: keyword/pattern rules, optional LLM classifier is **out of v1**.
- Tool-Abuse [REC]: implemented by calling the same pure capability-check helper the policy engine uses, emitting findings for visibility; **the Policy Engine remains the sole authority** for capability decisions and does not depend on this detector.
- Anomaly: simple counters/thresholds over session history; no ML [DOC].
- Sensitive-data: regex patterns (passwords, keys, token shapes, simple PII).
- Evidence strings are masked before storage [DOC: never log secrets].
- **Risk score [REC]:** derive from max severity; log it; Policy does not use it in v1 (the doc computes it but never defines how it influences decisions).

### 6.4 Policy Engine (`policy.py`)
- **Role [DOC]:** deterministic allow/deny/escalate. Same inputs → same output; no randomness.
- **Interface [DOC]:** `evaluate(request, context, findings) -> SecurityDecision`.
- **Config:** `SecurityPolicy(version: str, deny_at_severity: Severity = HIGH, require_approval_for_destructive: bool = True)` loaded from code or simple JSON/YAML [DOC]; no other policy language.

**Evaluation order [REC]** (the doc gives two different orderings in §3 and §4.4; this one makes DENY always beat REQUIRE_APPROVAL):

| # | Check | Result |
|---|---|---|
| 1 | `context.authorized` is false | DENY `UNAUTHORIZED_AGENT` |
| 2 | Tool has no grant in envelope | DENY `UNAUTHORIZED_TOOL` |
| 3 | Grant constraint violated: path outside `allowed_path_prefixes` (canonicalised) | DENY `RESTRICTED_PATH`; other constraints → `CAPABILITY_EXCEEDED` |
| 4 | Any finding with severity ≥ `deny_at_severity` | DENY with the finding's code (e.g. `PROMPT_INJECTION`) |
| 5 | Rate limit exceeded | DENY `RATE_LIMIT_EXCEEDED` *(milestone M4; skipped in M1)* |
| 6 | Tool is `destructive` and policy requires approval | REQUIRE_APPROVAL |
| 7 | Otherwise | ALLOW |

**Default-deny note:** the doc says both "default allow if no rule applies" (§3, 4.4) and "default-deny for any action not explicitly allowed" (§7). Resolved by check #2: ALLOW is only reachable for explicitly granted tools, so the system is default-deny overall.

### 6.5 Tool Proxy & Output Filter (`proxy.py`, `registry.py`)
- **Role [DOC]:** the only component that invokes tools; enforce the decision at the tool boundary.
- **Interface [DOC]:** `execute(request, decision) -> ToolResult`.
- **Registry [DOC]:** all tools registered with name, function, optional metadata; agents can never run arbitrary code.
- **Logic:** DENY/REQUIRE_APPROVAL → return `blocked`, **tool function never called**. ALLOW → resolve registered fn → re-validate args against `arg_schema` and re-check path constraints (**canonicalise with `os.path.realpath` to defeat `..` and symlinks** [REC]) → invoke → output filter → return.
- **Output filter [DOC]:** redact secret patterns, or convert to blocked per policy. Stripping "instruction-like content" is **not implemented in v1** (doc gives no definition) [REC].
- **Timeouts/resource caps [DOC "if configured"]:** not enforced in M1. In-process Python cannot reliably kill a running function; record this in Known limitations [REC].
- **Note [REC]:** output filtering happens *after* execution; it protects what reaches the agent, not side effects of the tool.

### 6.6 Audit Logger & Alerts (`audit.py`)
- **Role [DOC]:** record every request, finding, decision, execution; append-only.
- **Interface [DOC]:** e.g. `log_decision(request_id, decision, reason)`; shared `AuditLogger` used by all stages.
- **Append-only [DOC]:** the repository exposes **insert and read only — no update or delete**.
- **Masking:** a shared `mask_secrets()` applied to arguments/evidence before write.
- **Alerts [DOC]:** `AlertManager` reads the audit stream and logs a warning on repeated high-severity denials; no email/SIEM in v1 [REC].
- Hash-chaining the log for tamper-evidence is a **[REC] later hardening**: the doc says "immutable" but an append-only table alone is not tamper-proof.

### 6.7 Public API (`client.py`)
- **Naming [REC]:** the doc uses both `Sentinel(policy=...)` (§1) and `SentinelClient(policy)` (§5). Use **`SentinelClient`**; update any README/example accordingly.
- **M1 surface:** `SentinelClient(policy, config)`, `.register_tool(...)`, `.register_agent(...)` (test/config seeding), `.evaluate_request(raw) -> PipelineResult`.
- **Later:** `.protect(workflow)` (§12).

---

## 7. Integration points and external dependencies named by the document

| Item | Role | When |
|---|---|---|
| LangGraph | `protect(StateGraph)`; hook on tool-call transitions | Milestone M5 |
| LangChain | wrap `Tool` objects / tool-call callback | Milestone M5 |
| Pydantic | all inter-module contracts | M1 |
| SQLAlchemy + SQLite | persistence | M1 (audit); later others |
| pytest | testing | M1 |
| Policy/capability stores (DB or config) | rules & envelopes | in-memory M1 |
| Session store | counters, history, approvals | in-memory |
| SIEM / email alerts | optional alert sinks | out of v1 |
| Auxiliary LLM classifier | optional injection detection | out of v1 |
| Secrets vault | future secret loading | out of v1 |

**Framework-integration open point [ASSUMPTION/REC]:** the doc has Sentinel *execute* tools from its own registry (proxy) but also *wrap* LangChain tool objects. Decide at M5: the wrapper replaces the tool's callable with one that calls `Pipeline.evaluate_request`, and the original function is registered in the Sentinel registry so the proxy remains the sole executor.

Do not treat the "Sentinel Gateway page" quoted in the source as a dependency; it is an unverified external reference, not part of this design.

---

## 8. Security principles to encode [DOC]
Least privilege (default-deny); deterministic policy; defense in depth (identity → detection → policy → proxy re-validation); immutable, append-only audit; fail with controlled exceptions that never expose secrets; consistent `request_id` on every log line and module call.

---

## 9. Configuration and secrets

- Library modules **do not read environment variables**; everything arrives via `SentinelConfig` and constructor arguments [DOC].
- `SentinelConfig`: `db_url` (default `sqlite:///:memory:`), `policy: SecurityPolicy`, `agents` and `envelopes` seed data (M1), `log_level`.
- **Secrets the project will handle (never hardcoded, never logged):**
  - per-agent credentials/API keys (stored only as hashes);
  - signing key for tokens, *only if* signed tokens are adopted [DOC "if signing tokens"];
  - registry-signing key, *only if* registry signing is adopted [DOC "may use"];
  - database credentials when moving off SQLite;
  - alert destination credentials (future).
- Only the example script and application code read the environment. `.env.example` lists names only (e.g. `SENTINEL_DB_URL`); `.env` is git-ignored [REC].
- Seed secrets in tests are obvious dummies generated in fixtures, not realistic-looking keys.

---

## 10. Testing expectations (pytest; tests ship in the same commit as the code)

| Engine | Required tests |
|---|---|
| **Models** | Validation of required fields/types; enum ordering of `Severity`; secrets (`SecretStr`) don't appear in `repr`/`model_dump_json`. |
| **Gateway** | Valid request normalizes and gets unique `request_id` + UTC timestamp; parametrized invalid inputs (missing field, wrong type, unknown tool) raise `InvalidRequestError`; session store records calls; gateway never returns a decision. |
| **Identity** | Known agent; unknown agent → `authorized=False`; disabled agent; credential present/missing/wrong; envelope loaded; agent with no envelope gets no grants; failures fail closed. |
| **Detector** | M1: stub returns `[]` and conforms to the interface. Later: table-driven positive **and** negative cases per detector; false-positive corpus of benign text; evidence is masked; findings schema contract test. |
| **Policy** | Truth table over every row of §6.4 including precedence (e.g. destructive tool + HIGH finding → DENY, not REQUIRE_APPROVAL); default-deny for ungranted tool; **determinism** (same inputs repeated N times → identical decision); reason codes and `policy_version` populated; no I/O in evaluate. |
| **Tool Proxy / Registry** | **Invariant: DENY ⇒ tool never called** (spy with call counter); REQUIRE_APPROVAL ⇒ not called; ALLOW executes and returns output; unregistered tool rejected; arg schema re-validation; path traversal (`/workspace/../etc/shadow`) and symlink escape denied; output redaction; tool exception handled without leaking details. |
| **Audit** | Every pipeline run produces REQUEST_RECEIVED, DECISION, and outcome events with required fields; DECISION event precedes tool execution; repository has no update/delete; secrets masked in arguments/evidence; all events for a run share one `request_id`. |
| **Pipeline / Client** | End-to-end allow, deny, require-approval, invalid request, unknown agent; injected component failure → DENY `INTERNAL_ERROR` and tool not called; `evaluate_request` does not raise on DENY. |
| **Integrations (later)** | A small LangGraph graph run through `protect()` with an allowed and a denied tool call; confirm denial reaches the agent as `ActionDenied`. |

CI runs ruff + pytest on every push.

---

## 11. Milestone 1 — runnable skeleton, engines stubbed and wired

**Goal:** after M1, `pip install -e ".[dev]"`, `pytest`, and `python examples/quickstart.py` all succeed, and a request travels Gateway → Identity → Detector(stub) → Policy → Proxy → Audit.

**"Stubbed" means** minimal but contract-correct, using the real models and interfaces:
- Gateway: real validation + in-memory session store.
- Identity: real lookup against in-memory agent/envelope repositories.
- Detector: returns `[]`.
- Policy: rows 1–4, 6, 7 of §6.4 (rate limiting deferred).
- Proxy: real registry lookup, arg re-validation, path canonicalisation, execution; output filter pass-through.
- Audit: real SQLite-backed append-only writer.
- Integrations: empty files.

**Commit plan (one commit each, in order):**
1. `chore: scaffold project (pyproject, src layout, README, .gitignore, .env.example)`
2. `ci: add GitHub Actions workflow running ruff and pytest`
3. `chore: add module skeletons and SentinelError hierarchy`
4. `feat(models): add Pydantic models and enums`
5. `feat(store): add ORM models and append-only audit repository`
6. `feat(gateway): validate and normalize requests, in-memory session store`
7. `feat(identity): in-memory agent lookup and capability envelope loading`
8. `feat(policy): deterministic evaluation with default-deny and approval for destructive tools`
9. `feat(proxy): tool registry and execution proxy with path canonicalisation`
10. `feat(audit): AuditLogger with secret masking`
11. `feat(detector): detector interface with empty stub`
12. `feat(pipeline): wire stages with fail-closed handling`
13. `feat(client): SentinelClient facade (register_tool, register_agent, evaluate_request)`
14. `docs(examples): quickstart demonstrating allow, deny, approval, unknown agent`
15. `docs(readme): status table, quickstart, limitations, open decisions`

(README edits also ride along inside each behavior commit per §0.4; commit 15 is the final consolidation pass.)

**M1 acceptance criteria**
- Quickstart shows: allowed `read_file` under `/workspace` executes; `read_file` on `/etc/shadow` or a `..` traversal is denied; ungranted tool denied; unknown agent denied; destructive tool returns REQUIRE_APPROVAL; denied/approval calls leave the tool's call counter at 0; audit rows printed for each.
- `pytest` green; ruff clean; CI green.
- README status table accurate (Detector = `stub`, integrations = `not started`).

---

## 12. Later milestones (from the document's build order)

| Milestone | Content | Doc step |
|---|---|---|
| M2 | Detectors: injection keywords, sensitive-data regex, tool-abuse findings; policy consumes them; anomaly counters if time permits | 9 |
| M3 | Output filter redaction/denial | 10 |
| M4 | Advanced policy: rate limiting, role hierarchy, cross-agent constraints (mechanism for cross-agent undefined: decide before starting) | 11 |
| M5 | `SentinelClient.protect()` for LangGraph, then LangChain; example graph | 12 |
| M6 | Optional audit viewer/dashboard | 13 |

[REC] Do a one-hour **spike of the LangGraph hook before M2** to confirm that tool-call interception is feasible at all, since it is the least-defined and highest-uncertainty piece and is last in the doc's order.

---

## 13. Decision log: recommendations to accept or reject

| # | Decision | Reason |
|---|---|---|
| R1 | Python ≥3.10, Pydantic v2 | 3.9 is EOL |
| R2 | `SentinelClient` is the one public class name | Doc uses two names |
| R3 | `evaluate_request` returns decisions; wrappers raise exceptions | Doc says both "exception" and `result.decision` |
| R4 | Policy order: authz → tool grant → arg constraints → findings → rate limit → approval → allow | Doc has two conflicting orders; DENY must beat approval |
| R5 | Default-deny via explicit-grant check | Doc has "default allow" and "default-deny" |
| R6 | `analyze(request, context)` signature | Doc's signature lacks the content it inspects |
| R7 | Severity enum LOW–CRITICAL; deny at ≥HIGH by default; risk score informational | Doc leaves scale and thresholds undefined |
| R8 | Policy is sole capability authority; detector emits informational findings | Doc scatters checks across detector, policy, proxy |
| R9 | `REQUIRE_APPROVAL` = recorded, not executed; no `RESTRICT` in v1 | Doc: approval out of scope; RESTRICT "possibly" |
| R10 | ToolSpec carries `destructive` and `path_args` | Policy needs to know which args are paths and which tools escalate |
| R11 | Canonicalise paths with `realpath` | Prefix checks alone are bypassable |
| R12 | DECISION audit event written before execution; fail closed | Ordering and failure behavior unspecified |
| R13 | No `Request` table; `AuditEvent` keyed by `request_id`; ER diagram absent from doc | Avoid undefined entity |
| R14 | M1 persists only audit to SQLite; other entities in-memory behind repository interfaces | Smallest runnable skeleton |
| R15 | Layout additions: `pipeline.py`, `registry.py`, `store.py`, `config.py`, `examples/`; `logging.py` → `audit.py` | Doc names components without files; avoids stdlib name clash |
| R16 | ruff + GitHub Actions | Doc requires lint/CI but names no tools |
| R17 | Known limitations stated in README (in-process trust boundary, heuristic detection, invisible LLM context, no timeouts) | Honest scope; doc overpromises ("prevented prompt injections") |
| R18 | LangGraph spike before M2 | De-risk the least-specified integration |
| R19 | Audit hash-chaining as later hardening | "Immutable" needs more than append-only |
