# Open Decisions and Specification Conflicts — Sentinel (AI-DLC Inception)

| | |
|---|---|
| Phase | Inception |
| Date | 2026-10-28 |
| Decision owner | Soham Pasalkar (project owner), for every entry |
| Status | All entries **PENDING OWNER REVIEW** |

> **Phase 1.5 notice (2026-10-28):** the active decision register is now [`decision_record.md`](decision_record.md) §7. This file is kept **unchanged below this notice** as the Inception history, including alternatives later refined or superseded. Where the two differ, `decision_record.md` is authoritative.
>
> | Inception ID | Decision-record ID | What changed in Phase 1.5 |
> |---|---|---|
> | CF-01, CF-02, CF-03, CF-06, CF-10, CF-11, CF-15 | D-24a–h | Unchanged; bundled for confirmation |
> | CF-04, CF-16 | D-06 | Unchanged |
> | CF-05 | D-14 | Single `outcome` enum replaced by separate `execution` / `output_released` / `audit_complete` / `error_code` fields |
> | CF-07 | D-15 | Unchanged (tool metadata passed as `ToolSpec`) |
> | CF-08 | D-07 | `request_id` binding extended to an `AuthorizedAction` with a digest; the proxy executes only `decision.action` |
> | CF-09 | D-03 | Option B refined: the pipeline **returns** an `audit_complete=False` result instead of raising; adapters raise |
> | CF-12 | D-04 | Unchanged; `request_id` added to reserved keys |
> | CF-13 | D-05, D-18 | Canonicalisation moved to the gateway (before policy); proxy re-resolution added; prefixes must exist at registration; hard-link limitation added |
> | CF-14 | D-19 | Unchanged |
> | CF-17 | D-02, D-24i | Unchanged; names remain Pending verification |
> | CF-18 | D-12 | `protect()` replaced by a recommended `wrap_tools()`; experiment specified (E1–E8) |
> | OD-01 | D-09 | Persistence model specified (`audit_events` only) |
> | OD-02 | D-16 | Unchanged |
> | OD-03 | D-10 | Unchanged |
> | OD-04 | D-17 | Unchanged |
> | OD-05 | D-23 | Authoritative location is now `decision_record.md` |
> | OD-06 | D-01 | Unchanged |
> | OD-07 | D-11 | **Recommendation changed:** durable SQLite file by default (was: no default). The Inception option is kept as an alternative |
> | OD-08 | D-20 | Unchanged |
> | OD-09 | D-08 | Open item 4 resolved as a recommendation: `arg_schema` required for every tool |
> | OD-10 | D-21 | Unchanged |
> | OD-11 | D-13 | Unchanged |
> | OD-12 | D-22 | Unchanged |

## How to read this log

- **CF-xx** entries are the 18 conflict areas named in the Inception brief (Workstream D).
- **OD-xx** entries are further decisions found while inspecting the repository.
- **Source tags:** `PDF §x` = the architecture PDF, `Brief §x / Rn` = `SENTINEL_BUILD_BRIEF.md` section or decision-log row, `Diagram` = a file under `docs/architecture/`.
- **Adoptable without approval?** "Yes" means low consequence, consistent with every source, and easy to reverse. Even these are listed so nothing is decided silently. Brief §0 says its `[REC]` items are to be implemented "unless the user rejects" them. This log treats them as **default-adopt, pending confirmation**, not as approved.
- **Blocks** names the first Construction increment (see `implementation_plan.md`) that cannot start reliably until the entry is decided.

## Summary

| ID | Topic | Recommendation (short) | Already resolved by brief? | Owner approval needed? | Blocks |
|---|---|---|---|---|---|
| CF-01 | Default-deny vs default-allow | Default-deny through mandatory explicit grant | Yes (R5) | Confirm | C-08 |
| CF-02 | Explicit grant for every invocation | Yes. Granularity = tool name | Yes (R5, §1) | Confirm | C-08 |
| CF-03 | Precedence of checks | Brief R4 order, with risk score informational | Yes (R4, R7) | Confirm | C-08 |
| CF-04 | DENY vs REQUIRE_APPROVAL | Approval = recorded, never executed. Approval cannot be granted in v1 | Yes (R9) | **Yes**: accept that destructive tools are unusable in v1 | C-08 |
| CF-05 | Structured result vs exception | Pipeline returns a result; adapters raise. Add an `outcome` field | Partly (R3) | Yes (adds a field) | C-03 |
| CF-06 | Detector input contract | `analyze(request, context)`; recurse into nested strings | Yes (R6) | Confirm | C-13 |
| CF-07 | Ownership of authorization | Policy is the sole authority. **Policy also needs tool metadata** | Partly (R8) | **Yes**: interface change | C-03 |
| CF-08 | Registry ↔ proxy ↔ adapter interface | Proxy is internal. Decision is bound to `request_id` | Partly (§7) | **Yes** | C-03 |
| CF-09 | Audit failure before and after execution | Before: DENY. **After: undefined in sources** | Partly (R12) | **Yes** | C-09 |
| CF-10 | Append-only vs tamper-proof | Claim only "append-only through Sentinel's API" | Yes (R19) | Confirm wording | — |
| CF-11 | In-process limits | Document the trust boundary | Yes (R17) | Confirm | — |
| CF-12 | Identity spoofing | Bind `agent_id` in trusted code (adapter), never from LLM output | Partly (§1 limitation) | **Yes** | C-07, C-16 |
| CF-13 | Paths, symlinks, TOCTOU | Canonicalise both sides, check by component, run the tool on the canonical path. **Meaning of `allowed_path_prefixes=None`** | Partly (R11) | **Yes** | C-04 |
| CF-14 | Output-filter mandate and failure | Filter failure → withhold output. Default mode for M3 | Partly (§6.5) | Yes (M3 mode) | C-10 (failure path), C-14 |
| CF-15 | Limits of heuristic injection detection | Advisory signal only; never a security guarantee | Yes (§1) | Confirm | — |
| CF-16 | Destructive tools | Make `destructive` a **required** registration argument | Partly (R10) | **Yes** | C-05 |
| CF-17 | Naming and signature consistency | `SentinelClient`, `audit.py`; **verify the PyPI and import names** | Partly (R2, R15) | **Yes** (distribution/import name) | C-01 |
| CF-18 | LangGraph/LangChain interception feasibility | Spike at C-02. Callbacks cannot enforce. Scope `protect()` to tool execution | Partly (R18) | **Yes** (scope of `protect`) | C-02 result → C-16 |
| OD-01 | ER diagram vs brief persistence model | AuditEvent per the brief; persist only that table in M1 | No (R13's premise is stale) | **Yes** | C-09 |
| OD-02 | Orchestrator: Pipeline or Gateway | `Pipeline` (brief) | Brief yes, diagrams no | Yes | C-11 |
| OD-03 | Scope of the September diagrams (delegation, provenance, risk engine…) | Out of v1 | No | **Yes** | — |
| OD-04 | Audit retrieval API | Minimal read API on the client | No | Yes | C-12 |
| OD-05 | Where open decisions live | This file is authoritative; README links to it | No | Yes | C-01 |
| OD-06 | Python version floor | `>=3.11` (3.10 reaches EOL in Oct 2026) | Brief says ≥3.10 | **Yes** | C-01 |
| OD-07 | Default audit database | No silent in-memory default for production use | Brief: `sqlite:///:memory:` | **Yes** | C-09 |
| OD-08 | Concurrency and thread safety | Pipeline is thread-safe for sync calls; async fails closed | No | Yes | C-09, C-11 |
| OD-09 | Argument-schema requirement and coercion | Validate once (strict); execute exactly the validated args | No | **Yes** | C-03, C-06 |
| OD-10 | Supported operating systems | Linux and macOS; Windows unsupported for path enforcement in v1 | No | Yes | C-04 |
| OD-11 | Commit / push authority in Construction | Local commit per increment after its gate passes; push only on request | Brief §0.3 | **Yes** | C-01 |
| OD-12 | Development-only dependencies | ruff, pytest, pytest-cov, mypy. Hypothesis optional | Partly (R16) | Yes | C-01 |

---

## Specification conflicts (CF-01 … CF-18)

### CF-01 — Default-deny versus default-allow

- **Statements:** PDF §4.4 "Default Allow: If none of the above apply, return ALLOW." PDF §7 "Least Privilege: Default-deny for any action not explicitly allowed."
- **Resolution in brief:** R5. The tool-grant check (policy row 2) runs before the final ALLOW, so ALLOW is reachable only for explicitly granted tools.
- **Consequence if unresolved:** an implementer following PDF §4.4 alone could allow ungranted tools.
- **Recommendation:** adopt R5. Add one rule: if a policy configuration cannot be loaded or is invalid, the pipeline denies (fails closed); it must not fall back to a permissive default.
- **Security implications:** this is the foundation of least privilege. SEC-001 tests it.
- **Adoptable without approval?** Yes (consistent with PDF §7, the core invariant and the brief). Listed for confirmation.

### CF-02 — Explicit capability grant for every invocation

- **Statements:** PDF §5 "an Agent ID must map to a capability set that lists all allowed (tool, action) pairs". Brief §1 [ASSUMPTION] "action granularity = tool name". The SVG diagram shows separate tool / operation / resource / target / params checks.
- **Resolution in brief:** grant per tool name (`ToolGrant.tool`), with optional path and rate constraints.
- **Consequence if unresolved:** a tool such as `db(op="delete")` that multiplexes several operations could not be restricted per operation.
- **Recommendation:** adopt tool-name granularity for v1. Register multiplexing tools as separate tools (`db_read`, `db_delete`). Record the absence of sub-action grants as a known limitation.
- **Security implications:** a tool that exposes several operations behind one name is granted all or nothing. Mitigate through registration guidance.
- **Adoptable without approval?** Yes (brief assumption, smallest option). Confirm.

### CF-03 — Ordering and precedence of authorization, findings, policy and approval

- **Statements:** PDF §3 order: authorized → tool allowed → special rules (destructive → approval) → severity → ALLOW. PDF §4.4 order: hard constraints → destructive → findings → rate → default allow. The two orders put approval *before* findings, so a destructive call carrying a HIGH injection finding could get REQUIRE_APPROVAL instead of DENY. Severity threshold: PDF §3 says "critical", PDF §4.4 says "high". Sequence diagram: policy consumes a "risk score".
- **Resolution in brief:** R4 order (authz → grant → constraints → findings ≥ `deny_at_severity` (default HIGH) → rate → destructive approval → ALLOW). R7: risk score is informational.
- **Recommendation:** adopt R4 and R7, with three precisions:
  1. Evaluation stops at the first matching row, and the reported reason is that row's code. With several findings, the reason is the code of the highest-severity finding; ties are broken by finding-code order, so the result stays deterministic.
  2. `policy_version` and an ordered list of finding codes are recorded on every decision.
  3. Inputs to `evaluate` are immutable values. Anything time-dependent (rate limits in M4) arrives as an explicit snapshot or clock argument, so determinism is testable.
- **Security implications:** DENY always takes precedence over REQUIRE_APPROVAL. A HIGH finding can never be "escalated" into an approval prompt.
- **Adoptable without approval?** Yes for R4 and R7. The tie-break rule is new but harmless. Confirm.

### CF-04 — DENY versus REQUIRE_APPROVAL

- **Statements:** PDF §4.4 destructive → REQUIRE_APPROVAL. PDF §7 human-in-the-loop out of scope ("just record"). Brief R9: recorded, not executed, no RESTRICT.
- **Consequence:** in v1, **a REQUIRE_APPROVAL call can never be executed**, because no mechanism exists to grant approval. With `require_approval_for_destructive=True` (the default), every destructive tool is unusable. Retries are each recorded as new REQUIRE_APPROVAL decisions.
- **Recommendation:** adopt R9. State in the README that destructive tools are blocked by default in v1 and become callable only if the owner sets `require_approval_for_destructive=False`, which turns them into normal granted tools. Do **not** add any "approve and replay" path in v1. To callers, REQUIRE_APPROVAL behaves like DENY, but it keeps a distinct decision value and a distinct exception (`ApprovalRequired`).
- **Security implications:** fail-safe. REQUIRE_APPROVAL ⇒ no execution (SEC-003).
- **Adoptable without approval?** **No.** The owner should explicitly accept that destructive tools are unusable in v1 by default.

### CF-05 — Structured result versus exception on denial

- **Statements:** PDF §3 "returns an error or exception back to the agent". PDF §6 test `result.decision == "deny"`. Brief R3: `evaluate_request` returns, adapters raise `ActionDenied` / `ApprovalRequired`.
- **Gap found:** `PipelineResult(request_id, decision, reason, tool_result)` cannot express "the decision was ALLOW and the tool ran, but the output was withheld (filter failure) or the outcome could not be audited". Brief §4.2 converts *any* unexpected exception to DENY `INTERNAL_ERROR`. That misreports a failure *after* the tool ran: the caller would believe no side effect happened.
- **Recommendation:** adopt R3. Add `outcome: Literal["not_executed", "executed", "executed_output_withheld", "tool_error"]` (exact names to be settled at C-03) to `PipelineResult`, and add `"error"` to `ToolResult.status`. Fail-closed conversion to DENY applies only to failures **before** execution. After execution, the result reports that the tool ran.
- **Security implications:** keeps the decision consistent with actual execution (SEC-010). Without this, the audit trail and the caller can disagree about whether side effects occurred.
- **Adoptable without approval?** No (public result-shape change). Low risk.

### CF-06 — Detector input contract

- **Statements:** PDF §5 `analyze(context)`. PDF §3/§4.3 say the detector inspects request content. Brief R6 `analyze(request, context)`.
- **Recommendation:** adopt R6. Also: (a) scan string values **recursively** through dicts, lists and tuples in `arguments`, not only top-level strings. (b) A detector exception is a security-critical failure and leads to DENY `INTERNAL_ERROR` (fail closed). (c) Detectors are pure, with no I/O, so policy stays deterministic for given findings.
- **Security implications:** nested arguments are a trivial evasion of top-level-only scanning.
- **Adoptable without approval?** Yes (R6 plus hardening). Confirm.

### CF-07 — Ownership of authorization checks across identity, policy, detector and proxy

- **Statements:** PDF §3 has the detector check path prefixes; PDF §4.3 has the Tool-Abuse detector check capabilities; PDF §4.4 has the policy check allowed tools; PDF §4.5 has the proxy re-validate. Brief R8: policy is the sole authority, and the detector emits informational findings by calling the same helper.
- **Gap found (missing contract):** policy row 3 (path constraints) and row 6 (destructive) need `ToolSpec.path_args` and `ToolSpec.destructive`. But `evaluate(request, context, findings)` receives no tool metadata, and `SecurityRequest` carries none. As written, the policy engine cannot implement rows 3 and 6 without reaching into the registry, which is hidden coupling and I/O inside `evaluate`.
- **Recommendation:**
  1. Policy is the single authority for ALLOW, DENY and REQUIRE_APPROVAL. Identity only resolves facts (`authorized`, envelope). It never decides.
  2. Pass the tool's immutable `ToolSpec` metadata (name, `destructive`, `path_args`, `arg_schema`; **no callable**: the registry holds the callable beside the spec) into `evaluate(request, context, findings, tool_spec)`. Equivalently, the gateway attaches it to the request. Recommend the explicit parameter.
  3. **Defer the Tool-Abuse detector.** It duplicates policy rows 2–3 and adds nothing to enforcement. If wanted later for visibility, it is derived from the policy result rather than re-implemented.
  4. The proxy re-check is defence in depth. It must call the **same** pure path-containment function as policy, so the two cannot drift apart. If the proxy re-check fails after policy said ALLOW, that indicates a bug or tampering: block, and audit as `ERROR`.
- **Security implications:** one owner per check. The proxy re-check is a safety net, not a second policy.
- **Adoptable without approval?** **No**: it changes the PDF/brief `evaluate` signature and drops a PDF-named detector from v1.

### CF-08 — Interface between tool registry, execution proxy and framework adapters

- **Statements:** PDF §5 `ToolProxy.execute(request, decision) -> ToolResult`. Brief §7 says the adapter replaces the tool's callable and registers the original function in the Sentinel registry. That decision is deferred to M5.
- **Gap found:** `execute(request, decision)` accepts a caller-constructed decision. Any code holding the proxy can call `execute(req, SecurityDecision(decision=ALLOW, …))` and skip policy. `SecurityDecision` also carries no `request_id`, so a decision for request A could be replayed against request B.
- **Recommendation:**
  1. Add `request_id` to `SecurityDecision`. The proxy refuses to execute (status `blocked`, audit `ERROR`) unless `decision.request_id == request.request_id` and `decision.decision is Decision.ALLOW`, compared by identity or equality, never by truthiness.
  2. The proxy is an **internal** component: not exported from `sentinel/__init__.py`, constructed only by `Pipeline`. The public path to execution is `SentinelClient.evaluate_request` (and later `protect`).
  3. Tool names in the registry are unique. Re-registering a name raises an error (no silent replacement).
  4. Adapters never call tool functions themselves. They call the pipeline, and the pipeline's proxy is the only code path that invokes a registered function.
  5. Be honest about the limit: in-process Python cannot make these objects unforgeable (CF-11). These measures stop *accidental* bypass and LLM-driven bypass; they cannot stop deliberately malicious in-process code.
- **Security implications:** keeps the decision bound to execution (SEC-010) and narrows the bypass surface (T-11).
- **Adoptable without approval?** **No** (model and public-surface changes).

### CF-09 — Audit persistence failure before and after execution

- **Statements:** PDF: every decision is audited, the log is immutable. Diagrams: audit is written **after** execution. Brief R12: the DECISION event is written before execution; if it cannot be written, DENY.
- **Undefined in every source:** what happens when an audit write fails **after** the tool has executed (TOOL_EXECUTED / OUTPUT_FILTERED). The side effect has already happened and cannot be undone.
- **Options for post-execution audit failure:**
  - (A) Return the output normally and report the audit failure through the Python `logging` module and a flag on the result.
  - (B) **Withhold the output** (`outcome="executed_output_withheld"`), raise `AuditUnavailable` to the caller with an explicit statement that the tool executed, and make a best-effort fallback record (e.g. stderr logger).
  - (C) Wrap each tool call in a transaction. Not possible in general for arbitrary side effects.
- **Recommendation:** pre-execution: **any** audit write failure before execution (REQUEST_RECEIVED, IDENTITY_RESOLVED, FINDING, DECISION) ⇒ the tool is not invoked. The decision event must be **committed**, not merely flushed, before execution. Post-execution: option **B**. Unaudited data does not reach the agent, and the caller is told plainly that side effects may have occurred. Failure to audit a DENY must not turn into an ALLOW (deny stays deny); the caller is notified.
- **Security implications:** SEC-005, SEC-006. Option A favours availability over auditability; B favours auditability.
- **Adoptable without approval?** Pre-execution half: yes (R12). Post-execution half: **No**, owner decision.

### CF-10 — Append-only versus tamper-proof audit

- **Statements:** PDF "immutable", "no one should tamper with old logs". Brief: the repository exposes insert/read only. Hash-chaining is deferred (R19).
- **Recommendation:** v1 documentation says **"append-only through Sentinel's API"** and never "immutable" or "tamper-proof". Anyone with file access to the SQLite file, or in-process access to the SQLAlchemy engine, can alter rows. Hash-chaining (tamper-*evidence*) stays a post-v1 hardening option.
- **Security implications:** avoids an unsupported security claim (T-08).
- **Adoptable without approval?** Yes (R19 plus wording). Confirm.

### CF-11 — Security limitations of an in-process Python library

- **Statements:** Brief §1 limitations and R17. The PDF claims Sentinel "would have already prevented … prompt injections", which overpromises.
- **Recommendation:** adopt R17. The trust boundary is defined in `architecture_assessment.md` §5. The README must state: Sentinel constrains tool calls routed through it; code running in the same process can bypass it, monkey-patch it, or call tool functions directly; detection is heuristic; Sentinel cannot see the LLM context; there are no execution timeouts.
- **Adoptable without approval?** Yes. Confirm.

### CF-12 — Identity spoofing with a caller-supplied `agent_id`

- **Statements:** Brief §6.2: token compared with `hmac.compare_digest` if a credential is configured; otherwise identity is the `agent_id` alone. Brief §1: "`agent_id` is caller-asserted unless a token is verified".
- **Analysis:** the realistic attacker is the **LLM**, steered by injected content, not the developer's code. If the `agent_id` that reaches Sentinel can be influenced by model output (for example, a tool-call argument or a state field the model writes), a low-privilege agent can claim a high-privilege identity. A token held in the same process does not help against malicious in-process code (CF-11), but it does help if `agent_id` leaks into model-controlled data.
- **Recommendation:**
  1. Primary control: **identity is bound by trusted code at wrap time.** Example: `protect(tool_node, agent_id="research_agent")` or an equivalent per-agent binding. The adapter never reads `agent_id` from tool-call arguments or LLM-generated content.
  2. `SecurityRequest` rejects an `agent_id` or `session_id` key appearing inside `arguments` (or the adapter strips it), so a model cannot smuggle one in.
  3. Credentials stay optional in v1 (PDF "if used"). Add a `SecurityPolicy`/config flag `require_credentials` (default `False` in v1) for deployments that want it.
  4. Raw tokens are never logged; the `SecretStr` repr is masked.
- **Security implications:** T-03. Without (1), capability envelopes provide no isolation between agents.
- **Adoptable without approval?** **No**: binding semantics shape the adapter API.

### CF-13 — Path traversal, symbolic links and filesystem boundaries

- **Statements:** PDF example "only under /workspace". Brief R11: canonicalise with `os.path.realpath`; R10: `path_args` on the ToolSpec.
- **Gaps found:**
  1. A plain string-prefix check is wrong: `/workspace2/x` "starts with" `/workspace`. Containment must be compared **by path component**, e.g. `Path(resolved).is_relative_to(Path(prefix_resolved))`.
  2. **Allowed prefixes must be canonicalised too.** On macOS `/tmp` resolves to `/private/tmp` (OBSERVED in this session), so a policy prefix `/tmp/work` would never match a resolved request path. That is safe (it fails closed) but makes the feature unusable, and a naive fix (skipping resolution) would be unsafe.
  3. **TOCTOU:** after `realpath` is checked, a path component can be swapped for a symlink before the tool opens it, by another process or by another tool call running concurrently. Mitigation in v1: the proxy passes the **canonical resolved path** to the tool, not the original string. Residual risk: swaps between resolution and `open()` remain possible. Kernel-level containment (`openat2(RESOLVE_BENEATH)`, Linux only) is out of v1.
  4. Passing the canonical path also defeats the tool calling `os.path.expanduser`, URL-decoding, or otherwise re-interpreting a string the policy evaluated differently.
  5. **`allowed_path_prefixes=None` is ambiguous.** Does it mean "unrestricted filesystem" or "no paths allowed"? Under default-deny, the brief's `None` default would give a granted file tool **unrestricted** filesystem access.
  6. Only **top-level** argument names listed in `path_args` are checked. Paths nested in lists or dicts, and paths the tool derives internally, are not.
  7. Relative paths resolve against the process working directory, which is environment-dependent.
  8. Case-insensitive filesystems (macOS default APFS) can make a correct path fail to match a prefix of different case. That fails closed.
- **Recommendation:** (1)–(4) as mandatory requirements (SEC-007). For (5): **a grant for a tool that declares `path_args` must specify `allowed_path_prefixes`; `None` or empty ⇒ DENY `RESTRICTED_PATH`.** Unrestricted access requires an explicit `["/"]`. For (6): `path_args` supports only top-level string arguments in v1; a tool with nested path structures must not be registered with filesystem access (document it). For (7): reject relative paths (`INVALID_REQUEST`), or resolve them against an explicit base directory. Recommend rejecting. (8): document.
- **Security implications:** T-06 and T-07. These checks are deterministic and testable.
- **Adoptable without approval?** Items 1–4, 6–8: yes (hardening of R11). **Item 5 and the relative-path choice: owner decision.**

### CF-14 — Whether output filtering is mandatory, and its failure behaviour

- **Statements:** PDF §4.5: redact, or convert to DENY "in extreme cases"; strip instruction-like content. Brief: M1 pass-through, M3 redaction; "strip instruction-like content" is not in v1.
- **Recommendation:**
  1. The output-filter **stage** is mandatory on every executed call from M1, even while it is a pass-through, so the failure path exists and is tested from the start.
  2. If the filter raises, the output is **withheld** (`outcome="executed_output_withheld"`), audited as `ERROR`, and never returned raw.
  3. M3 filters `str`, and recursively `dict`/`list`/`tuple` of `str`. For outputs of other types (bytes, custom objects), withhold in `enforce` mode, owner-configurable.
  4. The M3 default mode (`redact` vs `block` on secret detection) is an owner decision. Recommend `redact`.
  5. The README states that output filtering cannot undo tool side effects; it limits what reaches the agent.
- **Security implications:** T-05. A filter that fails open would leak exactly what it exists to catch.
- **Adoptable without approval?** Items 1–2: yes (fail-closed, consistent with the PDF). Items 3–4: owner decision before M3.

### CF-15 — Limits of heuristic prompt-injection detection

- **Statements:** PDF §1 claims prevention. Brief §1 says it is heuristic.
- **Analysis:** keyword and regex rules are trivially evaded (paraphrase, encoding, other languages, splitting across arguments) and produce false positives on benign security-related text. The PDF's own example threat (an instruction hidden in a retrieved document) arrives through **tool output or LLM context**, which v1 does not scan for injection at all.
- **Recommendation:** classify injection detection as **advisory, defence-in-depth**. The real control against injection consequences is the **capability envelope**: an injected agent can still do only what it was granted. The README and requirements never describe detection as preventing injection. M2 must ship with a benign false-positive corpus and with measured detection and false-positive counts. No claimed rates.
- **Adoptable without approval?** Yes. Confirm.

### CF-16 — Handling of destructive tools

- **Statements:** PDF: "destructive actions (like deleting a database) may always require human approval". Brief R10: `ToolSpec.destructive: bool = False`.
- **Analysis:** whether a tool counts as destructive is declared by the developer at registration. With a `False` default, forgetting the flag silently turns a delete tool into a normal ALLOW. That is a fail-open default on the one control that guards the highest-impact actions.
- **Recommendation:** make `destructive` a **required keyword argument** of `register_tool` (no default), so every registration makes a conscious choice. Alternative: default `True` (fail-safe, but noisy). Combined with CF-04: in v1, destructive tools are blocked unless the owner disables approval.
- **Adoptable without approval?** **No** (public API ergonomics).

### CF-17 — Consistency of package names, import names, class names, signatures and examples

| Item | Variants found | Recommendation | Status |
|---|---|---|---|
| Main class | `Sentinel(policy=…)` (PDF §1); `SentinelClient(policy)` (PDF §5) | `SentinelClient` | Brief R2 — confirm |
| Audit module | `logging.py` (PDF) | `audit.py` (avoids confusion with stdlib `logging`) | Brief R15 — confirm |
| Gateway method | `Gateway.handle()` (PDF §5); `handleRequest()` (class diagram) | `handle()` | Adopt |
| Audit method | `AuditLogger.log_decision(...)` (PDF); `log()` (class diagram) | Typed methods per event type behind one `record(event)` | Adopt at C-09 |
| Detector signature | `analyze(context)` (PDF) | `analyze(request, context)` | CF-06 |
| Policy signature | `evaluate(request, context, findings)` | `+ tool_spec: ToolSpec` (metadata only) | CF-07 (approval) |
| `SecurityDecision` fields | decision, reason, policy_version | `+ request_id`, `+ finding_codes` | CF-08 (approval) |
| `ToolResult.status` | executed / blocked | `+ error` | CF-05 (approval) |
| Decision values in tests | `"deny"` (PDF test) vs enum `DENY` | Define `Decision(str, Enum)` with lowercase values `"allow"`/`"deny"`/`"require_approval"` so the PDF test reads literally; names stay upper-case | Adopt (cosmetic) |
| Reason vs finding codes | `RESTRICTED_PATH` is both a finding code and a policy reason | Allowed: a policy reason may equal the triggering finding code. Document it | Adopt |
| Distribution name | `sentinel-ai` | **Availability on PyPI not verified** (no network checks in this phase). Verify before C-01 so `pyproject.toml` is right first time; never publish without the owner's approval | **Owner** |
| Import name | `sentinel` | **INFERRED risk:** a short generic name like `sentinel` may already be used by another PyPI distribution, which would make the two packages clash in one environment. Not verified. Options: keep `sentinel`, or choose a distinctive import name such as `sentinel_ai`. Renaming later touches every file | **Owner** |
| Product name | "Sentinel" | Generic name shared by other security products (e.g. Microsoft Sentinel). Not a technical blocker; note for publishing | Owner (informational) |
| Python version | 3.9+ (PDF); ≥3.10 (brief) | See OD-06 | **Owner** |

### CF-18 — Compatibility and interception feasibility for LangGraph and LangChain

- **Statements:** PDF §5 suggests `protect(StateGraph)`, "inject a sentinel node on every tool-call transition", wrap LangChain `Tool` objects, or "hook into LangChain's callback for tool calls". Brief §7/§12: decide at M5; spike before M2 (R18).
- **Analysis (from general framework knowledge; NOT verified in this session, no packages installed or docs fetched):**
  1. **Callbacks are observational.** `on_tool_start` handlers are designed for tracing. Whether an exception raised in a handler reliably stops the tool depends on handler configuration (e.g. `raise_error`) and framework version. That is not a trustworthy enforcement point. **Recommend: never use callbacks as the enforcement mechanism.**
  2. **Wrapping an entire compiled `StateGraph` generically is not feasible.** Graph nodes are arbitrary Python callables, and a node can call a tool function directly. Sentinel can only enforce on tool calls that go through a component it controls (a tool node, or tool objects it wrapped). `protect(graph)` would therefore promise more than it can deliver.
  3. **Feasible pattern (hypothesis to verify):** wrap each tool object (or the tool-execution node) so its execution entry point calls `Pipeline.evaluate_request`. The original function is moved into Sentinel's registry, so the proxy remains the only executor. Recent LangChain/LangGraph releases may offer an official tool-call wrapping or middleware hook. **Unverified; the spike must check the installed version.**
  4. Framework tool execution can be **async** (`ainvoke`) and **parallel** (several tool calls in one step). The brief defers async APIs. An adapter that wraps only the sync path could let async calls through unguarded. **Recommend: until async is supported, the wrapped tool's async entry point fails closed (raises), never calls the original.**
  5. A denial must surface to the model as a tool error message, so the agent loop continues, or as an exception that halts the graph. That is a product choice; the spike should show both.
- **Recommendation:** move the spike to **C-02** (immediately after scaffold, before engine work), timeboxed, throwaway code outside `src/`. Scope `protect()` in requirements to "tool calls executed through Sentinel-wrapped tools or tool nodes" and drop the claim to protect "every invocation of the workflow".
- **Security implications:** if interception is infeasible or bypassable, the core product promise fails for framework users. Discovering that at M5 would invalidate earlier design work.
- **Adoptable without approval?** **No.** Narrowing the `protect()` promise is a scope decision.

---

## Additional decisions (OD-01 … OD-12)

### OD-01 — ER diagram versus the brief's persistence model

- **Statements:** Brief R13: "ER diagram absent from doc", no `Request` table, `AuditEvent` keyed by `request_id`. Repository: `EntityRelationshipDaigram.png` (2026-10-26) **exists**, with USER, AGENT, POLICY, CAPABILITY_ENVELOPE, TOOL, REQUEST, DECISION, ALERT and **no AuditEvent**.
- **Consequence:** two incompatible schemas. The ER diagram also lacks any event-history entity, which the audit requirements need.
- **Recommendation:** keep the brief's model for v1: an append-only `AuditEvent` stream keyed by `request_id`. "Request" and "Decision" in the ER diagram are *views* over audit events (REQUEST_RECEIVED, DECISION). For M1, define and persist **only the `AuditEvent` table**. Brief R14 also defines ORM models for four unused entities; recommend deferring those until a milestone needs them (avoids dead schema). The owner may want to update the ER diagram later. Inception does not modify original diagrams.
- **Adoptable without approval?** **No** (conflicts with the owner's most recent diagram).

### OD-02 — Orchestrator: `Pipeline` or `Gateway`

- **Statements:** Class and sequence diagrams: `Gateway.handleRequest()` calls every module. Brief §4.2/§6.1: `Pipeline` orchestrates; Gateway only validates.
- **Recommendation:** `Pipeline` (brief). Keeping validation separate from orchestration gives the enforcement path one owner that is easy to review. The diagrams' "Gateway" can be read as the Sentinel boundary as a whole.
- **Adoptable without approval?** Yes in substance (brief R15). Listed because it contradicts the owner's diagrams.

### OD-03 — Scope of the September diagrams

- **Statements:** `AI Agent Data Security` and `Core Security Pipeline` diagrams: provenance tagging, RAG trust defense, quarantine, agent-delegation validation, privilege-drift checks, live execution graph, cross-domain risk engine with CONFIRM, scoped credentials, security dashboard. None of these is in the PDF's v1 scope or the brief.
- **Recommendation:** treat them as **long-term vision, out of v1**. `requirements.md` lists them under "Out of scope (v1)". Multi-agent delegation is the most relevant omission for a "multi-agent" product. Record it as the first post-v1 candidate.
- **Adoptable without approval?** **No**: scope confirmation.

### OD-04 — Audit retrieval API

- **Statements:** Use-case diagram: Auditor → View Audit Logs. PDF: logs "can be exported or monitored". Brief M1 API: no read method.
- **Recommendation:** add a minimal read-only `SentinelClient.audit_events(request_id: str | None = None, limit: int = …) -> list[AuditEvent]`. Tests need it anyway, and it matches the use case. No export formats or query language in v1.
- **Adoptable without approval?** No (new public API), low risk.

### OD-05 — Location of the authoritative decision log

- **Recommendation:** this file is authoritative during AI-DLC. The README's "Open decisions" section (brief §0.4) contains short summaries that link here, so the two cannot diverge.
- **Adoptable without approval?** Yes. Confirm.

### OD-06 — Python version floor

- **Statements:** PDF 3.9+; brief ≥3.10, tested on 3.11 and 3.12.
- **Analysis:** under the CPython 5-year support policy (PEP 619), 3.10 reaches end of life in October 2026, the current month. (INFERRED from the published schedule; confirm on python.org.) The brief's own reasoning for dropping 3.9 now applies to 3.10. Locally available: 3.11 and 3.12 (OBSERVED). LangGraph/LangChain minimums are not verified.
- **Recommendation:** `requires-python = ">=3.11"`; CI matrix 3.11, 3.12, 3.13. Revisit if the spike shows a framework constraint.
- **Adoptable without approval?** **No** (changes brief R1).

### OD-07 — Default audit database

- **Statements:** Brief §9 `db_url` default `sqlite:///:memory:`.
- **Analysis:** an in-memory default means audit records **silently disappear** at process exit, which contradicts the "audit trail" promise. With SQLAlchemy, `:memory:` databases are per connection unless a static pool is used, so multi-threaded use (OD-08) can lose rows or fail.
- **Recommendation:** `SentinelConfig` has **no default** `db_url` (explicit is required). An explicit helper (`SentinelConfig.for_testing()` or `db_url="sqlite:///:memory:"`) is documented as non-persistent. The quickstart uses a file path inside a temporary or example directory, and `*.db` is git-ignored.
- **Adoptable without approval?** **No** (API ergonomics; changes the brief).

### OD-08 — Concurrency and thread safety

- **Analysis:** frameworks may execute several tool calls concurrently in threads (to be confirmed in the C-02 spike). Shared state: session store (per-agent history, later rate limits), the SQLAlchemy engine/session, and the registry.
- **Recommendation:** v1 guarantees **thread-safe synchronous** use. Locks protect the session store; each pipeline run uses its own SQLAlchemy session (or a lock around writes); the registry is read-only once the pipeline is constructed. Rate-limit check-and-record is atomic, under one lock (M4). Async is not supported, and async entry points fail closed (CF-18). A multi-process deployment is out of scope (PDF §7), and per-process rate limits are documented.
- **Adoptable without approval?** Yes in substance. Confirm.

### OD-09 — Argument schema requirement and coercion

- **Analysis:** Brief: `arg_schema` is optional and re-validated in the proxy. Two problems:
  - (a) A tool without a schema has **unvalidated** arguments.
  - (b) Pydantic's default (lax) validation **coerces** values. If the policy evaluates the raw arguments but the proxy executes the coerced ones, the executed call differs from the evaluated call (a check/use mismatch).
- **Recommendation:**
  1. Validate arguments against `arg_schema` **once, before policy** (in the gateway stage), in **strict** mode.
  2. Policy, detector and proxy all see the same frozen, validated arguments.
  3. The proxy executes exactly those arguments (path arguments replaced by their canonical form, CF-13), and its re-validation only asserts that they are unchanged.
  4. `arg_schema` is **required** for any tool that declares `path_args`, and **recommended** for all tools. Owner decision: require it for all?
  5. Pydantic validation error messages include input values by default and must never be passed into exceptions or audit text unsanitised (SEC-008).
- **Adoptable without approval?** Items 1–3 and 5: yes (hardening). Item 4: **owner decision.**

### OD-10 — Supported operating systems

- **Recommendation:** support Linux and macOS (POSIX path semantics) in v1. Windows is untested and path enforcement there is unsupported (drive letters, UNC paths, junctions, case-insensitivity). Sentinel should raise if path-constrained tools are registered on Windows rather than enforce incorrectly. CI runs on `ubuntu-latest`; adding `macos-latest` is recommended because of the `/private` symlink behaviour.
- **Adoptable without approval?** No (portability scope), low risk.

### OD-11 — Commit and push authority during Construction

- **Statements:** Brief §0.3: small conventional commits, the first is the scaffold, push once the remote is provided. This Inception phase: no commits. A remote already exists (OBSERVED).
- **Recommendation:** in Construction, Claude makes **one local commit per increment, only after that increment's test gate passes**, using the brief's message convention, after the owner approves Construction. **No push** until the owner explicitly requests one. Before the first commit, add `.gitignore` so `.DS_Store` is excluded. Original design documents (brief, `docs/architecture/`) are committed as-is in their own `docs:` commit if the owner wants them versioned.
- **Adoptable without approval?** **No.**

### OD-12 — Development-only dependencies

- **Recommendation:** `pytest`, `pytest-cov` (branch coverage on security-critical modules), `ruff` (lint + format), `mypy` (type checking on `src/`; the security contracts rely on precise types). Optional: `hypothesis` for property tests of path containment (high value for a small cost). Build backend: `hatchling` or `setuptools`; either is fine, recommend `hatchling` for minimal config. Framework packages go only under an optional extra (`[langgraph]`), never in core dependencies.
- **Adoptable without approval?** Yes for pytest/ruff (brief). mypy, pytest-cov and hypothesis are new. Confirm.
