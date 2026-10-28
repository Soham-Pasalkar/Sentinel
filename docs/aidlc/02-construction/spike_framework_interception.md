# C-02 Report: LangGraph Tool-Interception Feasibility Experiment

| | |
|---|---|
| Increment | C-02 (isolated, disposable experiment; no production code) |
| Date | 2026-10-28 |
| Status | **Experiment complete. Owner review required before any decision below is adopted.** |
| Verdict | **E1 and E2 pass. Denied and approval-required calls did not execute on any intercepted path tested, and authorized calls executed exactly once. The stop condition was not triggered.** |
| Not covered | Full-graph protection is **not** claimed and was **not** demonstrated. See §8. |

Labels: **OBSERVED** = measured in this experiment (evidence in `spikes/langgraph_interception/results/`). **RECOMMENDATION** = my proposal. **UNRESOLVED** = not tested or not known.

> **Rev. 2 update (2026-10-28, after owner review):** the findings below are unchanged. The owner approved the proposed changes as D-12 (expanded), D-14 amendment, D-25, D-26, D-27 and D-28; see `decision_record.md` §0.4 and §12. The `# ruff: noqa` headers mentioned below were replaced by a `spikes` Ruff exclusion in `pyproject.toml` (D-28). This report remains the evidence record.

---

## 1. Summary

1. **OBSERVED:** LangGraph (`langgraph` 1.2.18) executes tools through `ToolNode`, which has an official interception hook (`wrap_tool_call` / `awrap_tool_call`). I tested two integration shapes against real `StateGraph` + `ToolNode` execution:
   - **Design A, hook:** Sentinel evaluates inside the hook, and the *framework* then runs the function.
   - **Design B, replacement tools:** `wrap_tools` returns new tool objects whose function calls Sentinel, and Sentinel's proxy is the *only* caller of the original function.
2. **OBSERVED:** both designs satisfied the required outcomes in the scenarios tested: Design A 45/45 and Design B 52/52 required checks. Both runners exited 0 on three consecutive repeated runs, again after reformatting, and again for the final saved transcripts. Some observations vary between runs (e.g. how many worker threads were used); the pass/fail outcomes did not.
3. **OBSERVED:** the framework provides **no binding** between an authorization decision and the request that ultimately runs. In Design A, a wrapper can swap the arguments, swap the tool object, or call `execute()` twice, and the framework runs it. Binding must be enforced by Sentinel itself.
4. **OBSERVED:** Design A has a trap: installing only the async hook leaves the **sync** path completely unguarded (a denied tool ran).
5. **RECOMMENDATION:** use **Design B** as the v1 enforcement boundary. It matches the decision record's rule that the proxy is the sole executor, needs no ToolNode configuration, gates direct calls to the wrapped tool, and avoids the async-hook trap. The proposed `wrap_tools` API is **feasible** with the constraints in §7.
6. **OBSERVED, important:** LangGraph's `RetryPolicy` re-executed a tool **3 times** when the wrapper raised a generic exception *after* execution. This is the same situation as a post-execution audit failure (decision C1.7). It must be handled in the adapter design (§6, F9).

## 2. Scope notes

### 2.1 Numbering
This prompt's E1–E8 differ from the E1–E8 in `decision_record.md` §3.4. Mapping:

| This prompt | Decision-record question answered |
|---|---|
| E1 authorized, E2 denied, E3 approval | old E1 |
| E4 mismatched action, E5 unwrapped tool | new in this prompt |
| E6 error handling and retries | old E3 (and partly E4) |
| E7 multiple calls | old E5 |
| E8 boundary (all invocation paths) | old E2, E4, E6 |
| E8b (my addition) | old E7 (official hook) and E8 (version floor) |

### 2.2 What is real and what is scripted
- **Real:** `StateGraph`, `ToolNode`, `tools_condition`, `create_react_agent`, `RetryPolicy`, LangChain `StructuredTool` / `@tool` objects, and all invocation APIs.
- **Scripted:** the "model" is a graph node (`ScriptedModel`) that emits prepared tool calls, because no LLM or network is used. One probe used a fake chat model subclass for `create_react_agent`.
- **Toy:** the gate is a dict lookup and the proxy is ~40 lines. They stand in for Sentinel and prove nothing about Sentinel's real logic.
- **Self-checking limits:** the checks are my own. Where a probe could pass vacuously, I found and fixed two such cases during the work (§9).

## 3. Environment (OBSERVED)

| Item | Value |
|---|---|
| OS / Python | macOS (Darwin), Python 3.11.14 (`/opt/homebrew/bin/python3.11`) |
| `langgraph` | 1.2.18 (`Requires-Python >=3.10`) |
| `langgraph-prebuilt` | 1.1.1 (`>=3.10`), the package that contains `ToolNode` |
| `langchain-core` | 1.7.1 (`>=3.10`), installed **as a dependency of langgraph** |
| `langgraph-checkpoint` | 4.3.1 (`>=3.10`) |
| `langchain` (the package) | **not installed**; no approval was requested or needed |
| Full freeze | `spikes/langgraph_interception/requirements-freeze.txt` (38 packages) |

Commands (run from the repository root; nothing global was touched, the project `.venv` was not used and still contains no LangGraph/LangChain):

```bash
mkdir -p spikes/langgraph_interception
/opt/homebrew/bin/python3.11 -m venv spikes/langgraph_interception/.venv
spikes/langgraph_interception/.venv/bin/python -m pip install --upgrade pip   # inside the spike venv only
spikes/langgraph_interception/.venv/bin/python -m pip install langgraph       # unpinned: resolved to the versions above
spikes/langgraph_interception/.venv/bin/python -m pip freeze > spikes/langgraph_interception/requirements-freeze.txt
cd spikes/langgraph_interception
.venv/bin/python run_experiments.py   # Design A (hook)
.venv/bin/python run_design_b.py      # Design B (replacement tools)
```

**OBSERVED:** all LangGraph components declare support for Python ≥3.10, which is compatible with the approved floor of ≥3.11 (D-01).

## 4. Experiment architecture

```text
START -> model (scripted node: emits AIMessage with tool_calls)
              |  tools_condition
              v
        tools (real ToolNode) -> back to model       counters: spy "invoke" events inside tool functions
```

- **Spy tools** (`standin.py`): `increment` (authorized), `dangerous` (denied), `needs_approval` (REQUIRE_APPROVAL), `typed_count(n: int)` (coercion probe), `unwrapped` (never registered), `state_reader` (framework-injected argument). Each tool's only effect is appending an `invoke` event to a thread-safe, ordered log. **That count is the invocation counter in every table below.**
- **Gate** (`standin.py`): default-deny policy table; returns a decision carrying the evaluated action and a SHA-256 digest; logs every evaluation.
- **Design A** (`Boundary` in `standin.py`): installed as `ToolNode(wrap_tool_call=..., awrap_tool_call=...)`.
- **Design B** (`standin_b.py`): `wrap_tools_replace` builds a `StructuredTool` per tool whose function calls the gate, then `Proxy.execute()`. The proxy verifies ALLOW, the live-request digest, and single use, then calls the original function with the *evaluated snapshot* of the arguments. Original functions live only in the proxy's registry.

## 5. Results E1–E8

"inv" = invocation counter of the tool in question; "eval" = gate evaluations. All numbers are from `results/transcript_*.txt`.

### E1: authorized invocation
| Design | inv(increment) | eval | Result |
|---|---|---|---|
| A (hook) | **1** | 1, before the invocation | PASS |
| B (replacement) | **1**, plus exactly 1 proxy-execute event | 1, before the invocation | PASS |

### E2: denied invocation
| Design / denial mode | inv(dangerous) | eval | How the graph saw it |
|---|---|---|---|
| A, raise | **0** | 1 | `ActionDenied` propagated out of `graph.invoke` (the default handler re-raises) |
| A, message | **0** | 1 | `ToolMessage status=error 'blocked: POLICY'` |
| A, tool absent from policy | **0** | 1 | `status=error 'blocked: UNAUTHORIZED_TOOL'` (default deny) |
| B, ToolException / raise / string | **0** (all three) | 1 | error message / `ActionDenied` out of the graph / `status=success 'blocked: POLICY'` |

### E3: approval-required invocation
Same tables as E2 with `needs_approval`. inv = **0** in every mode in both designs; `ApprovalRequired` or `'blocked: REQUIRE_APPROVAL'` was surfaced distinctly from DENY. PASS.

### E4: incorrect or mismatched action
| Case | Result (OBSERVED) |
|---|---|
| **A, control: no binding check; arguments swapped after the decision** | The function **ran with the swapped value** (`label='TAMPERED'`), with 1 evaluation. The framework does not stop it. |
| A, verified: same swap | Blocked (`ACTION_MISMATCH`); inv = 0 |
| **A, control: `request.override(tool=dangerous)` keeping the evaluated name `increment`** | The framework ran **`dangerous`** (inv(dangerous)=1, inv(increment)=0). It executes `request.tool`, not the name that was evaluated. |
| A, verified: same swap | Blocked; nothing executed |
| **A, control: wrapper calls `execute()` twice for one evaluation** | 1 evaluation, **2 invocations** |
| B, decision for args A used to execute args B | Blocked (`ActionMismatch`); inv = 0 |
| B, decision for tool X used for tool Y | Blocked; inv = 0 |
| B, DENY decision handed to the proxy | Blocked; inv = 0 |
| B, arguments mutated after evaluation | Blocked; inv = 0 |
| B, replay of one ALLOW decision | First run executed (inv = 1); **second blocked** (`DECISION_ALREADY_USED`). One decision authorizes one execution |
| Coercion, model emits `n="5"` for an `int` parameter | **A:** the gate evaluated the string `"5"`, the function received int `5`. The evaluated and executed values **differ**, and no check catches it because the digest covers what the gate saw. **B:** the framework coerces *before* the guarded function runs, so the gate evaluated `{"n": 5}` and the function received `5`: **evaluated = executed**. |
| Framework-injected parameter (`InjectedState`) | **A:** the function received the full graph state (`['messages']`); the gate saw only `{'label': 'x'}`. **B:** `wrap_tools` refused the tool at construction (`framework-injected parameters: ['state']`), via a schema diff that found nothing on ordinary tools. |

Note: the A "tamper" cases use a test hook I added to simulate hostile or buggy code. The framework does not produce mismatches by itself. They show that the framework offers no protection against them, and that a digest check catches them.

### E5: unwrapped tool
| Case | inv | eval | Result |
|---|---|---|---|
| Plain `ToolNode([unwrapped])` in a graph (no Sentinel) | **1** | 0 | **Executes, unprotected.** No Sentinel involvement at all |
| Protected node, model emits a name not in the node (A) | 0 | 1 (deny) | The hook still runs with `tool=None`; the gate default-denied it, so it is **audited** |
| Protected node, model emits a name not in the node (B) | 0 | **0** | The framework rejects it first (`'unwrapped is not a valid tool'`). Sentinel **never sees** it, so no audit record |
| Tool in node but absent from policy (A) | 0 | 1 | Default-denied at call time |
| `wrap_tools` given an unregistered tool | n/a | n/a | Refused at construction in both designs |
| `increment.invoke()` on the **original** object after wrapping | **1** | 0 | **Bypass.** The original stays callable and unguarded if the developer keeps using it |
| A: `tool.invoke()` called directly on a tool that a hook-protected node holds | 1 | 0 | Bypass (the hook lives on the node, not on the tool object) |
| **B:** the wrapped tool invoked directly | 1 (allowed tool) | **1** | **Gated**, unlike the hook |

The stand-in `wrap_tools` covers only the tools passed to it and makes no other claim.

### E6: framework error handling, retries, loops
| Case | inv | eval | Observation |
|---|---|---|---|
| A raise, default handler | 0 | 1 | Graph run **aborts** with the exception |
| A/B raise, `handle_tool_errors=True`, agent retries ×3 | 0 | 4 | Converted to a message: `"Error: ActionDenied('POLICY')\n Please fix your mistakes."`. The agent loop retried; every retry was re-evaluated and denied |
| A message / B tool_exception, agent retries ×3 | 0 | 4 | Fixed text only (`blocked: POLICY`); every retry re-evaluated |
| B string mode | 0 | 1 | Result is `status=success`, so a retry-on-error loop **does not even notice** the denial |
| Denial raised + `RetryPolicy(max_attempts=3)` on the node | **0** | **3** | The framework retried the *denial*: 3 evaluations, never executed |
| **Failure raised AFTER the tool ran, custom `Exception` subclass + `RetryPolicy`** | **3** | 3 | **The tool executed 3 times.** Each retry is a fresh request, so each passes the gate and runs |
| Same, but a `RuntimeError` subclass | 1 | 1 | Not retried (LangGraph's default predicate excludes `RuntimeError` and several other types) |
| Same failure surfaced as an in-tool `ToolException` (`handle_tool_error=True`) | **1** | 1 | Not retried; message `status=error` |

No scenario produced an unauthorized execution. Denials never triggered execution through retries or loops.

### E7: multiple tool calls
One model turn with 5 calls: `increment`×3, `dangerous`, `needs_approval`.

| Design / path | increment | dangerous | needs_approval | eval | Threads observed |
|---|---|---|---|---|---|
| A sync (`invoke`) | **3** | **0** | **0** | 5, each allow before its invocation | `ThreadPoolExecutor-N` workers (evaluation and invocation on the same worker per call) |
| A async (`ainvoke`) | 3 | 0 | 0 | 5 | **evaluation on `MainThread` (the event loop)**; invocation in `asyncio_N` executor threads (measured per event kind) |
| B sync | 3 | 0 | 0 | 5 | `ThreadPoolExecutor-N` workers |
| B async | 3 | 0 | 0 | 5 | all in `asyncio_N` threads |

Every call was evaluated independently and before its own execution. The number of distinct pool workers varied between runs (1 or 2 observed), so parallelism is possible but not guaranteed.

### E8: boundary — which invocation paths are intercepted

"Intercepted" means the gate was evaluated; "blocked" requires the gate to have run **and** the denied tool to have not run.

| Path | Design A (hook) | Design B (replacement) |
|---|---|---|
| `graph.invoke`, `stream`, `batch`, `ainvoke`, `astream` | Intercepted and blocked | Intercepted and blocked |
| Tool node inside a subgraph | Intercepted and blocked | Intercepted and blocked |
| `create_react_agent(model, ...)` | Intercepted and blocked (given the wrapped `ToolNode`) | Intercepted and blocked, given a **plain list** of wrapped tools with **no hook configuration** |
| Async path, only the **sync** hook installed | Intercepted and blocked (the framework calls the sync wrapper) | n/a |
| Sync path, only the **async** hook installed | **NOT intercepted. The denied tool ran (inv = 1, eval = 0)** | n/a |
| Wrapped tool called directly (`tool.invoke`, `tool.ainvoke`) | **Not intercepted** (bypass) | **Intercepted and blocked** (`ainvoke` ran the sync function in an executor thread) |
| Original tool object `.invoke()`, or the original function | Bypass | Bypass (if the developer retains the original) |
| `ToolNode.invoke()` outside a graph | Could not be run (`ValueError: Missing required config key`), so **no conclusion** | n/a |
| Callback `on_tool_start` raising, `raise_error=False` (default) | Tool **ran** (error only logged to stderr) | n/a |
| Callback raising, `raise_error=True` | Tool did **not** run | n/a |
| Same graph with the callback omitted from the call's `config` | Tool **ran** | n/a |

**Assumptions needed for reliable enforcement (OBSERVED/INFERRED):** (a) every tool a model can call is wrapped, and no unwrapped or original reference is used; (b) in Design A, **both** hooks are installed; (c) the developer does not call original functions directly; (d) tools have no framework-injected parameters; (e) tests ran one framework version.

## 6. Findings

**OBSERVED unless marked.**

| ID | Finding | Evidence |
|---|---|---|
| F1 | `ToolNode` has an official hook: `ToolNode(wrap_tool_call=..., awrap_tool_call=...)` in `langgraph.prebuilt.tool_node`. It runs for every call, including names the node does not know (`request.tool is None`). | source read; E5 |
| F2 | Both designs block DENY and REQUIRE_APPROVAL with inv = 0 on every intercepted path tested, and run ALLOW exactly once. | E1–E3, E7, E8 |
| F3 | The framework imposes no link between the decision and what runs. Arguments, tool object, and repeated `execute()` calls can all diverge in Design A. | E4 controls |
| F4 | A hook installed on only the async side leaves the sync path **unguarded**. | E8 |
| F5 | The async path falls back to the sync hook when no async hook exists. | E8 |
| F6 | Hook-based protection lives on the node, so direct tool calls bypass it. Replacement tools gate direct calls. | E5, E8 |
| F7 | The framework coerces arguments (`"5"` → `5`) before they reach a hook-evaluated function or a replacement tool. With a hook, the gate sees the pre-coercion value; with replacement tools, the gate sees the coerced value. | E4 |
| F8 | Injected parameters (e.g. `InjectedState`) reach the function but are invisible to a hook-level gate. They can be detected at wrap time by comparing the tool's input schema with its model-facing schema. | E4 |
| F9 | **Retries can re-execute a tool.** `RetryPolicy` retried a generic exception raised after execution (3 executions). `RuntimeError` subclasses and in-tool `ToolException` were not retried. Every retry is a new request and a new decision. | E6 |
| F10 | `handle_tool_errors=True` puts the exception `repr` and "Please fix your mistakes." into the message the model sees. The default handler instead aborts the whole run. A fixed-text `ToolException` avoids both. | E6 |
| F11 | Sync tool calls in one step run in a thread pool (1–2 distinct workers observed across runs). Async calls run sync functions in executor threads. Design A's async hook evaluates on the **event-loop thread** (measured). The pipeline must be thread-safe, and any blocking audit write must not run on the event loop. | E7 |
| F12 | Callbacks are not a boundary: default `raise_error=False` swallows the exception, callbacks come from per-call config the caller can omit, and they receive only strings. | E8 |
| F13 | Design B cannot audit model-emitted unknown tool names, because the framework rejects them first. Design A can. | E5 |
| F14 | `create_react_agent` emits a deprecation warning ("moved to `langchain.agents`"). The framework's agent API is in flux. | E8b |
| F15 | **INFERRED, not tested:** string-mode denial (`status=success`) is hazardous because loops and instrumentation that key off `status=error` treat it as success. | E6 |

## 7. Recommended integration boundary and `wrap_tools` feasibility

### 7.1 Recommendation (not a decision)
**Design B: `wrap_tools` returns replacement tools.** Narrowest interface that gave the guarantee:

> A call made through a tool object returned by `wrap_tools` is evaluated by Sentinel before the original function can run, and the original function runs only inside Sentinel's proxy, only for an ALLOW decision bound to the evaluated action, once.

Reasons: it keeps the proxy the sole executor (decision record C1.4); it needs no `ToolNode` configuration (F4 trap avoided); it gates direct calls (F6); the gate sees the post-coercion values that execute (F7).

### 7.2 Is `wrap_tools(tools, client=..., agent_id=...)` feasible? **Yes, with these constraints** (RECOMMENDATION from OBSERVED behaviour)
1. **Metadata is needed per tool**, because LangChain tools carry no `destructive` flag (C1.3). The signature needs either prior `client.register_tool(...)` registration or a metadata mapping. The stand-in refused unregistered tools at construction, and this worked.
2. Tools are **replaced, not mutated**. The caller must pass only the returned tools to the framework and discard the originals (the original stays a bypass).
3. **Refuse at wrap time:** tools with framework-injected parameters (F8). *UNRESOLVED:* class-based `BaseTool` subclasses without a `.func`, and native-coroutine tools, were **not tested**. The stand-in assumes `.func`. Refuse them until tested.
4. **Do not raise generic exceptions after a tool has run** (F9). Surface non-ALLOW and post-execution results as an in-tool `ToolException` with fixed, non-secret text (not a string return, F15; not exception `repr`, F10).
5. **Single-use decisions:** the proxy must mark a decision used (replay was blocked in the stand-in).
6. **Execute the evaluated snapshot**, not the live argument dict (the stand-in did, and a mutation test was blocked).
7. Identity is bound by closure at wrap time. **UNRESOLVED:** whether the framework can pass an `agent_id`-named argument through to the tool function was **not tested**. The gateway's reserved-key rejection (SEC-013) must remain regardless.
8. **Coverage statement for the README:** only tool objects returned by `wrap_tools`; not graph-wide; not original references; `protect(graph)` should not exist.

### 7.3 Design A (hook), if ever used
Only as a second layer or for auditing unknown names (F13), never as the sole boundary: install both hooks (F4), never override requests, and enforce digest binding and single use (F3).

## 8. What was NOT demonstrated (UNRESOLVED)

- **Full-graph protection.** Plain `ToolNode`s, direct tool calls, original references, and graph nodes calling functions directly are unprotected (E5, E8).
- **The `langchain` package** (`langchain.agents.create_agent`, agent middleware). Not installed, so not tested. `create_react_agent` is deprecated in favour of it (F14). Testing it needs your approval to install `langchain` in the spike venv.
- Class-based `BaseTool` subclasses; native async (coroutine) tools; tools returning `Command`; `InjectedStore` / `ToolRuntime` / `InjectedToolCallId` parameters beyond `InjectedState`; interrupts and human-in-the-loop; streaming tool events.
- A real LLM. Tool calls were scripted, so model-formatted edge cases (malformed arguments, duplicated ids) were not exercised.
- Behaviour of other framework versions, other operating systems, or Python 3.12/3.13.
- Mapping of Sentinel's real `PipelineResult` into a LangChain tool return value, and its output types.
- Performance, and thread-safety of a real SQLite audit store under the parallel execution seen in F11.

## 9. Method notes and limitations (honesty)

- Two of my own checks passed **vacuously** at first and were fixed before the final runs: (1) a direct `ToolNode.invoke()` probe errored before reaching the gate yet was counted as "blocked"; (2) a direct `ainvoke` probe reused the previous probe's evaluation count. Probes now require the gate to have been evaluated *and* the tool not run, with per-probe isolation. The direct `ToolNode.invoke()` case remains **inconclusive**, and is reported as such.
- The controls show the instrumentation can detect an unguarded execution (e.g. E5 plain node inv = 1, async-only hook inv = 1).
- All checks are mine; this report is not independently reviewed.
- One machine, one framework version set (§3), a stand-in gate. Treat results as evidence for *this* version, not a guarantee.

## 10. Proposed changes (NOT applied; each needs owner approval)

### Decision register (`decision_record.md`)
| Item | Proposed change |
|---|---|
| D-12 | Move from Pending to **Proposed**, revised: `wrap_tools` returns replacement tools (Design B); no ToolNode hook; no `protect()`; coverage statement per §7.2.8; `wrap_tools` takes per-tool metadata (§7.2.1). Evidence: this report. |
| C3.2 / C3.3 | Rewrite to the Design B contract; add refusal rules (injected parameters, unsupported tool classes). Remove "wrapper replaces the tool's callable" ambiguity. |
| C1.4 | Add: a decision is **single-use** (replay blocked); the proxy executes the evaluated JSON snapshot. Confirms D-07 consequence that arguments must be JSON-serialisable. |
| C1.7 / C1.8 / D-03 / FR-018 | The adapter surfaces non-ALLOW and post-execution failures as a fixed-text in-tool `ToolException`, **not** a raised `ActionDenied`/`ToolExecutionError` (F9, F10). Keep the exceptions for direct `evaluate_request` callers. Document that a node-level `RetryPolicy` can re-run non-idempotent tools, and that each retry is a new request. |
| SEC-016 | Revisit. Design B's async path ran through the sync pipeline in an executor thread and was gated. "Async fails closed" can narrow to "native-coroutine tools are refused until tested". |
| D-20 | Strengthen: parallel sync calls and executor threads were observed (F11). The pipeline must be thread-safe, and audit writes must not run on the event loop. |
| New requirement | The adapter refuses tools with framework-injected parameters (F8). |
| New limitation | Unknown tool names emitted by the model are rejected by the framework and are **not audited** under Design B (F13). |
| New decision | Add `spikes/` to Ruff's `extend-exclude` in `pyproject.toml` (see §11). Needs your approval; this task forbade editing `pyproject.toml`. |

### Implementation plan (`implementation_plan.md`)
- Mark C-02 **executed**, with this report as evidence.
- **Add C-02b (optional, before C-16):** repeat the essential scenarios with `langchain` installed in the spike venv (needs your approval), covering `create_agent` and agent middleware, class-based tools, coroutine tools, and `Command`-returning tools.
- **C-16:** acceptance criteria become: E1–E3, E7 and E8 as regression tests against the real adapter; replay, mutation and injected-parameter refusal tests; post-execution-failure + `RetryPolicy` test; a documented coverage statement. Keep the stand-in scenarios as seeds for `tests/integrations/`.
- **C-03:** no model change required by this experiment beyond the single-use rule. It can proceed once the other C-03 decisions are approved.

## 11. Repository impact and cleanup

- **Files added (all untracked, none committed), under `spikes/langgraph_interception/`:** `standin.py`, `standin_b.py`, `run_experiments.py`, `run_design_b.py`, `requirements-freeze.txt`, `results/` (2 JSON files, 2 console transcripts), `README.md`. Plus this report.
- **No production file changed:** `src/`, `tests/`, `pyproject.toml`, `constraints-dev.txt`, `.github/` and the commit history are untouched. Nothing was committed, pushed, or renamed.
- **Lint side effect:** the spike files initially made the project's `ruff check .` fail (200 errors) because the project's rules apply to everything under the repository root. I did **not** edit `pyproject.toml`; instead the four spike modules carry a file-level `# ruff: noqa` and are formatted, so `ruff check .` and `ruff format --check .` pass. **Committing `spikes/` without excluding it in `pyproject.toml` is a decision for you** (§10).
- **Cleanup:** the disposable `spikes/langgraph_interception/.venv` (71 MB, git-ignored) was removed after the results, freeze file and transcripts were preserved. Recreate it with the commands in §3 to rerun.
