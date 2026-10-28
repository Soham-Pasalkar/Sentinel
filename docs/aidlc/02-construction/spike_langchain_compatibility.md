# C-02b Report: LangChain `create_agent`, Async-Native Tools and `Command` Tools

| | |
|---|---|
| Increment | C-02b (isolated, disposable experiment; no production code) |
| Date | 2026-10-28 |
| Builds on | [`spike_framework_interception.md`](spike_framework_interception.md) (C-02) |
| Status | **Experiment complete. No canonical decision status was changed.** Every proposed change below needs owner approval. |
| Verdict | **Design B (replacement tools) remains suitable** for the tested patterns. No scenario showed a denied or approval-required call executing, and no scenario challenged the assumption that replacement tools can enforce the tested boundary. **It is suitable only with the extra adapter behaviours in §8, and some risks cannot be removed by the adapter alone (§7).** |
| Not covered | Full framework coverage is **not** claimed. See §9. |

Labels: **OBSERVED** = measured here (evidence in `spikes/langchain_compatibility/results/`). **RECOMMENDATION** = my proposal. **UNRESOLVED** = not tested or not known.

> **Rev. 2 update (2026-10-28, after owner review):** the findings below are unchanged. The owner approved the proposed changes as D-12 (expanded), D-14 amendment, D-25, D-26, D-27 and D-28; see `decision_record.md` §0.4 and §12. The `# ruff: noqa` headers mentioned below were replaced by a `spikes` Ruff exclusion in `pyproject.toml` (D-28). This report remains the evidence record.

---

## 1. Summary

1. **OBSERVED:** across a 20-row matrix of tool kind (sync, async-native, `Command`), verdict and entry point, every denied or approval-required call had an invocation counter of **0** and was never claimed by the proxy. In **16** rows the gate explicitly evaluated it once. The other **4** (async-native tools entered through a *sync* entry point) failed inside the framework before reaching the adapter, so their non-execution is the framework's doing, not a Sentinel decision. Authorized calls ran exactly once.
2. **OBSERVED, the key new risk:** if an adapter lets the original exception escape after a tool has run, **the framework re-executes the tool**: 3 executions under both LangGraph's `RetryPolicy` and `create_agent`'s `ToolRetryMiddleware`, for sync, async-native and `Command` tools. Converting the failure inside the adapter into a fixed-text `ToolException` gives 1 execution in every cell, and so does an at-most-once-per-`tool_call_id` guard.
3. **OBSERVED:** `Command` semantics are preserved. State updates and routing matched the unwrapped original exactly. A denied `Command` tool changed no state and triggered no routing, while the unwrapped control did route.
4. **OBSERVED:** a decision consumed concurrently by 8 threads, or 8 asyncio tasks, executed exactly once in 100 of 100 trials each. A deliberately racy control duplicated execution in 50 of 50 trials, so the test can detect failure.
5. **OBSERVED, challenges an earlier contract:** cancelling an async tool mid-execution leaves the call in an **interrupted / unknown** state, which the current decision record says the in-process pipeline never produces (C1.6). This is not a failure of the boundary, but the contract needs updating.
6. **Not enforceable by the adapter alone:** trusted-code bypass (middleware, original references, unwrapped tools), model-driven repeat calls, `Command` downstream effects after an ALLOW, and process-level interruption (§7).

## 2. Scope notes (what is real, scripted and toy)

- **Real:** `langchain.agents.create_agent`, `AgentMiddleware`, `ToolRetryMiddleware`, `ToolNode`, `StateGraph`, `RetryPolicy`, `Command`, `InjectedToolCallId`, LangChain `StructuredTool` / `@tool` objects (sync, async-native), real `asyncio` tasks and threads.
- **Scripted:** the chat model is a subclass of LangChain's `GenericFakeChatModel` that replays prepared messages. No LLM, API key or network was used. Real model output (malformed arguments, duplicate call ids) was not exercised.
- **Toy:** the gate is a dict lookup and the proxy is a small state machine. They stand in for Sentinel and prove nothing about Sentinel's real logic.
- **The checks are mine.** Every control that demonstrates a *bypass* or a *duplicate execution* is labelled `[control]` and passes when the bad behaviour is observed, which shows the instrumentation can detect it.

## 3. Environment (OBSERVED)

| Item | Value |
|---|---|
| OS / Python | macOS (Darwin), Python 3.11.14 |
| `langchain` | **1.4.7** (new in C-02b) |
| `langgraph` | 1.2.18, `langgraph-prebuilt` 1.1.1, `langgraph-checkpoint` 4.3.1 (same as C-02) |
| `langchain-core` | 1.7.1 |
| `pydantic` | 2.14.1 |
| Provider SDKs installed | none (no `openai`/`anthropic` packages) |
| Full freeze | `spikes/langchain_compatibility/requirements-freeze.txt` (39 packages) |

The environment is separate from the project's `.venv` and from the C-02 environment, which had been removed. The project `.venv` still contains no LangChain or LangGraph.

```bash
# from the repository root
mkdir -p spikes/langchain_compatibility/results
/opt/homebrew/bin/python3.11 -m venv spikes/langchain_compatibility/.venv
spikes/langchain_compatibility/.venv/bin/python -m pip install --upgrade pip   # inside the spike venv only
spikes/langchain_compatibility/.venv/bin/python -m pip install langchain       # unpinned: resolved to the versions above
spikes/langchain_compatibility/.venv/bin/python -m pip freeze > spikes/langchain_compatibility/requirements-freeze.txt
cd spikes/langchain_compatibility
.venv/bin/python run_c02b.py            # exits 1 if a required check fails
```

`standin_c.py` imports the C-02 stand-ins from the sibling directory `spikes/langgraph_interception/`, so that directory must be present. Repeat runs, no network needed at run time.

## 4. Adapter shape under test

`wrap_tools_c(tools, gate, proxy, agent_id, on_block=..., on_tool_error=..., once_per_call_id=...)`, a Design B prototype extended from C-02:

- Returns **replacement `StructuredTool`s** (sync `func` and/or async `coroutine`, as in the original). Original functions live only in the proxy.
- The proxy claims a decision **atomically** (single use), then executes the **evaluated snapshot** of the arguments. States: `claimed → entered → completed | failed | interrupted`.
- `InjectedToolCallId` is accepted as the only injected parameter. It is forwarded to the function but kept **out of** the evaluated action.
- Non-ALLOW results raise a fixed-text `ToolException` (handled in-tool, so the framework produces an error `ToolMessage` and never a `Command`).
- `on_tool_error="convert"` turns any original exception into a fixed-text `ToolException`; `"propagate"` is the **naive control** that lets the original exception escape.
- `once_per_call_id=True` injects a framework-supplied `tool_call_id` into the replacement (hidden from the model) and refuses a second execution for the same id.
- Refuses at wrap time: unregistered tools, provider built-in (`dict`) tools, class-based `BaseTool`s, and tools with injected parameters other than `tool_call_id`.

## 5. Results

"inv" = the tool's invocation counter; "eval" = gate evaluations. Numbers are from `results/transcript_c02b.txt` and `results/results_c02b.json`. **120 of 120 required checks passed**, across 16 scenarios; the runner exited 0 on five consecutive repeats before a final addition of two checks, and on three more afterwards.

### Experiment A: `create_agent`

| Case | Result (OBSERVED) |
|---|---|
| Authorized sync tool | inv **1**, eval 1 (before the invocation), proxy state `completed` |
| Denied sync tool | inv **0**, eval 1, proxy never claimed it; the model saw `'blocked: POLICY'` |
| REQUIRE_APPROVAL | inv **0**, eval 1; `'blocked: REQUIRE_APPROVAL'` |
| Unknown tool name emitted by the model | inv 0, **eval 0**: rejected by the **framework** (`'ghost is not a valid tool'`) before the adapter, so Sentinel never saw it |
| Denied tool (contrast) | inv 0, **eval 1**: an explicit Sentinel decision. *Whether an evaluation event exists* distinguishes the two |
| Unwrapped tool in the same agent | **inv 1, eval 0** ([control] it runs with no Sentinel involvement) |
| Tool supplied by a middleware's `tools` attribute | **inv 1, eval 0** ([control] same) |
| Coverage inspection of the compiled agent | Reported `{"s_inc": true, "s_raw": false}` for the mixed agent, and flagged the middleware-supplied tool as `false`. It reads `agent.nodes["tools"].bound.tools_by_name`, which is **an internal attribute path** |
| Middleware that rewrites the arguments | The gate evaluated the **rewritten** arguments (`{"label": "TAMPERED"}`) and the function received the same. Authorization follows what actually reaches the function |
| Middleware that swaps in the original, denied tool object | **inv(denied) 1, eval 0.** Bypass by trusted code (documented, not defended) |
| Wrap-time refusals | `dict` provider tool, unregistered tool, and class-based `BaseTool` were all refused (see saved results for the messages) |
| Mismatched or replayed decision | Not reachable through the agent, so tested at the proxy (Experiment D) |

### Experiment B: async-native tools

| Case | Result (OBSERVED) |
|---|---|
| Authorized / denied / approval via `create_agent.ainvoke` and via `StateGraph+ToolNode.ainvoke` | inv **1 / 0 / 0**, eval 1 each, evaluation before invocation |
| Where the gate ran | In an executor thread (`asyncio_0`), via `asyncio.to_thread`, **not** on the event-loop thread |
| Sync entry (`invoke`) into an async-only tool | `NotImplementedError: StructuredTool does not support sync invocation`: inv 0, **eval 0**, identical to the unwrapped original. The framework fails before the adapter; nothing executes |
| 8 concurrent attempts on one decision | asyncio: **100/100 trials executed exactly once**, 700 refusals. Threads (barrier-released): **100/100 exactly once**, 700 refusals. **Racy control: 50/50 trials duplicated** (up to 8 executions) in both modes |
| Cancellation mid-execution (caller timeout 0.15 s, tool sleeps 0.6 s) | started 1, completed 0, cancelled 1, eval 1. Proxy state **`interrupted`**. The counter stayed 1 for a further 0.9 s: no retry |
| Failure after execution | See §6 |

### Experiment C: tools returning `Command`

| Case | Result (OBSERVED) |
|---|---|
| `Command(update=...)` tool, original vs wrapped | Identical final state (`notes == ["x"]`), identical messages; inv 1, eval 1 |
| `Command(goto="side_node", update=...)` tool, original vs wrapped | Identical, including routing: `side_node` ran **1** time in both |
| `InjectedToolCallId` | Forwarded to the original function. The `ToolMessage` inside the Command carried the model's call id, and `ToolNode`'s own validation accepted it. Model-facing schema stayed `["label"]`; the gate's evaluated arguments stayed `{"label": "x"}` |
| Other injected parameters (`InjectedState`) | Still refused at wrap time |
| Denied / approval-required `Command` tool | **Control (unwrapped):** the function ran and `side_node` ran 1 time, `notes == ["side"]`. **Wrapped:** inv **0**, `side_node` ran **0** times, `notes == []`, represented as an error `ToolMessage`, never a `Command` |
| Async-native `Command` tool | inv 1; the update was applied (`notes == ["x"]`) |
| `Command` tool inside `create_agent` with a custom state key | Update applied for both the original and the wrapped tool (`notes == ["x"]`) |
| Failure after execution | See §6 |

### Experiment D: invariants

| # | Invariant | Result (OBSERVED) |
|---|---|---|
| 1 | One authorization, one exact action | Sync and async proxies refused: decision for args A used for args B; decision for tool X used for tool Y; args mutated after evaluation. inv 0 in each |
| 2 | Single use | Sequential replay: first executed, second refused (`DECISION_ALREADY_USED`), inv 1 |
| 3 | Concurrent consumption | 100/100 trials exactly one execution (asyncio and threads); racy control fails |
| 4 | DENY never executes | 20-row matrix (3 tool kinds × 2 verdicts × entry points): **0 invocations in total** |
| 5 | REQUIRE_APPROVAL never executes | Same matrix |
| 6 | Post-execution failure is not shown as non-execution | See below |
| 7 | Retries cannot repeat a side effect | See §6 |

**Matrix detail:** 16 rows were explicitly evaluated once and never claimed by the proxy. **4 rows** (async-native tools entered through a *sync* entry point) failed in the framework before the adapter was reached: `NotImplementedError`, 0 evaluations, 0 invocations. Their never-executed outcome comes from the framework, not from a Sentinel decision, and the report treats them separately.

**Invariant 6:** after a post-execution failure the proxy state is `failed` (sync and async), and the message to the model reads `'tool failed (execution may have occurred)'`: it does not say "blocked" or "not executed". By contrast a DENY leaves **no** proxy state. After cancellation the state is `interrupted`. The three situations stay distinguishable.

## 6. Retry findings (Experiment D #7)

Executions of a tool that **performs its side effect and then raises**. Every row is from the saved results; a "decision" per attempt means each retry was re-evaluated.

| Retry mechanism | Tool | Adapter behaviour | Executions | Evaluations |
|---|---|---|---|---|
| `ToolRetryMiddleware(max_retries=2)` | sync | convert to `ToolException` | **1** | 1 |
| `ToolRetryMiddleware(max_retries=2)` | sync | **naive propagate** | **3** | 3 |
| `ToolRetryMiddleware(max_retries=2)` | sync | propagate + once-per-call-id | **1** | 2 |
| `ToolRetryMiddleware(max_retries=2)` | sync | convert + once-per-call-id | **1** | 1 |
| `ToolRetryMiddleware(max_retries=2)` | async | convert | **1** | 1 |
| `ToolRetryMiddleware(max_retries=2)` | async | **naive propagate** | **3** | 3 |
| `ToolRetryMiddleware(max_retries=2)` | async | propagate + once-per-call-id | **1** | 2 |
| `RetryPolicy(max_attempts=3)` | async | convert | **1** | 1 |
| `RetryPolicy(max_attempts=3)` | async | **naive propagate** | **3** | 3 |
| `RetryPolicy(max_attempts=3)` | async | propagate + once-per-call-id | **1** | 2 |
| `RetryPolicy(max_attempts=3)` | `Command` | convert | **1** | 1 |
| `RetryPolicy(max_attempts=3)` | `Command` | **naive propagate** | **3** | 3 |
| `RetryPolicy(max_attempts=3)` | `Command` | propagate + once-per-call-id | **1** | 2 |

Further observations:
- **OBSERVED:** the naive-propagate runs through `RetryPolicy` surfaced the original exception text to the *caller* of the graph (the planted canary appeared in the error), and `ToolRetryMiddleware` did not forward it to the model. The "convert" rows never exposed the canary anywhere.
- **OBSERVED:** the extra evaluation in the once-per-call-id rows is a gate evaluation that produced ALLOW but was blocked before execution. In the real audit design that reads as DECISION(allow) without EXECUTION_STARTED, which the C4.4 rules classify as "not executed". That is accurate but noisy.
- **OBSERVED:** an **agent-loop retry** (the model re-emitting the call after an error) produced 2 executions under 2 distinct decisions; no decision was consumed twice. This is a new, legitimately authorized request, and the adapter cannot tell it from an intended repeat.

## 7. Behaviour the adapter cannot enforce alone

| Item | Why |
|---|---|
| **Trusted-code bypass** | Middleware swapped in an original denied tool and it ran with no evaluation. Unwrapped tools and middleware-supplied tools also run unprotected. The adapter can only *report* coverage, not prevent this. |
| **Model-driven repeats** | A model that re-calls a failed tool gets a new, valid decision each time. Limiting it is policy (rate limits, idempotency design), not adapter logic. |
| **Cancellation / process death** | After the function starts, the caller cannot know whether it finished. The best an in-process adapter can do is mark the request interrupted before re-raising; a process kill leaves only the audit's "started, never completed" evidence. |
| **`Command` consequences** | An ALLOWED tool's `Command` (`goto`, state updates) is applied by the framework afterward. `side_node` ran once for an allowed call. Sentinel authorized the *tool call*, not the downstream graph effects. `Send` and `Command.PARENT` were not tested. |
| **tool_call_id reliability** | The once-per-call-id guard depends on the framework and provider producing a unique id per model tool call. That was true with the scripted model; real providers were not tested. |
| **Provider built-in tools** | `dict` tools run on the provider's side. They cannot be wrapped or observed in-process. |
| **Framework internals** | Coverage inspection reads an internal attribute path, and `create_react_agent` is already deprecated in favour of `create_agent`. |

## 8. Is Design B still suitable? Recommended v1 compatibility scope

**RECOMMENDATION:** yes, with the following required adapter behaviours. All were demonstrated in the prototype.

1. **Convert every original exception after the function has been entered into a fixed-text in-tool `ToolException`** (`"tool failed (execution may have occurred)"`). Never let the original exception reach the framework (§6). This is the retry fix.
2. **Optionally add an at-most-once-per-`tool_call_id` guard** as defence in depth, keyed in production by at least agent, session/thread and call id (uniqueness was not verified across providers).
3. **Claim decisions atomically**, using a lock that works for both threads and asyncio (the racy control shows a naive check-then-act fails).
4. **Mark `interrupted` for any `BaseException`** that escapes after the function was entered (cancellation), then re-raise.
5. **Return-handling contract for `Command`:** on ALLOW return the original return value **unchanged** (`str`, `ToolMessage` or `Command`); on non-ALLOW or failure return only an error `ToolMessage` via `ToolException`, **never** a `Command`; forward `InjectedToolCallId` outside the evaluated action; refuse all other injected parameters.
6. **Async:** keep async-native tools async-native and run the (blocking) pipeline in a worker thread so it never blocks the event loop.
7. **Fixed-text messages only** (no exception `repr`, no policy details), as in C-02.
8. **Expose a coverage report** so unwrapped or middleware-supplied tools are never represented as protected.

**Suggested v1 compatibility scope (for owner decision):**

| In scope (tested here) | Out of scope / refused (documented) |
|---|---|
| Sync function tools (`@tool`, `StructuredTool`) | Provider built-in (`dict`) tools |
| Async-native tools, through async entry points | Class-based `BaseTool` subclasses without `.func` / `.coroutine` |
| `Command`-returning tools whose only injected parameter is `InjectedToolCallId` (sync or async) | Tools with other injected parameters (`InjectedState`, `InjectedStore`, `ToolRuntime`) |
| Tools passed to `create_agent` or a LangGraph `ToolNode` | Tools added by middleware; any unwrapped tool |
| | `Command` with `Send` / `Command.PARENT`; human-in-the-loop middleware; structured-output tools; `return_direct` / artifact responses; checkpoint resume (all **untested**) |

## 9. Not demonstrated (UNRESOLVED)

- **Full framework coverage.** Only the patterns above were tested; nothing here supports a claim beyond them.
- A real LLM and real provider `tool_call_id` behaviour; duplicate or missing ids.
- `HumanInTheLoopMiddleware` and interrupts (relevant to a future approval workflow); checkpointer resume or replay (a resumed node would re-enter the adapter).
- `Command` with `Send`, `Command.PARENT` or other routing; tools returning `ToolMessage` directly; `content_and_artifact` response formats; structured-output / `response_format` tools; `return_direct`.
- Other Python versions, operating systems or framework versions.
- Sentinel's real pipeline: its audit writes, and mapping a real `PipelineResult` into a tool return value.
- Performance, and thread-safety of a real SQLite audit store under parallel tool execution.

## 10. Proposed contract changes (NOT applied; owner approval required)

| Area | Proposed change |
|---|---|
| **D-12 / C3.2 / C3.3** | Extend the Design B contract: async-native and `Command` tools in scope under §8's return-handling rules; add the refusal list; add a coverage-report requirement. D-12 stays **Pending** until you decide. |
| **C1.6 / C1.7 / FR-017** | `execution="unknown"` **is reachable in-process** (cancellation), contrary to the current text. The pipeline should record `EXECUTION_STARTED`, and on any `BaseException` after that point write a best-effort completion with `execution="unknown"` and re-raise. Revise the "not produced by the in-process pipeline" statement. |
| **C1.4 / D-07** | State that decision claiming is **atomic across threads and asyncio**, and add the concurrency test (racy control included) to the acceptance criteria. |
| **New decision** | At-most-once per framework `tool_call_id` (key, scope and lifetime; behaviour on checkpoint resume; the duplicate-attempt audit semantics). Optional defence in depth, not the primary retry fix. |
| **FR-018 / D-03** | Confirm that adapters convert post-execution failures to fixed-text in-tool exceptions rather than raising Sentinel exceptions into the framework (this strengthens the C-02 proposal with retry-matrix evidence). |
| **SEC-016** | The C-02 proposal to narrow "async fails closed" stands, and is now evidenced for async-native tools: the sync entry fails before the adapter, async entry is gated. |
| **New requirement** | The adapter exposes a coverage report, with a documented dependency on framework internals (see §7). |
| **`pyproject.toml`** | As in C-02: add `spikes/` to Ruff's `extend-exclude`. This task did not touch `pyproject.toml`. The spike files carry a file-level `# ruff: noqa`, are formatted, and pass the project's Ruff. No suppression exists in production code. |

## 11. Method notes and limitations

- **Checks I got wrong and fixed:** the first full run showed 2 failing checks in my D4–D5 matrix. The cause was my expectation, not the boundary: an async-only tool entered through a *sync* entry point fails inside the framework before the adapter, so "evaluated once" was the wrong assertion. I split those 4 rows out (§5). Two claims rested on a throwaway smoke test (class-based refusal; hidden `tool_call_id` schema), so I added them as recorded checks.
- **Test power:** concurrency, bypass and duplicate-execution controls exist to show the harness can fail (racy control 50/50; unwrapped tools executed; naive propagation re-executed).
- **Repeats:** five consecutive runs gave identical pass counts and identical retry-matrix outcomes; three more followed the last edit.
- One machine, one framework version set, scripted model, toy gate. Results are evidence for *this* configuration.

## 12. Repository impact and cleanup

- **Added (untracked, nothing committed), under `spikes/langchain_compatibility/`:** `standin_c.py`, `run_c02b.py`, `requirements-freeze.txt`, `README.md`, `results/` (`results_c02b.json`, `transcript_c02b.txt`). Plus this report.
- **Unchanged:** `src/`, `tests/`, `pyproject.toml`, `constraints-dev.txt`, `.github/`, the C-02 spike files, the decision register, and the commit history. Nothing was committed, pushed, or renamed.
- **Cleanup:** the disposable `spikes/langchain_compatibility/.venv` (git-ignored) was removed after the results, freeze file and transcript were preserved. Recreate it with §3.
