# Sentinel

> **Status: pre-release (milestone M1 implemented, not yet signed off).** Sentinel authorizes, executes and audits tool calls routed through `SentinelClient`. Threat detection, output filtering, rate limits and framework adapters are **not implemented yet**. Do not rely on it as your only security control.

Sentinel is a runtime security library for AI agent systems. It sits between agents and the tools they invoke and decides, for each tool call, whether that call may execute. A call that Sentinel denies, or that requires approval, never executes. Every step is recorded in a local audit log.

## Quickstart

```python
from pydantic import BaseModel, ConfigDict

from sentinel import SecurityPolicy, SentinelClient, SentinelConfig, ToolGrant


class AddArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")  # required: unknown keys are refused
    a: int
    b: int


def add(a: int, b: int) -> int:
    return a + b


config = SentinelConfig(audit_db_path="audit.db", require_credentials=False)
with SentinelClient(SecurityPolicy(version="v1"), config) as client:
    client.register_tool("add", arg_schema=AddArgs, destructive=False, sync_fn=add)
    client.register_agent("calculator_agent", grants=(ToolGrant(tool="add"),))
    result = client.evaluate_request(
        {
            "agent_id": "calculator_agent",
            "session_id": "s1",
            "tool": "add",
            "arguments": {"a": 2, "b": 3},
        }
    )
    print(result.decision, result.execution, result.output)  # allow succeeded 5
    print([e.event_type for e in client.audit_events(result.request_id)])
```

A runnable version is in [`examples/quickstart.py`](examples/quickstart.py) (`python examples/quickstart.py`; it uses a temporary database and leaves no file behind).

## How a request is handled

`evaluate_request(raw)` runs every call through one pipeline:

**request validation → agent identity and grants → detection → deterministic policy decision → controlled execution → output filter**

- `raw` is built by **trusted application code**: `agent_id` and `session_id` come from your application; only `tool` and `arguments` come from the model. Identity keys inside `arguments` are refused.
- Arguments are validated once, strictly (no type coercion), against the tool's schema. Path arguments are made absolute and canonical.
- Default deny: an agent may use a tool only with an explicit `ToolGrant`; a grant covers the whole registered tool. Paths must lie under the grant's prefixes. Destructive tools require approval by default, and an approval-required call is never executed in this version.
- The decision is bound to the exact validated call. It is used at most once, and a framework `tool_call_id` is executed at most once per agent and session within the guard's lifetime.
- Each audit event is committed before the next stage runs. The tool runs only after its `EXECUTION_STARTED` event is committed.
- The result says what actually happened: the policy `decision` (`allow`, `deny`, `require_approval`, or `None` for operational refusals and internal errors), the `execution` state, whether output was released, whether the audit is complete, and a stable `error_code`. `evaluate_request` returns for every request outcome; it raises only if `raw` is not a mapping.

The contracts and the decisions behind them are in [`docs/aidlc/01-inception/decision_record.md`](docs/aidlc/01-inception/decision_record.md), the canonical decision register.

## Public API

Everything in `sentinel.__all__` is public; every other module and name is internal and may change.

| Name | Purpose |
|---|---|
| `SentinelClient(policy, config=None)` | The client. Methods: `register_tool`, `register_agent`, `evaluate_request`, `audit_events`, `close`; usable with `with` |
| `SentinelConfig` | `audit_db_path` (default `sentinel_audit.db`), `require_credentials` (default `True`), `guard_ttl_seconds` (300), `guard_capacity` (10,000) |
| `SecurityPolicy` | `version`, `deny_at_severity` (default `Severity.HIGH`), `require_approval_for_destructive` (default `True`) |
| `ToolGrant` | `tool`, `allowed_path_prefixes` |
| `PipelineResult`, `Decision`, `Execution`, `Severity` | Result and enum types |
| `AuditEvent` | An immutable audit record returned by `audit_events` |
| `SentinelError`, `ConfigurationError`, `RegistrationError`, `InvalidRequestError`, `AuditUnavailableError` | Exceptions |

- `register_tool(name, *, arg_schema, destructive, path_args=(), sync_fn=None, async_fn=None)`. Names are unique, `arg_schema` must forbid extra fields, and `destructive` must be stated.
- `register_agent(agent_id, *, credential=None, user_id=None, disabled=False, grants=())`. Register tools first, then agents; credentials are `SecretStr` values, stored as digests.
- `audit_events(request_id=None, limit=100)` is read-only. It returns at most `limit` events (1 to 1,000), the first in sequence order, and raises `AuditUnavailableError` if the store cannot be read.
- `close()` closes the audit store; afterwards requests return `AUDIT_UNAVAILABLE` and nothing runs.

## Current status

| Component | Status |
|---|---|
| Models, action digest, exceptions (C-03a, C-03) | implemented |
| Filesystem path guard (C-04) | implemented; path arguments only, not a sandbox |
| Tool registry (C-05) | implemented |
| Request gateway (C-06) | implemented |
| Identity and tool-level grants (C-07) | implemented |
| Policy engine (C-08) | implemented; rate-limit row deferred to C-15 |
| Audit store and logger (C-09) | implemented; local SQLite, append-only through Sentinel's API |
| Execution proxy (C-10) | implemented |
| Pipeline (C-11) | implemented |
| Public client, quickstart (C-12) | implemented |
| Threat detection (C-13) | **not implemented**: the detector finds nothing |
| Output filtering (C-14) | **not implemented**: the output filter is a pass-through |
| Rate limits (C-15) | **not implemented**: grants with a rate limit are refused |
| Framework adapters, LangGraph and LangChain (C-16) | **not implemented**; design approved (D-12) |

Milestone M1 is implemented. Its gate (G-M1) is **not yet closed**: it also requires a coverage measurement, which needs a development tool not yet approved (decision D-22), and an owner review.

## Known limitations

- **In-process only.** Sentinel constrains only tool calls routed through `SentinelClient`. Code in the same process can call tools directly, forge decisions or patch Sentinel.
- **No detection or output filtering yet.** Until C-13 and C-14, prompt injection and sensitive data in arguments or outputs are not detected. When added, detection will be heuristic: it reduces risk and does not prevent prompt injection.
- **Granted tools are trusted with their arguments.** A grant covers a whole tool; free-form arguments (SQL, shell, URLs) are only as safe as the tool and its schema.
- **Paths are authorized, not isolated.** A symlink swapped after the final check, hard links, paths a tool derives internally, and mount boundaries are not covered. Path-constrained tools are supported on Linux and macOS only; registering one on Windows is refused.
- **The audit log is not tamper-proof.** It is append-only through Sentinel's API only. Anyone with write access to the file can change it; durability depends on the filesystem honouring `fsync`; one process per file. Masking of secrets in audit records is heuristic.
- **No exactly-once side effects.** If a tool ran and a later step failed (filter, audit), the side effect is not undone, and the result says so. A new call with a new `tool_call_id` is a new request. The at-most-once guards are process-local.
- **An in-memory audit store (`":memory:"`) never releases output**, because its audit is never complete.
- **No public async API.** An internal async entry exists for future framework adapters.

The full lists are in the decision register (§2, §4.6, §6) and [`docs/aidlc/01-inception/threat_model.md`](docs/aidlc/01-inception/threat_model.md).

## Requirements

- Python 3.11 or newer. Runtime dependency: Pydantic v2. CI tests 3.11, 3.12 and 3.13 on Linux (`ubuntu-latest`) and macOS (`macos-latest`) on every push to the development branch and on pull requests.

## Installation and development setup

Create a project-local virtual environment and install the package in editable mode with the development tools (pytest, Ruff):

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]" -c constraints-dev.txt
```

`constraints-dev.txt` pins the exact versions used to verify the project, so local and CI runs use the same versions.

## Running tests and linting

```bash
pytest                     # tests
ruff check .               # lint
ruff format --check .      # formatting check (use `ruff format .` to apply)
python examples/quickstart.py
```

The same checks run in GitHub Actions (`.github/workflows/ci.yml`) on every push to `main` or `c01-project-scaffold` and on every pull request.

## Package name

The distribution name `sentinel-ai` and import name `sentinel` are **provisional** (decision D-02). Their availability on PyPI has not been checked. The package carries the `Private :: Do Not Upload` classifier to prevent accidental publication.

## License

No license has been chosen yet.
