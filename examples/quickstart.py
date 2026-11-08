"""Sentinel quickstart: register a tool and an agent, evaluate tool calls.

Run from a checkout after ``python -m pip install -e ".[dev]" -c
constraints-dev.txt``::

    python examples/quickstart.py

The audit database is created in a temporary directory and removed at the
end. This pre-release has no threat detection (C-13) and no real output
filtering (C-14): the example shows authorization and auditing only.
"""

import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sentinel import SecurityPolicy, SentinelClient, SentinelConfig, ToolGrant


class AddArgs(BaseModel):
    """Arguments of the ``add`` tool. Unknown keys are refused."""

    model_config = ConfigDict(extra="forbid")

    a: int
    b: int


def add(a: int, b: int) -> int:
    """A harmless tool."""
    return a + b


def subtract(a: int, b: int) -> int:
    """Another harmless tool, registered but not granted to the agent."""
    return a - b


def main() -> None:
    """Run two requests and print the results and the audit trail."""
    with tempfile.TemporaryDirectory() as tmp:
        config = SentinelConfig(
            audit_db_path=str(Path(tmp) / "audit.db"),
            require_credentials=False,  # identity by agent id alone, for the demo
        )
        with SentinelClient(SecurityPolicy(version="quickstart-1"), config) as client:
            client.register_tool(
                "add", arg_schema=AddArgs, destructive=False, sync_fn=add
            )
            client.register_tool(
                "subtract", arg_schema=AddArgs, destructive=False, sync_fn=subtract
            )
            client.register_agent("calculator_agent", grants=(ToolGrant(tool="add"),))

            allowed = client.evaluate_request(
                {
                    "agent_id": "calculator_agent",
                    "session_id": "demo",
                    "tool": "add",
                    "arguments": {"a": 2, "b": 3},
                }
            )
            print(
                f"add:      decision={allowed.decision.value} "
                f"execution={allowed.execution.value} output={allowed.output}"
            )

            denied = client.evaluate_request(
                {
                    "agent_id": "calculator_agent",
                    "session_id": "demo",
                    "tool": "subtract",
                    "arguments": {"a": 2, "b": 3},
                }
            )
            print(
                f"subtract: decision={denied.decision.value} reason={denied.reason} "
                f"execution={denied.execution.value}"
            )

            events = client.audit_events(allowed.request_id)
            print("audit:    " + " > ".join(event.event_type for event in events))


if __name__ == "__main__":
    main()
