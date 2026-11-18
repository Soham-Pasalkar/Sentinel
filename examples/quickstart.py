"""Sentinel quickstart: register tools and agents, then evaluate tool calls.

Run from a checkout after ``python -m pip install -e ".[dev]" -c
constraints-dev.txt``::

    python examples/quickstart.py

It demonstrates the FR-023 scenarios through the public API only:

1. an allowed call that executes;
2. a path traversal out of the granted workspace (denied);
3. a registered tool the agent was not granted (denied);
4. an unknown agent (denied);
5. a destructive tool, which requires approval and never runs in this version;

and prints each request's audit rows and how often each tool actually ran.

Everything happens in a temporary directory (a workspace, a directory
outside it, and the audit database), which is removed at the end. The tools
are harmless: the path tool reads only files the example creates, and the
"destructive" tool only returns a string. This pre-release has no threat
detection (C-13) and no real output filtering (C-14): the example shows
authorization and auditing only.
"""

import tempfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from sentinel import SecurityPolicy, SentinelClient, SentinelConfig, ToolGrant

# How often each tool function was actually entered (counted by the tools).
CALLS = {"add": 0, "subtract": 0, "read_file": 0, "delete_note": 0}


class NumbersArgs(BaseModel):
    """Arguments of ``add`` and ``subtract``. Unknown keys are refused."""

    model_config = ConfigDict(extra="forbid")

    a: int
    b: int


class PathArgs(BaseModel):
    """Arguments of ``read_file``: one absolute path."""

    model_config = ConfigDict(extra="forbid")

    path: str


class NoteArgs(BaseModel):
    """Arguments of ``delete_note``."""

    model_config = ConfigDict(extra="forbid")

    note: str


def add(a: int, b: int) -> int:
    """A harmless tool, granted to the agent."""
    CALLS["add"] += 1
    return a + b


def subtract(a: int, b: int) -> int:
    """A harmless tool, registered but not granted to the agent."""
    CALLS["subtract"] += 1
    return a - b


def read_file(path: str) -> str:
    """Read a file; Sentinel lets it see only paths under its granted prefix."""
    CALLS["read_file"] += 1
    return Path(path).read_text()


def delete_note(note: str) -> str:
    """Registered as destructive; harmless here (it deletes nothing)."""
    CALLS["delete_note"] += 1
    return f"would delete {note}"


def describe(event) -> str:
    """One audit row: the event type and the outcome fields it carries."""
    parts = [event.event_type]
    if event.decision is not None:
        parts.append(f"decision={event.decision.value}")
    if event.reason is not None:
        parts.append(f"reason={event.reason}")
    if event.execution is not None:
        parts.append(f"execution={event.execution.value}")
    return " ".join(parts)


def main() -> None:
    """Run the five requests and print results, audit rows and call counts."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        workspace = root / "workspace"
        outside = root / "outside"
        workspace.mkdir()
        outside.mkdir()
        (workspace / "notes.txt").write_text("hello from the workspace")
        (outside / "secret.txt").write_text("not for agents")

        config = SentinelConfig(
            audit_db_path=str(root / "audit.db"),
            require_credentials=False,  # identity by agent id alone, for the demo
        )
        with SentinelClient(SecurityPolicy(version="quickstart-1"), config) as client:
            client.register_tool(
                "add", arg_schema=NumbersArgs, destructive=False, sync_fn=add
            )
            client.register_tool(
                "subtract", arg_schema=NumbersArgs, destructive=False, sync_fn=subtract
            )
            client.register_tool(
                "read_file",
                arg_schema=PathArgs,
                destructive=False,
                path_args=("path",),
                sync_fn=read_file,
            )
            client.register_tool(
                "delete_note",
                arg_schema=NoteArgs,
                destructive=True,
                sync_fn=delete_note,
            )
            client.register_agent(
                "calculator_agent",
                grants=(
                    ToolGrant(tool="add"),
                    ToolGrant(
                        tool="read_file", allowed_path_prefixes=(str(workspace),)
                    ),
                    ToolGrant(tool="delete_note"),
                ),
            )

            requests = [
                ("allow", "calculator_agent", "add", {"a": 2, "b": 3}),
                (
                    "traversal",
                    "calculator_agent",
                    "read_file",
                    {"path": f"{workspace}/../outside/secret.txt"},
                ),
                ("ungranted", "calculator_agent", "subtract", {"a": 2, "b": 3}),
                ("unknown agent", "intruder_agent", "add", {"a": 2, "b": 3}),
                ("approval", "calculator_agent", "delete_note", {"note": "draft"}),
            ]
            for label, agent_id, tool, arguments in requests:
                result = client.evaluate_request(
                    {
                        "agent_id": agent_id,
                        "session_id": "demo",
                        "tool": tool,
                        "arguments": arguments,
                    }
                )
                print(
                    f"{label}: {tool} decision={result.decision.value} "
                    f"reason={result.reason} execution={result.execution.value} "
                    f"output={result.output}"
                )
                for event in client.audit_events(result.request_id):
                    print(f"  audit: {describe(event)}")

        print("calls: " + " ".join(f"{name}={count}" for name, count in CALLS.items()))


if __name__ == "__main__":
    main()
