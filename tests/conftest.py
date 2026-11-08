"""Shared fixtures for the pipeline suites (C-11): the testing §8 walking
skeleton, with spy tools and audit fault injection."""

import asyncio
import sqlite3
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict

from sentinel.audit import AuditLogger
from sentinel.exceptions import AuditUnavailableError
from sentinel.identity import IdentityStore
from sentinel.models import ToolGrant
from sentinel.pipeline import Pipeline
from sentinel.policy import PolicyEngine, SecurityPolicy
from sentinel.proxy import ExecutionProxy, ToolCallGuard, pass_through_filter
from sentinel.registry import ToolRegistry
from sentinel.store import AuditStore

T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class PathArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class EmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str
    body: str


class Env:
    """The testing §8 fixture: workspace, tools, agent, policy, pipeline."""

    def __init__(
        self,
        tmp_path,
        *,
        output_filter=pass_through_filter,
        detector=None,
        db_path=None,
        guard=None,
        policy=None,
    ):
        self.tmp_path = tmp_path
        self.ws = tmp_path / "ws"
        self.ws.mkdir()
        (self.ws / "data.txt").write_text("hello")
        (self.ws / "sub").mkdir()
        (self.ws / "sub" / "b.txt").write_text("inside-b")
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("secret")
        self.db = db_path if db_path is not None else tmp_path / "audit.db"
        self.calls = {"read": 0, "delete": 0, "email": 0, "aread": 0}
        self.seen_in_spy = []
        self.raise_in_tool = None
        self.tool_hook = None

        self.registry = ToolRegistry()
        self.registry.register(
            "read_file",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            sync_fn=self.read_file,
        )
        self.registry.register(
            "delete_file",
            arg_schema=PathArgs,
            destructive=True,
            path_args=("path",),
            sync_fn=self.delete_file,
        )
        self.registry.register(
            "send_email",
            arg_schema=EmailArgs,
            destructive=False,
            sync_fn=self.send_email,
        )
        self.registry.register(
            "aread_file",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            async_fn=self.aread_file,
        )
        self.identity = IdentityStore(self.registry, require_credentials=False)
        prefix = (str(self.ws),)
        grants = tuple(
            ToolGrant(tool=t, allowed_path_prefixes=prefix)
            for t in ("read_file", "delete_file", "aread_file")
        )
        self.identity.register_agent("research_agent", grants=grants)
        self.identity.register_agent("other_agent", grants=grants)
        self.store = AuditStore(self.db)
        self.logger = AuditLogger(self.store, clock=lambda: T0)
        self.guard = guard if guard is not None else ToolCallGuard()
        self.proxy = ExecutionProxy(
            self.registry, output_filter=output_filter, guard=self.guard
        )
        self.pipeline = Pipeline(
            registry=self.registry,
            identity=self.identity,
            policy=PolicyEngine(policy or SecurityPolicy(version="test-1")),
            audit=self.logger,
            proxy=self.proxy,
            detector=detector,
            clock=lambda: T0,
        )
        self.failing = set()
        real_insert = self.store.insert

        def insert(row):
            if row.event_type in self.failing:
                raise AuditUnavailableError("injected")
            return real_insert(row)

        self.store.insert = insert

    # ------------------------------------------------------- spies
    def _committed_events(self):
        if str(self.db) == ":memory:":
            return []  # nothing to inspect from another connection
        with sqlite3.connect(self.db) as conn:
            last = conn.execute(
                "SELECT request_id FROM audit_events "
                "WHERE event_type='REQUEST_RECEIVED' ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if last is None:
                return []
            return conn.execute(
                "SELECT event_type, decision, action_digest FROM audit_events "
                "WHERE request_id=? ORDER BY seq",
                last,
            ).fetchall()

    def _enter(self, name):
        self.calls[name] += 1
        self.seen_in_spy.append(self._committed_events())
        if self.tool_hook is not None:
            self.tool_hook()
        if self.raise_in_tool is not None:
            raise self.raise_in_tool

    def read_file(self, path):
        self._enter("read")
        with open(path) as handle:
            return handle.read()

    def delete_file(self, path):
        self._enter("delete")
        return "deleted"

    def send_email(self, to, body):
        self._enter("email")
        return "sent"

    async def aread_file(self, path):
        self._enter("aread")
        await asyncio.sleep(0)
        with open(path) as handle:
            return handle.read()

    # ------------------------------------------------------ helpers
    def raw(self, tool="read_file", arguments=None, agent_id="research_agent", **extra):
        if arguments is None:
            arguments = {"path": str(self.ws / "data.txt")}
        return {
            "agent_id": agent_id,
            "session_id": extra.pop("session_id", "sess-1"),
            "tool": tool,
            "arguments": arguments,
            **extra,
        }

    def events(self, request_id):
        with sqlite3.connect(self.db) as conn:
            return [
                r[0]
                for r in conn.execute(
                    "SELECT event_type FROM audit_events "
                    "WHERE request_id=? ORDER BY seq",
                    (request_id,),
                )
            ]

    def rows(self, request_id):
        return self.store.read(request_id)

    def total_calls(self):
        return sum(self.calls.values())


@pytest.fixture
def make_env(tmp_path):
    created = []

    def factory(**kwargs):
        sub = tmp_path / f"env{len(created)}"
        sub.mkdir()
        env = Env(sub, **kwargs)
        created.append(env)
        return env

    yield factory
    for env in created:
        env.store.close()


@pytest.fixture
def env(make_env):
    return make_env()
