"""SentinelClient end to end (C-12): FR-013, FR-016, FR-017, FR-018, D-17,
D-24i, D-30 (AT-34); E2E-01 … E2E-09 through the public client; I-32 to I-35.

Everything goes through ``SentinelClient``. Only fault injection reaches
into internals, to make the audit store fail.
"""

import dataclasses
import inspect
import os
import sqlite3
import types
import uuid

import pytest
from pydantic import BaseModel, ConfigDict, SecretStr

import sentinel
from sentinel import (
    AuditEvent,
    AuditUnavailableError,
    ConfigurationError,
    Decision,
    Execution,
    InvalidRequestError,
    PipelineResult,
    RegistrationError,
    SecurityPolicy,
    SentinelClient,
    SentinelConfig,
    SentinelError,
    ToolGrant,
)
from sentinel.exceptions import AuditIntegrityError


class PathArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class EmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to: str
    body: str


class ClientEnv:
    """The testing §8 fixture, through the public client."""

    def __init__(self, tmp_path, *, require_credentials=False):
        self.ws = tmp_path / "ws"
        self.ws.mkdir()
        (self.ws / "data.txt").write_text("hello")
        self.outside = tmp_path / "outside"
        self.outside.mkdir()
        (self.outside / "secret.txt").write_text("secret")
        self.db = tmp_path / "audit.db"
        self.calls = {"read": 0, "delete": 0, "email": 0, "aread": 0}
        self.raise_in_tool = None
        self.client = SentinelClient(
            SecurityPolicy(version="test-1"),
            SentinelConfig(
                audit_db_path=str(self.db), require_credentials=require_credentials
            ),
        )
        c = self.client
        c.register_tool(
            "read_file",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            sync_fn=self.read_file,
        )
        c.register_tool(
            "delete_file",
            arg_schema=PathArgs,
            destructive=True,
            path_args=("path",),
            sync_fn=self.delete_file,
        )
        c.register_tool(
            "send_email",
            arg_schema=EmailArgs,
            destructive=False,
            sync_fn=self.send_email,
        )
        c.register_tool(
            "aread_file",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            async_fn=self.aread_file,
        )
        prefix = (str(self.ws),)
        c.register_agent(
            "research_agent",
            grants=tuple(
                ToolGrant(tool=t, allowed_path_prefixes=prefix)
                for t in ("read_file", "delete_file")
            ),
        )

    def read_file(self, path):
        self.calls["read"] += 1
        if self.raise_in_tool:
            raise self.raise_in_tool
        with open(path) as handle:
            return handle.read()

    def delete_file(self, path):
        self.calls["delete"] += 1
        return "deleted"

    def send_email(self, to, body):
        self.calls["email"] += 1
        return "sent"

    async def aread_file(self, path):
        self.calls["aread"] += 1
        return "x"

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

    def fail(self, *event_types):
        store = self.client._pipeline.audit.store
        real = type(store).insert

        def insert(row):
            if row.event_type in event_types:
                raise AuditUnavailableError("injected")
            return real(store, row)

        store.insert = insert

    def types(self, request_id):
        return [e.event_type for e in self.client.audit_events(request_id)]


@pytest.fixture
def env(tmp_path):
    e = ClientEnv(tmp_path)
    yield e
    e.client.close()


def outcome(r):
    return (r.decision, r.reason, r.execution, r.output_released, r.audit_complete)


RR, IR, DEC, ES, OF, RC = (
    "REQUEST_RECEIVED",
    "IDENTITY_RESOLVED",
    "DECISION",
    "EXECUTION_STARTED",
    "OUTPUT_FILTERED",
    "REQUEST_COMPLETED",
)


# ============================================================ public API


def test_public_import_and_exact_exports():
    from sentinel import SentinelClient as Imported

    assert Imported is SentinelClient
    assert SentinelClient.__module__ == "sentinel.client"
    internal = {
        "Pipeline",
        "build_pipeline",
        "ExecutionProxy",
        "ProxyRun",
        "ToolCallGuard",
        "AuditStore",
        "AuditLogger",
        "IdentityStore",
        "PolicyEngine",
        "ToolRegistry",
        "validate_request",
        "NullDetector",
        "ActionDenied",
        "ApprovalRequired",
    }
    assert not internal & set(sentinel.__all__)
    assert not any(hasattr(sentinel, n) for n in internal)


def test_public_signatures_are_stable():
    sig = inspect.signature
    assert list(sig(SentinelClient).parameters) == ["policy", "config"]
    assert list(sig(SentinelClient.register_tool).parameters) == [
        "self",
        "name",
        "arg_schema",
        "destructive",
        "path_args",
        "sync_fn",
        "async_fn",
    ]
    assert list(sig(SentinelClient.register_agent).parameters) == [
        "self",
        "agent_id",
        "credential",
        "user_id",
        "disabled",
        "grants",
    ]
    assert list(sig(SentinelClient.evaluate_request).parameters) == ["self", "raw"]
    params = sig(SentinelClient.audit_events).parameters
    assert list(params) == ["self", "request_id", "limit"]
    assert (params["request_id"].default, params["limit"].default) == (None, 100)


def test_no_public_async_entry_or_internal_access():
    # AT-34: no async method on SentinelClient (D-30).
    public = {n for n in dir(SentinelClient) if not n.startswith("_")}
    assert public == {
        "register_tool",
        "register_agent",
        "evaluate_request",
        "audit_events",
        "close",
    }
    assert not any(
        inspect.iscoroutinefunction(getattr(SentinelClient, n)) for n in public
    )


def test_defaults_use_the_durable_file_in_the_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with SentinelClient(SecurityPolicy(version="v")) as client:
        assert (tmp_path / "sentinel_audit.db").is_file()
        client.register_tool(
            "t", arg_schema=EmailArgs, destructive=False, sync_fn=lambda to, body: 1
        )
        client.register_agent("a", grants=(ToolGrant(tool="t"),))
        r = client.evaluate_request(
            {
                "agent_id": "a",
                "session_id": "s",
                "tool": "t",
                "arguments": {"to": "x", "body": "y"},
            }
        )
        # require_credentials defaults to True: no credential, no access.
        assert (r.decision, r.reason) == (Decision.DENY, "UNAUTHORIZED_AGENT")


def test_invalid_configuration_and_policy(tmp_path):
    with pytest.raises(ConfigurationError):
        SentinelConfig(guard_capacity=0)
    with pytest.raises(ConfigurationError):
        SentinelClient(SecurityPolicy(version="v"), {"audit_db_path": "x"})
    with pytest.raises(ConfigurationError):
        SentinelClient(
            SecurityPolicy(version="v"),
            SentinelConfig(audit_db_path=str(tmp_path / "no" / "a.db")),
        )
    with pytest.raises(ConfigurationError):
        SentinelClient(
            {"version": "v"}, SentinelConfig(audit_db_path=str(tmp_path / "a.db"))
        )


def test_memory_store_is_explicit_and_never_releases_output(tmp_path):
    with SentinelClient(
        SecurityPolicy(version="v"),
        SentinelConfig(audit_db_path=":memory:", require_credentials=False),
    ) as c:
        c.register_tool(
            "t", arg_schema=EmailArgs, destructive=False, sync_fn=lambda to, body: "out"
        )
        c.register_agent("a", grants=(ToolGrant(tool="t"),))
        r = c.evaluate_request(
            {
                "agent_id": "a",
                "session_id": "s",
                "tool": "t",
                "arguments": {"to": "x", "body": "y"},
            }
        )
        assert (r.execution, r.audit_complete, r.output) == (
            Execution.SUCCEEDED,
            False,
            None,
        )


# =========================================================== registration


def test_duplicate_and_invalid_tools_are_refused(env):
    c = env.client
    with pytest.raises(RegistrationError):
        c.register_tool(
            "read_file", arg_schema=PathArgs, destructive=False, sync_fn=env.read_file
        )

    class Loose(BaseModel):
        path: str

    for kwargs in (
        {"arg_schema": Loose, "destructive": False, "sync_fn": len},
        {"arg_schema": PathArgs, "sync_fn": len},
        {"destructive": False, "sync_fn": len},
        {"arg_schema": PathArgs, "destructive": "no", "sync_fn": len},
        {"arg_schema": PathArgs, "destructive": False},
        {
            "arg_schema": PathArgs,
            "destructive": False,
            "path_args": ("missing",),
            "sync_fn": len,
        },
    ):
        with pytest.raises(RegistrationError):
            c.register_tool("new_tool", **kwargs)


def test_path_tool_on_windows_is_refused(env, monkeypatch):
    from sentinel import paths

    fake = types.SimpleNamespace(name="nt", path=os.path, fsencode=os.fsencode)
    monkeypatch.setattr(paths, "os", fake)
    with pytest.raises(ConfigurationError):
        env.client.register_tool(
            "winpath",
            arg_schema=PathArgs,
            destructive=False,
            path_args=("path",),
            sync_fn=len,
        )
    env.client.register_tool(
        "winplain", arg_schema=EmailArgs, destructive=False, sync_fn=len
    )


def test_registration_never_runs_the_tool(env):
    calls = []
    env.client.register_tool(
        "spy",
        arg_schema=EmailArgs,
        destructive=False,
        sync_fn=lambda **k: calls.append(1),
    )
    assert calls == []


def test_agent_registration_rules(env, tmp_path):
    c = env.client
    with pytest.raises(RegistrationError):
        c.register_agent("research_agent")  # duplicate
    with pytest.raises(RegistrationError):
        c.register_agent("x", grants=(ToolGrant(tool="unknown"),))
    with pytest.raises(ConfigurationError):
        c.register_agent(
            "y",
            grants=(
                ToolGrant(
                    tool="read_file", allowed_path_prefixes=(str(tmp_path / "nope"),)
                ),
            ),
        )
    with pytest.raises(RegistrationError):
        c.register_agent("z", credential="plain-text")


def test_credentials_are_enforced_and_never_exposed(tmp_path):
    canary = "CANARY-" + uuid.uuid4().hex
    e = ClientEnv(tmp_path, require_credentials=True)
    try:
        e.client.register_agent(
            "secure",
            credential=SecretStr(canary),
            grants=(ToolGrant(tool="send_email"),),
        )
        args = {"to": "a", "body": "b"}
        ok = e.client.evaluate_request(
            {**e.raw("send_email", args, agent_id="secure"), "auth_token": canary}
        )
        bad = e.client.evaluate_request(
            {**e.raw("send_email", args, agent_id="secure"), "auth_token": "wrong"}
        )
        missing = e.client.evaluate_request(
            e.raw("send_email", args, agent_id="secure")
        )
        assert ok.decision is Decision.ALLOW and ok.output == "sent"
        assert bad.reason == missing.reason == "UNAUTHORIZED_AGENT"
        text = (
            repr(e.client.audit_events(limit=1000)) + repr(ok) + repr(e.client.__dict__)
        )
        with sqlite3.connect(e.db) as conn:
            text += repr(conn.execute("SELECT * FROM audit_events").fetchall())
        assert canary not in text
    finally:
        e.client.close()


# ======================================================= E2E-01 … E2E-09


def test_e2e_01_allowed(env):
    r = env.client.evaluate_request(env.raw())
    assert isinstance(r, PipelineResult)
    assert outcome(r) == (Decision.ALLOW, "ALLOWED", Execution.SUCCEEDED, True, True)
    assert r.output == "hello" and env.calls["read"] == 1
    assert env.types(r.request_id) == [RR, IR, DEC, ES, OF, RC]


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("e2e-02", (Decision.DENY, "RESTRICTED_PATH")),
        ("e2e-03", (Decision.DENY, "UNAUTHORIZED_TOOL")),
        ("e2e-04", (Decision.DENY, "UNAUTHORIZED_AGENT")),
        ("e2e-05", (Decision.REQUIRE_APPROVAL, "DESTRUCTIVE_TOOL")),
        ("e2e-06", (None, "INVALID_REQUEST")),
        ("e2e-08", (None, "INVALID_REQUEST")),
    ],
)
def test_non_executing_scenarios(env, case, expected):
    raw = {
        "e2e-02": env.raw(arguments={"path": str(env.ws) + "/../outside/secret.txt"}),
        "e2e-03": env.raw("send_email", {"to": "a", "body": "b"}),
        "e2e-04": env.raw(agent_id="unknown_agent"),
        "e2e-05": env.raw("delete_file"),
        "e2e-06": {"agent_id": "research_agent"},
        "e2e-08": env.raw(
            arguments={"path": str(env.ws / "data.txt"), "agent_id": "admin"}
        ),
    }[case]
    r = env.client.evaluate_request(raw)
    assert (r.decision, r.reason) == expected
    assert r.execution is Execution.NOT_STARTED and r.audit_complete
    assert sum(env.calls.values()) == 0
    assert (env.ws / "data.txt").exists()


def test_e2e_07_decision_audit_failure(env):
    env.fail(DEC)
    r = env.client.evaluate_request(env.raw())
    assert outcome(r) == (
        Decision.ALLOW,
        "AUDIT_UNAVAILABLE",
        Execution.NOT_STARTED,
        False,
        False,
    )
    assert env.calls["read"] == 0


def test_e2e_09_completion_audit_failure(env):
    env.fail(RC)
    r = env.client.evaluate_request(env.raw())
    assert outcome(r) == (
        Decision.ALLOW,
        "AUDIT_UNAVAILABLE",
        Execution.SUCCEEDED,
        False,
        False,
    )
    assert r.output is None and env.calls["read"] == 1


def test_tool_failure_and_operational_refusal(env):
    env.raise_in_tool = RuntimeError("boom with secret text")
    failed = env.client.evaluate_request(env.raw())
    assert outcome(failed) == (
        Decision.ALLOW,
        "TOOL_FAILED",
        Execution.FAILED,
        False,
        True,
    )
    assert "boom" not in repr(failed)
    env.raise_in_tool = None
    first = env.client.evaluate_request(env.raw(tool_call_id="c1"))
    again = env.client.evaluate_request(env.raw(tool_call_id="c1"))
    assert first.execution is Execution.SUCCEEDED
    assert (again.decision, again.error_code) == (None, "DUPLICATE_TOOL_CALL")
    assert env.calls["read"] == 2


def test_filter_is_the_pass_through_until_c14(env):
    r = env.client.evaluate_request(env.raw())
    assert r.output == "hello"  # unchanged: not a security filter yet


def test_async_only_tool_is_refused_by_the_sync_client(env):
    env.client.register_agent(
        "async_agent",
        grants=(ToolGrant(tool="aread_file", allowed_path_prefixes=(str(env.ws),)),),
    )
    r = env.client.evaluate_request(env.raw("aread_file", agent_id="async_agent"))
    assert (r.decision, r.error_code) == (None, "INTERNAL_ERROR")
    assert env.calls["aread"] == 0


@pytest.mark.parametrize("raw", [None, "request", 42, ["agent_id"]])
def test_non_mapping_raw_is_api_misuse(env, raw):
    # I-32: raises TypeError; not a request, so nothing is audited.
    before = len(env.client.audit_events(limit=1000))
    with pytest.raises(TypeError):
        env.client.evaluate_request(raw)
    assert len(env.client.audit_events(limit=1000)) == before


def test_every_outcome_returns_without_raising(env):
    for raw in (
        env.raw(),
        env.raw("send_email", {"to": "a", "body": "b"}),
        {"tool": 1},
        env.raw("delete_file"),
    ):
        assert isinstance(env.client.evaluate_request(raw), PipelineResult)


# ======================================================== audit_events (D-17)


def test_audit_events_all_requests_in_seq_order(env):
    a = env.client.evaluate_request(env.raw())
    b = env.client.evaluate_request(env.raw("send_email", {"to": "a", "body": "b"}))
    events = env.client.audit_events()
    assert [e.seq for e in events] == sorted(e.seq for e in events)
    assert {e.request_id for e in events} == {a.request_id, b.request_id}
    assert events[0].request_id == a.request_id


def test_audit_events_filtered_by_request(env):
    a = env.client.evaluate_request(env.raw())
    env.client.evaluate_request(env.raw())
    events = env.client.audit_events(a.request_id)
    assert {e.request_id for e in events} == {a.request_id}
    assert [e.event_type for e in events] == [RR, IR, DEC, ES, OF, RC]


def test_audit_events_typed_fields(env):
    r = env.client.evaluate_request(env.raw())
    ev = env.client.audit_events(r.request_id)
    assert all(isinstance(e, AuditEvent) for e in ev)
    dec, rc = ev[2], ev[-1]
    assert dec.decision is Decision.ALLOW and dec.policy_version == "test-1"
    assert rc.execution is Execution.SUCCEEDED and rc.action_digest == dec.action_digest
    assert ev[0].occurred_at.utcoffset().total_seconds() == 0
    assert isinstance(ev[0].detail, str)  # stored JSON text, not parsed
    assert ev[0].schema_version == 1 and ev[0].agent_id == "research_agent"


def test_audit_events_empty_result(env):
    assert env.client.audit_events("no-such-request") == ()
    assert env.client.audit_events() == ()


def test_audit_events_default_and_custom_limits(env):
    for _ in range(20):  # 6 events each -> 120 events
        env.client.evaluate_request(env.raw())
    assert len(env.client.audit_events()) == 100
    assert len(env.client.audit_events(limit=7)) == 7
    assert len(env.client.audit_events(limit=1000)) == 120
    first = env.client.audit_events(limit=5)
    assert [e.seq for e in first] == [1, 2, 3, 4, 5]  # the first, oldest


def test_audit_events_limit_maximum_is_1000(env):
    for _ in range(170):  # 1,020 events
        env.client.evaluate_request(env.raw())
    assert len(env.client.audit_events(limit=1000)) == 1000
    with pytest.raises(InvalidRequestError):
        env.client.audit_events(limit=1001)


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"limit": True}, TypeError),
        ({"limit": False}, TypeError),
        ({"limit": 10.0}, TypeError),
        ({"limit": "10"}, TypeError),
        ({"limit": None}, TypeError),
        ({"limit": 0}, InvalidRequestError),
        ({"limit": -1}, InvalidRequestError),
        ({"limit": 1001}, InvalidRequestError),
        ({"limit": 10**9}, InvalidRequestError),
        ({"request_id": ""}, InvalidRequestError),
        ({"request_id": 5}, TypeError),
        ({"request_id": b"r"}, TypeError),
    ],
)
def test_audit_events_argument_validation(env, kwargs, error):
    with pytest.raises(error) as info:
        env.client.audit_events(**kwargs)
    for value in kwargs.values():
        if isinstance(value, str) and value:
            assert value not in str(info.value)
    if error is InvalidRequestError:
        assert issubclass(error, SentinelError)


def test_limit_is_applied_in_the_query(env):
    for _ in range(5):
        env.client.evaluate_request(env.raw())
    statements = []
    env.client._pipeline.audit.store._conn.set_trace_callback(statements.append)
    env.client.audit_events(limit=3)
    env.client.audit_events("some-request", limit=2)
    selects = [s for s in statements if s.upper().startswith("SELECT")]
    assert len(selects) == 2
    assert all(s.rstrip().upper().endswith(("LIMIT 3", "LIMIT 2")) for s in selects)
    assert "WHERE REQUEST_ID" in selects[1].upper()


def test_audit_events_are_immutable_copies(env):
    r = env.client.evaluate_request(env.raw())
    events = env.client.audit_events(r.request_id)
    assert isinstance(events, tuple)
    with pytest.raises(dataclasses.FrozenInstanceError):
        events[0].reason = "TAMPERED"
    assert env.client.audit_events(r.request_id) == events


def test_audit_events_expose_no_internals():
    names = {f.name for f in dataclasses.fields(AuditEvent)}
    assert names == {
        "seq",
        "event_id",
        "request_id",
        "event_type",
        "occurred_at",
        "agent_id",
        "session_id",
        "tool",
        "decision",
        "reason",
        "policy_version",
        "action_digest",
        "execution",
        "detail",
        "schema_version",
    }


def test_audit_read_failure_is_never_an_empty_result(env, monkeypatch):
    import sqlite3 as _sqlite3

    env.client.evaluate_request(env.raw())

    class Broken:
        def execute(self, *a):
            raise _sqlite3.DatabaseError("disk gone")

    monkeypatch.setattr(env.client._pipeline.audit.store, "_conn", Broken())
    with pytest.raises(AuditUnavailableError):
        env.client.audit_events()


def test_unknown_stored_value_is_an_integrity_error(env, tmp_path):
    env.client.evaluate_request(env.raw())
    with sqlite3.connect(env.db) as conn:
        conn.execute(
            "INSERT INTO audit_events (event_id, request_id, event_type, "
            "occurred_at, decision, schema_version) VALUES "
            "('x', 'r', 'DECISION', '2026-01-01T00:00:00+00:00', 'error', 1)"
        )
    with pytest.raises(AuditIntegrityError):
        env.client.audit_events(limit=1000)


# ============================================================ lifecycle


def test_close_is_idempotent_and_final(env):
    env.client.close()
    env.client.close()
    with pytest.raises(AuditUnavailableError):
        env.client.audit_events()
    r = env.client.evaluate_request(env.raw())
    assert (r.decision, r.error_code, r.execution) == (
        None,
        "AUDIT_UNAVAILABLE",
        Execution.NOT_STARTED,
    )
    assert env.calls["read"] == 0


def test_context_manager_closes(tmp_path):
    cfg = SentinelConfig(audit_db_path=str(tmp_path / "a.db"))
    with SentinelClient(SecurityPolicy(version="v"), cfg) as client:
        assert client.audit_events() == ()
    with pytest.raises(AuditUnavailableError):
        client.audit_events()


def test_one_pipeline_for_the_client_lifetime(env):
    pipeline = env.client._pipeline
    for _ in range(3):
        env.client.evaluate_request(env.raw(tool_call_id="same"))
    assert env.client._pipeline is pipeline
    assert env.calls["read"] == 1  # the duplicate guard persisted


def test_no_destructor_based_cleanup():
    assert "__del__" not in SentinelClient.__dict__
