"""NI-11 canary test (C-11): SEC-008 across the pipeline's sinks.

A canary secret is placed in the auth token, in sensitive argument values,
in a tool exception message, in an output-filter exception and in detector
evidence. It must appear in no audit row, no log record, no exception string
and no serialised result. Masking is heuristic (D-29); this test pins the
cases the recorded rules cover.
"""

import json
import logging
import sqlite3
import uuid

import pytest
from pydantic import BaseModel, ConfigDict, SecretStr

from sentinel.models import SecurityFinding, Severity, ToolGrant


@pytest.fixture
def canary():
    return "CANARY-" + uuid.uuid4().hex


class LoginArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: str
    password: str


def all_rows(env):
    with sqlite3.connect(env.db) as conn:
        return repr(conn.execute("SELECT * FROM audit_events").fetchall())


def test_canary_reaches_no_sink(make_env, canary, caplog):
    class EvidenceDetector:
        def analyze(self, request, context):
            return (
                SecurityFinding(
                    code="SECRET_IN_ARGS",
                    severity=Severity.LOW,
                    evidence=f"header was Bearer {canary}",
                ),
            )

    def leaky_filter(out):
        raise RuntimeError(f"filter saw {canary}")

    env = make_env(detector=EvidenceDetector(), output_filter=leaky_filter)
    calls = []

    def login(user, password):
        calls.append(1)
        raise RuntimeError(f"login failed for {user} with {password}")

    env.registry.register(
        "login", arg_schema=LoginArgs, destructive=False, sync_fn=login
    )
    env.identity.register_agent(
        "secure_agent", credential=SecretStr(canary), grants=(ToolGrant(tool="login"),)
    )
    results = []
    with caplog.at_level(logging.DEBUG):
        results.append(
            env.pipeline.evaluate(
                {
                    "agent_id": "secure_agent",
                    "session_id": "s",
                    "tool": "login",
                    "arguments": {"user": "u", "password": canary},
                    "auth_token": canary,
                }
            )
        )
        results.append(env.pipeline.evaluate(env.raw()))  # filter raises
        env.failing.add("REQUEST_COMPLETED")  # fallback log path
        results.append(
            env.pipeline.evaluate(
                {
                    "agent_id": "secure_agent",
                    "session_id": "s",
                    "tool": "login",
                    "arguments": {"user": "u", "password": canary},
                    "auth_token": canary,
                }
            )
        )
    assert results[0].error_code == "TOOL_FAILED" and calls == [1, 1]
    assert results[1].error_code == "OUTPUT_FILTER_FAILED"
    sinks = {
        "audit rows": all_rows(env),
        "log records": " ".join(r.getMessage() for r in caplog.records),
        "results": " ".join(repr(r) + r.model_dump_json() for r in results),
    }
    for name, text in sinks.items():
        assert canary not in text, name
    stored = [json.loads(r.detail) for r in env.store.read() if r.detail]
    assert any(d.get("arguments", {}).get("password") == "[MASKED]" for d in stored)


def test_tool_exception_text_never_reaches_the_caller(env, canary):
    env.raise_in_tool = RuntimeError(canary)
    r = env.pipeline.evaluate(env.raw())  # never raises
    assert canary not in repr(r) and canary not in r.model_dump_json()
    assert canary not in all_rows(env)
