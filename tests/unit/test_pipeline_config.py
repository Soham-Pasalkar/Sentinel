"""Configuration and construction (C-11): I-31, D-11, D-31, FR-009."""

from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from sentinel.config import SentinelConfig
from sentinel.detector import NullDetector
from sentinel.exceptions import ConfigurationError
from sentinel.models import Decision, Execution, ToolGrant
from sentinel.pipeline import Pipeline, build_pipeline
from sentinel.policy import SecurityPolicy
from sentinel.proxy import pass_through_filter
from sentinel.registry import ToolRegistry


class QArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str


def test_config_defaults_are_the_approved_values():
    config = SentinelConfig()
    assert config.audit_db_path == "sentinel_audit.db"
    assert config.require_credentials is True
    assert (config.guard_ttl_seconds, config.guard_capacity) == (300.0, 10_000)


@pytest.mark.parametrize(
    "fields",
    [
        {"audit_db_path": ""},
        {"require_credentials": 1},
        {"guard_ttl_seconds": 0},
        {"guard_ttl_seconds": float("nan")},
        {"guard_ttl_seconds": float("inf")},
        {"guard_ttl_seconds": True},
        {"guard_capacity": 0},
        {"guard_capacity": True},
        {"guard_capacity": 1.5},
        {"unknown": 1},
    ],
)
def test_invalid_config_is_a_configuration_error(fields):
    with pytest.raises(ConfigurationError):
        SentinelConfig(**fields)


def test_null_detector_finds_nothing():
    assert NullDetector().analyze(None, None) == ()


def test_build_pipeline_uses_a_durable_default_store(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    registry = ToolRegistry()
    registry.register("echo", arg_schema=QArgs, destructive=False, sync_fn=lambda q: q)
    pipeline = build_pipeline(
        SentinelConfig(require_credentials=False),
        registry=registry,
        policy=SecurityPolicy(version="v1"),
        output_filter=pass_through_filter,
    )
    try:
        assert pipeline.audit.store.path == str(Path.cwd() / "sentinel_audit.db")
        pipeline.identity.register_agent("a", grants=(ToolGrant(tool="echo"),))
        r = pipeline.evaluate(
            {
                "agent_id": "a",
                "session_id": "s",
                "tool": "echo",
                "arguments": {"q": "hi"},
            }
        )
        assert (r.decision, r.execution, r.output, r.audit_complete) == (
            Decision.ALLOW,
            Execution.SUCCEEDED,
            "hi",
            True,
        )
    finally:
        pipeline.close()


def test_build_pipeline_requires_credentials_by_default(tmp_path):
    registry = ToolRegistry()
    registry.register("echo", arg_schema=QArgs, destructive=False, sync_fn=lambda q: q)
    pipeline = build_pipeline(
        SentinelConfig(audit_db_path=str(tmp_path / "a.db")),
        registry=registry,
        policy=SecurityPolicy(version="v1"),
        output_filter=pass_through_filter,
    )
    try:
        pipeline.identity.register_agent("a", grants=(ToolGrant(tool="echo"),))
        r = pipeline.evaluate(
            {
                "agent_id": "a",
                "session_id": "s",
                "tool": "echo",
                "arguments": {"q": "hi"},
            }
        )
        assert (r.decision, r.reason) == (Decision.DENY, "UNAUTHORIZED_AGENT")
    finally:
        pipeline.close()


def test_build_pipeline_validates_its_inputs(tmp_path):
    with pytest.raises(ConfigurationError):
        build_pipeline(
            {"audit_db_path": "x"},
            registry=ToolRegistry(),
            policy=SecurityPolicy(version="v"),
            output_filter=pass_through_filter,
        )
    with pytest.raises(ConfigurationError):
        build_pipeline(
            SentinelConfig(audit_db_path=str(tmp_path / "missing" / "a.db")),
            registry=ToolRegistry(),
            policy=SecurityPolicy(version="v"),
            output_filter=pass_through_filter,
        )


def test_pipeline_rejects_wrong_components(env):
    parts = dict(
        registry=env.registry,
        identity=env.identity,
        policy=env.pipeline._policy,
        audit=env.logger,
        proxy=env.proxy,
    )
    for name in parts:
        with pytest.raises(ConfigurationError):
            Pipeline(**{**parts, name: object()})
    with pytest.raises(ConfigurationError):
        Pipeline(**parts, detector=object())


def test_pipeline_keeps_one_proxy_and_guard_for_its_lifetime(env):
    proxy, guard = env.pipeline._proxy, env.pipeline._proxy.guard
    for _ in range(3):
        env.pipeline.evaluate(env.raw(tool_call_id="same"))
    assert env.pipeline._proxy is proxy and env.pipeline._proxy.guard is guard
    assert env.calls["read"] == 1  # the guard survived across requests
