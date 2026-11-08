"""Gateway tests (C-06): FR-001, FR-003, FR-004, SEC-008, SEC-013, D-04, D-08.

Gateway parts only: AT-31 (non-JSON-native values -> INVALID_REQUEST) and AT-36
(``tool_call_id`` without ``session_id`` -> INVALID_REQUEST). The guard part
of AT-36 is C-10. Every refusal here is ``InvalidRequestError``, which the
pipeline (C-11) reports as ``decision=None``, ``INVALID_REQUEST``.
"""

import copy
import logging
import math
import os
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field

import sentinel
from sentinel.action import action_digest
from sentinel.exceptions import ActionDenied, InvalidRequestError
from sentinel.gateway import ValidatedRequest, validate_request
from sentinel.models import (
    INVALID_REQUEST,
    RESERVED_ARGUMENT_KEYS,
    Decision,
    Execution,
    PipelineResult,
)
from sentinel.registry import ToolRegistry

CANARY = "CANARY-6e0a-not-in-errors-or-logs"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    limit: int = 10


class Inner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    depth: int
    tags: list[str]


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str
    count: int
    exact: bool
    ratio: float = 0.5
    inner: Inner | None = None
    extra: dict[str, Any] | None = None


class LaxField(BaseModel):
    # The field itself declares strict=False; the gateway must still be strict.
    model_config = ConfigDict(extra="forbid")

    n: int = Field(strict=False)


class CopyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src: str
    dst: str


class LeakySchema(BaseModel):
    # No hide_input_in_errors: Pydantic's own message would contain the input.
    model_config = ConfigDict(extra="forbid")

    count: int


class Spy:
    def __init__(self):
        self.calls = 0

    def __call__(self, **kwargs):
        self.calls += 1


@pytest.fixture
def ws(tmp_path):
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "a.txt").write_text("inside")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.txt").write_text("secret")
    return ws


@pytest.fixture
def spy():
    return Spy()


@pytest.fixture
def registry(spy):
    reg = ToolRegistry()
    reg.register(
        "read_file",
        arg_schema=ReadArgs,
        destructive=False,
        path_args=("path",),
        sync_fn=spy,
    )
    reg.register("search", arg_schema=SearchArgs, destructive=False, sync_fn=spy)
    reg.register("lax", arg_schema=LaxField, destructive=False, sync_fn=spy)
    reg.register(
        "copy",
        arg_schema=CopyArgs,
        destructive=True,
        path_args=("src", "dst"),
        sync_fn=spy,
    )
    reg.register("leaky", arg_schema=LeakySchema, destructive=False, sync_fn=spy)
    return reg


_DEFAULT = object()


def raw(tool="search", arguments=_DEFAULT, **overrides):
    base = {
        "agent_id": "agent-1",
        "session_id": "sess-1",
        "tool": tool,
        "arguments": (
            {"query": "q", "count": 1, "exact": False}
            if arguments is _DEFAULT
            else arguments
        ),
    }
    base.update(overrides)
    return base


def check(registry, request, request_id="req-1", received_at=NOW):
    return validate_request(
        request, registry=registry, request_id=request_id, received_at=received_at
    )


def refused(registry, request, **kwargs):
    with pytest.raises(InvalidRequestError) as info:
        check(registry, request, **kwargs)
    return info.value


# ------------------------------------------------------------- happy path


def test_valid_request_produces_request_action_and_spec(registry):
    result = check(registry, raw())
    assert isinstance(result, ValidatedRequest)
    req, action = result.request, result.action
    assert (req.request_id, req.agent_id, req.session_id, req.tool) == (
        "req-1",
        "agent-1",
        "sess-1",
        "search",
    )
    assert req.received_at == NOW
    assert req.auth_token is None and req.tool_call_id is None
    assert action.request_id == "req-1"
    assert action.agent_id == "agent-1"
    assert action.tool == "search"
    assert action.arguments == {"query": "q", "count": 1, "exact": False}
    assert req.arguments == action.arguments
    assert result.spec is registry.lookup("search").spec


def test_auth_token_none_means_absent(registry):
    assert check(registry, raw(auth_token=None)).request.auth_token is None


def test_auth_token_subclass_is_refused(registry):
    class Token(str):
        pass

    refused(registry, raw(auth_token=Token("t")))


def test_auth_token_is_kept_secret(registry):
    req = check(registry, raw(auth_token=CANARY)).request
    assert req.auth_token.get_secret_value() == CANARY
    assert CANARY not in repr(req)
    assert CANARY not in req.model_dump_json()


def test_schema_defaults_are_not_added_to_the_action(registry, ws):
    action = check(registry, raw("read_file", {"path": str(ws / "a.txt")})).action
    assert "limit" not in action.arguments


def test_gateway_never_invokes_the_tool(registry, spy, ws):
    check(registry, raw())
    check(registry, raw("read_file", {"path": str(ws / "a.txt")}))
    for bad in (raw("search", {"query": 1}), raw("nope")):
        with pytest.raises(InvalidRequestError):
            check(registry, bad)
    assert spy.calls == 0


# -------------------------------------------------------- FR-001: shape


@pytest.mark.parametrize("missing", ["agent_id", "session_id", "tool", "arguments"])
def test_missing_required_field_is_refused(registry, missing):
    request = raw()
    del request[missing]
    refused(registry, request)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", None),
        ("agent_id", 1),
        ("agent_id", b"agent"),
        ("session_id", None),
        ("session_id", 7),
        ("tool", None),
        ("tool", ["search"]),
        ("arguments", None),
        ("arguments", "query=q"),
        ("arguments", [("query", "q")]),
        ("auth_token", 123),
        ("auth_token", b"token"),
        ("tool_call_id", 5),
    ],
)
def test_wrong_field_types_are_refused(registry, field, value):
    refused(registry, raw(**{field: value}))


@pytest.mark.parametrize("field", ["agent_id", "session_id", "tool", "tool_call_id"])
def test_empty_strings_are_refused(registry, field):
    refused(registry, raw(**{field: ""}))


@pytest.mark.parametrize(
    "extra", ["request_id", "received_at", "agent", "metadata", "decision"]
)
def test_unexpected_top_level_fields_are_refused(registry, extra):
    # request_id and received_at are assigned by the pipeline, never supplied.
    refused(registry, raw(**{extra: "x"}))


def test_non_mapping_request_is_refused(registry):
    for bad in (None, "request", [("tool", "search")], 42):
        refused(registry, bad)


def test_mapping_arguments_must_be_a_plain_dict(registry):
    class Args(dict):
        pass

    from types import MappingProxyType

    refused(registry, raw(arguments=MappingProxyType({"query": "q"})))
    refused(registry, raw(arguments=Args(query="q", count=1, exact=False)))


def test_non_string_argument_keys_are_refused(registry):
    refused(registry, raw(arguments={1: "x"}))


@pytest.mark.parametrize(
    "when",
    [
        datetime(2026, 11, 8, 12, 0),  # naive
        datetime(2026, 11, 8, 12, 0, tzinfo=timezone(timedelta(hours=2))),
    ],
)
def test_received_at_must_be_utc(registry, when):
    refused(registry, raw(), received_at=when)


@pytest.mark.parametrize("request_id", ["", None, 1])
def test_invalid_request_id_is_refused(registry, request_id):
    refused(registry, raw(), request_id=request_id)


def test_any_mapping_type_is_accepted_for_the_request(registry):
    from types import MappingProxyType

    result = check(registry, MappingProxyType(raw()))
    assert result.action.tool == "search"


# ------------------------------------------------------- FR-003: registry


def test_unregistered_tool_is_refused(registry):
    refused(registry, raw("delete_everything"))
    refused(registry, raw("Search"))  # names are exact


def test_registered_tool_spec_is_used_not_copied(registry):
    assert check(registry, raw()).spec is registry.lookup("search").spec


# ------------------------------------------------- D-04: reserved keys


@pytest.mark.parametrize("key", sorted(RESERVED_ARGUMENT_KEYS))
def test_each_reserved_key_in_arguments_is_refused(registry, key):
    arguments = {"query": "q", "count": 1, "exact": False, key: CANARY}
    error = refused(registry, raw(arguments=arguments))
    assert CANARY not in str(error)


@pytest.mark.parametrize("key", sorted(RESERVED_ARGUMENT_KEYS))
def test_reserved_key_is_refused_even_if_the_schema_declares_it(spy, key):
    # Proves the D-04 rule itself, not just extra="forbid" in the schema.
    schema = type(
        "Declares",
        (BaseModel,),
        {"__annotations__": {key: str}, "model_config": ConfigDict(extra="forbid")},
    )
    reg = ToolRegistry()
    reg.register("t", arg_schema=schema, destructive=False, sync_fn=spy)
    assert schema.model_validate({key: "x"}, strict=True)  # the schema accepts it
    refused(reg, raw("t", {key: "x"}))


def test_reserved_key_is_refused_even_when_identity_matches(registry):
    arguments = {"query": "q", "count": 1, "exact": False, "agent_id": "agent-1"}
    refused(registry, raw(arguments=arguments))


def test_reserved_names_nested_in_tool_data_are_tool_data(registry):
    # D-04 reserves keys of ``arguments`` itself; nested data is the tool's.
    arguments = {
        "query": "q",
        "count": 1,
        "exact": False,
        "extra": {"agent_id": "someone-else"},
    }
    result = check(registry, raw(arguments=arguments))
    assert result.action.agent_id == "agent-1"
    assert result.request.agent_id == "agent-1"


def test_trusted_identity_comes_from_the_request_not_the_model(registry):
    result = check(registry, raw(agent_id="trusted-agent"))
    assert result.action.agent_id == "trusted-agent"
    assert "agent_id" not in result.action.arguments


# --------------------------------------------- FR-004 / D-08: strict schema


def test_missing_schema_field_is_refused(registry):
    refused(registry, raw(arguments={"query": "q", "count": 1}))


def test_unexpected_argument_field_is_refused(registry):
    refused(
        registry,
        raw(arguments={"query": "q", "count": 1, "exact": False, "x": 1}),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("count", "1"),  # str -> int coercion
        ("count", 1.0),  # float -> int
        ("count", True),  # bool is not an int here
        ("exact", 1),  # int -> bool
        ("exact", "true"),  # str -> bool
        ("query", 5),  # int -> str
        ("query", b"q"),  # bytes -> str
        ("ratio", "0.5"),  # str -> float
    ],
)
def test_type_coercion_is_refused(registry, field, value):
    arguments = {"query": "q", "count": 1, "exact": False, field: value}
    refused(registry, raw(arguments=arguments))


def test_int_is_accepted_for_a_float_field(registry):
    # Pydantic strict mode accepts an int for a float; the action keeps the int.
    arguments = {"query": "q", "count": 1, "exact": False, "ratio": 1}
    assert check(registry, raw(arguments=arguments)).action.arguments["ratio"] == 1


@pytest.mark.parametrize(
    "inner",
    [
        {"depth": "1", "tags": []},
        {"depth": 1, "tags": "a"},
        {"depth": 1, "tags": [1]},
        {"depth": 1, "tags": [], "unexpected": 1},
        {"tags": []},
        "not-a-model",
    ],
)
def test_invalid_nested_values_are_refused(registry, inner):
    arguments = {"query": "q", "count": 1, "exact": False, "inner": inner}
    refused(registry, raw(arguments=arguments))


def test_valid_nested_values_are_accepted(registry):
    arguments = {
        "query": "q",
        "count": 1,
        "exact": False,
        "inner": {"depth": 2, "tags": ["a", "b"]},
    }
    action = check(registry, raw(arguments=arguments)).action
    assert action.arguments["inner"] == {"depth": 2, "tags": ["a", "b"]}


def test_strict_is_enforced_even_when_a_field_declares_strict_false(registry):
    # Regression (Pydantic 2.14.1): model_validate(strict=True) wins over the
    # field-level strict=False, so "1" is not coerced to 1.
    assert LaxField.model_validate({"n": "1"}).n == 1  # lax by itself
    refused(registry, raw("lax", {"n": "1"}))
    assert check(registry, raw("lax", {"n": 1})).action.arguments == {"n": 1}


def test_schema_errors_never_expose_input_values(registry):
    error = refused(registry, raw("leaky", {"count": CANARY}))
    assert CANARY not in str(error)
    assert CANARY not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None or error.__suppress_context__


# ------------------------------------------------------- C2.3/C2.4: paths


def test_absolute_path_is_canonicalised_in_the_action(registry, ws, tmp_path):
    given = str(ws) + "/sub/../a.txt"
    result = check(registry, raw("read_file", {"path": given}))
    expected = os.path.join(os.path.realpath(ws), "a.txt")
    assert result.action.arguments["path"] == expected
    assert result.request.arguments["path"] == expected


def test_canonical_path_is_what_the_digest_covers(registry, ws):
    given = str(ws) + "/sub/../a.txt"
    action = check(registry, raw("read_file", {"path": given})).action
    canonical = os.path.join(os.path.realpath(ws), "a.txt")
    assert action.digest == action_digest(
        request_id="req-1",
        agent_id="agent-1",
        tool="read_file",
        arguments={"path": canonical},
    )
    assert action.digest != action_digest(
        request_id="req-1",
        agent_id="agent-1",
        tool="read_file",
        arguments={"path": given},
    )


@pytest.mark.parametrize(
    "path",
    ["a.txt", "./a.txt", "ws/a.txt", "", "\x00", "/ws/a\x00.txt", "~", "~/.ssh/id"],
)
def test_invalid_paths_are_refused(registry, path, ws, monkeypatch):
    # F7, F8, F9 at gateway level. Even with cwd inside the workspace and HOME
    # set, nothing is resolved or expanded.
    monkeypatch.chdir(ws)
    monkeypatch.setenv("HOME", str(ws))
    refused(registry, raw("read_file", {"path": path}))


def test_symlink_is_resolved_as_in_c04(registry, ws, tmp_path):
    (ws / "link").symlink_to(tmp_path / "outside" / "secret.txt")
    action = check(registry, raw("read_file", {"path": str(ws / "link")})).action
    assert action.arguments["path"] == os.path.realpath(
        tmp_path / "outside" / "secret.txt"
    )


def test_traversal_is_resolved_but_not_judged(registry, ws, tmp_path):
    # The gateway canonicalises; containment is policy (C-08). An escaping
    # path is therefore accepted here, with its true canonical target.
    given = str(ws) + "/../outside/secret.txt"
    action = check(registry, raw("read_file", {"path": given})).action
    assert action.arguments["path"] == os.path.realpath(
        tmp_path / "outside" / "secret.txt"
    )


def test_every_path_argument_is_canonicalised(registry, ws):
    arguments = {"src": str(ws) + "/sub/../a.txt", "dst": str(ws / "sub") + "/./b"}
    action = check(registry, raw("copy", arguments)).action
    real = os.path.realpath(ws)
    assert action.arguments == {
        "src": os.path.join(real, "a.txt"),
        "dst": os.path.join(real, "sub", "b"),
    }


def test_one_invalid_path_argument_refuses_the_request(registry, ws):
    refused(registry, raw("copy", {"src": str(ws / "a.txt"), "dst": "relative"}))


def test_missing_path_argument_is_refused_even_with_a_schema_default(spy):
    class DefaultPath(BaseModel):
        model_config = ConfigDict(extra="forbid")

        path: str = "/etc/passwd"

    reg = ToolRegistry()
    reg.register(
        "read",
        arg_schema=DefaultPath,
        destructive=False,
        path_args=("path",),
        sync_fn=spy,
    )
    refused(reg, raw("read", {}))


def test_gateway_does_not_check_containment(registry, ws):
    # No grant or prefix is consulted: there is none in the gateway's inputs.
    import inspect

    from sentinel import gateway

    source = inspect.getsource(gateway)
    assert "is_contained" not in source
    assert "register_prefixes" not in source


# --------------------------------------------------- C1.4: action integrity


def test_digest_is_stable_for_the_same_request(registry):
    a = check(registry, raw()).action
    b = check(registry, raw(arguments={"exact": False, "count": 1, "query": "q"}))
    assert a.digest == b.action.digest
    assert a == b.action


def test_digest_changes_with_identity_and_arguments(registry):
    base = check(registry, raw()).action.digest
    assert check(registry, raw(), request_id="req-2").action.digest != base
    assert check(registry, raw(agent_id="agent-2")).action.digest != base
    other = {"query": "q", "count": 2, "exact": False}
    assert check(registry, raw(arguments=other)).action.digest != base


def test_tool_call_id_is_excluded_from_the_digest(registry):
    without = check(registry, raw())
    with_id = check(registry, raw(tool_call_id="call-1"))
    other_id = check(registry, raw(tool_call_id="call-2"))
    assert with_id.request.tool_call_id == "call-1"
    assert without.action.digest == with_id.action.digest == other_id.action.digest


def test_tool_call_id_without_session_id_is_refused(registry):
    # AT-36, gateway part. The guard part (no entry created) is C-10.
    request = raw(tool_call_id="call-1")
    del request["session_id"]
    refused(registry, request)


def test_mutating_the_caller_dict_does_not_change_the_action(registry):
    arguments = {
        "query": "q",
        "count": 1,
        "exact": False,
        "inner": {"depth": 1, "tags": ["a"]},
        "extra": {"k": [1, {"deep": True}]},
    }
    original = copy.deepcopy(arguments)
    request = raw(arguments=arguments)
    result = check(registry, request)
    arguments["count"] = 99
    arguments["inner"]["tags"].append("b")
    arguments["extra"]["k"][1]["deep"] = False
    request["agent_id"] = "attacker"
    assert result.action.arguments == original
    assert result.request.arguments == original
    assert result.action.agent_id == "agent-1"


def test_action_arguments_are_fresh_copies(registry):
    action = check(registry, raw()).action
    action.arguments["count"] = 99
    assert action.arguments["count"] == 1


@pytest.mark.parametrize(
    "value",
    [{1, 2}, (1, 2), math.nan, math.inf, b"bytes", datetime(2026, 1, 1)],
    ids=["set", "tuple", "nan", "inf", "bytes", "datetime"],
)
def test_non_json_native_values_are_refused(registry, value):
    # AT-31, gateway part: values the schema accepts (here via dict[str, Any])
    # but that cannot be encoded in an action are refused, not stringified.
    arguments = {"query": "q", "count": 1, "exact": False, "extra": {"v": value}}
    refused(registry, raw(arguments=arguments))


def test_nan_in_a_float_field_is_refused(registry):
    arguments = {"query": "q", "count": 1, "exact": False, "ratio": math.nan}
    refused(registry, raw(arguments=arguments))


# ------------------------------------------- refusal semantics and leakage


def test_refusals_are_invalid_requests_never_policy_denials(registry):
    error = refused(registry, raw("nope"))
    assert isinstance(error, InvalidRequestError)
    assert not isinstance(error, ActionDenied)
    # How the pipeline reports it (C1.6 rev. 6): decision None, INVALID_REQUEST.
    result = PipelineResult(
        request_id="req-1",
        decision=None,
        reason=INVALID_REQUEST,
        error_code=INVALID_REQUEST,
        execution=Execution.NOT_STARTED,
        output_released=False,
        audit_complete=True,
    )
    assert result.decision is None
    with pytest.raises(ValueError):
        PipelineResult(
            request_id="req-1",
            decision=Decision.DENY,
            reason=INVALID_REQUEST,
            error_code=INVALID_REQUEST,
            execution=Execution.NOT_STARTED,
            output_released=False,
            audit_complete=True,
        )


def test_no_error_or_log_contains_request_values(registry, ws, caplog):
    attempts = [
        raw(agent_id=CANARY, arguments={"query": 1}),
        raw(CANARY),
        raw(arguments={"query": CANARY, "count": CANARY, "exact": False}),
        raw("read_file", {"path": CANARY}),
        raw("read_file", {"path": f"/{CANARY}\x00"}),
        raw(**{CANARY: "x"}),
        raw(arguments={"query": "q", "count": 1, "exact": False, "agent_id": CANARY}),
        raw(auth_token=123, tool_call_id=CANARY),
        raw(session_id=5, tool_call_id=CANARY),  # fails inside SecurityRequest
    ]
    with caplog.at_level(logging.DEBUG):
        for attempt in attempts:
            error = refused(registry, attempt)
            assert CANARY not in str(error)
            assert CANARY not in repr(error)
            assert error.__cause__ is None
            assert error.__context__ is None or error.__suppress_context__
    assert all(CANARY not in r.getMessage() for r in caplog.records)


def test_gateway_is_internal():
    assert not {"validate_request", "ValidatedRequest"} & set(sentinel.__all__)
    assert not hasattr(sentinel, "validate_request")
