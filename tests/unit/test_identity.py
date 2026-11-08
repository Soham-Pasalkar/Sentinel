"""Identity and capability tests (C-07): FR-005, FR-006, FR-007, D-04, D-24b.

Identity produces facts (``SecurityContext``), never decisions: the DENY
``UNAUTHORIZED_AGENT`` / ``UNAUTHORIZED_TOOL`` / ``RESTRICTED_PATH`` outcomes
are policy rows 1-3 (C-08) and are not tested here.
"""

import ast
import hashlib
import hmac
import inspect
import logging
import os
import threading
import time
import types
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError

import sentinel
from sentinel import identity, paths
from sentinel.exceptions import ConfigurationError, RegistrationError
from sentinel.identity import IdentityStore
from sentinel.models import (
    CapabilityEnvelope,
    RateLimit,
    SecurityContext,
    SecurityRequest,
    ToolGrant,
)
from sentinel.registry import ToolRegistry

CANARY = "CANARY-31f7-credential-not-in-errors"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


class PathArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class QueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str


def noop(**kwargs):
    return None


@pytest.fixture
def ws(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "other").mkdir()
    (tmp_path / "file.txt").write_text("x")
    return ws


@pytest.fixture
def registry():
    reg = ToolRegistry()
    reg.register(
        "read_file",
        arg_schema=PathArgs,
        destructive=False,
        path_args=("path",),
        sync_fn=noop,
    )
    reg.register(
        "delete_file",
        arg_schema=PathArgs,
        destructive=True,
        path_args=("path",),
        sync_fn=noop,
    )
    reg.register("search", arg_schema=QueryArgs, destructive=False, sync_fn=noop)
    return reg


@pytest.fixture
def store(registry):
    return IdentityStore(registry)


def request(agent_id="agent-1", tool="search", presented=None, **extra):
    fields = {
        "request_id": "req-1",
        "received_at": NOW,
        "agent_id": agent_id,
        "session_id": "sess-1",
        "tool": tool,
        "arguments": {},
    }
    if presented is not None:
        fields["auth_token"] = presented
    fields.update(extra)
    return SecurityRequest(**fields)


def secret(value="token-1"):
    return SecretStr(value)


# ================================================================ models


def test_models_are_frozen():
    grant = ToolGrant(tool="search")
    envelope = CapabilityEnvelope(agent_id="a", grants=(grant,))
    context = SecurityContext(agent_id="a", authorized=True, envelope=envelope)
    limit = RateLimit(max_calls=5, window_seconds=3600)
    for model, field_name, value in [
        (grant, "tool", "other"),
        (envelope, "grants", ()),
        (context, "authorized", False),
        (limit, "max_calls", 99),
    ]:
        with pytest.raises(ValidationError):
            setattr(model, field_name, value)


@pytest.mark.parametrize(
    ("cls", "fields"),
    [
        (ToolGrant, {"tool": "search", "action": "read"}),  # no sub-actions
        (ToolGrant, {"tool": "search", "arguments": {"q": "x"}}),
        (ToolGrant, {"tool": "search", "destructive": False}),
        (CapabilityEnvelope, {"agent_id": "a", "owner": "x"}),
        (SecurityContext, {"agent_id": "a", "authorized": True, "role": "admin"}),
        (RateLimit, {"max_calls": 1, "window_seconds": 1, "burst": 2}),
    ],
)
def test_extra_fields_are_rejected(cls, fields):
    with pytest.raises(ValidationError):
        cls(**fields)


@pytest.mark.parametrize(
    ("cls", "fields"),
    [
        (ToolGrant, {"tool": ""}),
        (ToolGrant, {"tool": 1}),
        (ToolGrant, {"tool": "t", "allowed_path_prefixes": ["/ws"]}),  # list
        (ToolGrant, {"tool": "t", "allowed_path_prefixes": "/ws"}),
        (ToolGrant, {"tool": "t", "allowed_path_prefixes": ("",)}),
        (ToolGrant, {"tool": "t", "rate_limit": {"max_calls": 1}}),
        (CapabilityEnvelope, {"agent_id": ""}),
        (CapabilityEnvelope, {"agent_id": "a", "grants": [ToolGrant(tool="t")]}),
        (SecurityContext, {"agent_id": "a", "authorized": 1}),
        (SecurityContext, {"agent_id": "a", "authorized": "true"}),
        (SecurityContext, {"agent_id": "a", "authorized": True, "user_id": ""}),
        (RateLimit, {"max_calls": 0, "window_seconds": 1}),
        (RateLimit, {"max_calls": 1, "window_seconds": -1}),
        (RateLimit, {"max_calls": True, "window_seconds": 1}),
        (RateLimit, {"max_calls": "5", "window_seconds": 1}),
        (RateLimit, {"max_calls": 1.0, "window_seconds": 1}),
    ],
)
def test_invalid_types_are_rejected_without_coercion(cls, fields):
    with pytest.raises(ValidationError):
        cls(**fields)


def test_envelope_rejects_two_grants_for_one_tool():
    with pytest.raises(ValidationError):
        CapabilityEnvelope(
            agent_id="a", grants=(ToolGrant(tool="t"), ToolGrant(tool="t"))
        )


def test_grant_lookup_is_exact_and_only_a_lookup():
    envelope = CapabilityEnvelope(
        agent_id="a", grants=(ToolGrant(tool="search"), ToolGrant(tool="read_file"))
    )
    assert envelope.grant_for("search").tool == "search"
    assert envelope.grant_for("read_file").tool == "read_file"
    for other in ("Search", "search ", "sear", "searchx", "", None, ["search"]):
        assert envelope.grant_for(other) is None
    assert CapabilityEnvelope(agent_id="a").grant_for("search") is None


def test_unauthorized_context_cannot_carry_an_envelope():
    envelope = CapabilityEnvelope(agent_id="a", grants=(ToolGrant(tool="t"),))
    with pytest.raises(ValidationError):
        SecurityContext(agent_id="a", authorized=False, envelope=envelope)


def test_context_envelope_must_belong_to_the_same_agent():
    envelope = CapabilityEnvelope(agent_id="b")
    with pytest.raises(ValidationError):
        SecurityContext(agent_id="a", authorized=True, envelope=envelope)


def test_grant_has_no_destructive_or_policy_fields():
    # D-24b: a grant covers the tool; destructive status stays in ToolSpec.
    assert set(ToolGrant.model_fields) == {
        "tool",
        "allowed_path_prefixes",
        "rate_limit",
    }
    assert set(SecurityContext.model_fields) == {
        "agent_id",
        "user_id",
        "authorized",
        "envelope",
    }


# ======================================================= agent identity


def test_known_enabled_agent_with_valid_credential_is_authorized(store):
    store.register_agent("agent-1", credential=secret(), user_id="user-1")
    context = store.authenticate(request(presented="token-1"))
    assert context.authorized is True
    assert context.agent_id == "agent-1"
    assert context.user_id == "user-1"
    assert context.envelope == CapabilityEnvelope(agent_id="agent-1")


def test_unknown_agent_is_not_authorized(store):
    store.register_agent("agent-1", credential=secret())
    context = store.authenticate(request("agent-2", presented="token-1"))
    assert context == SecurityContext(agent_id="agent-2", authorized=False)


def test_unknown_agent_is_not_authorized_when_credentials_are_not_required(registry):
    lax = IdentityStore(registry, require_credentials=False)
    lax.register_agent("agent-1")
    assert lax.authenticate(request("agent-2")) == SecurityContext(
        agent_id="agent-2", authorized=False
    )


def test_missing_token_never_matches_even_the_placeholder_credential(store):
    # The digest used in place of a missing token must not authenticate an
    # agent whose credential happens to hash to the same value.
    store.register_agent("agent-1", credential=secret("sentinel:no-presented-token"))
    assert store.authenticate(request()).authorized is False
    assert (
        store.authenticate(request(presented="sentinel:no-presented-token")).authorized
        is True
    )


def test_disabled_agent_is_not_authorized_even_with_the_right_credential(store):
    store.register_agent("agent-1", credential=secret(), disabled=True)
    context = store.authenticate(request(presented="token-1"))
    assert context.authorized is False
    assert context.envelope is None


def test_disabled_agent_without_credential_is_not_authorized(registry):
    lax = IdentityStore(registry, require_credentials=False)
    lax.register_agent("agent-1", disabled=True)
    assert lax.authenticate(request()).authorized is False


def test_require_credentials_defaults_to_true(registry):
    assert (
        inspect.signature(IdentityStore).parameters["require_credentials"].default
        is True
    )
    store = IdentityStore(registry)
    store.register_agent("agent-1")  # no credential configured
    assert store.authenticate(request()).authorized is False
    assert store.authenticate(request(presented="anything")).authorized is False


def test_missing_credential_is_not_authorized(store):
    store.register_agent("agent-1", credential=secret())
    assert store.authenticate(request()).authorized is False


@pytest.mark.parametrize(
    "token", ["token-2", "token-1 ", "TOKEN-1", "token-", "x" * 1000]
)
def test_wrong_credential_is_not_authorized(store, token):
    store.register_agent("agent-1", credential=secret())
    assert store.authenticate(request(presented=token)).authorized is False


def test_empty_presented_token_is_not_authorized(store):
    store.register_agent("agent-1", credential=secret())
    assert store.authenticate(request(presented="")).authorized is False


def test_credential_not_required_accepts_identity_only_agents(registry):
    lax = IdentityStore(registry, require_credentials=False)
    lax.register_agent("agent-1")
    assert lax.authenticate(request()).authorized is True
    # A token presented to an agent without a credential is not checked.
    assert lax.authenticate(request(presented="whatever")).authorized is True


def test_configured_credential_is_enforced_even_when_not_required(registry):
    lax = IdentityStore(registry, require_credentials=False)
    lax.register_agent("agent-1", credential=secret())
    assert lax.authenticate(request()).authorized is False
    assert lax.authenticate(request(presented="wrong")).authorized is False
    assert lax.authenticate(request(presented="token-1")).authorized is True


@pytest.mark.parametrize("value", [None, 0, 1, "true", "False"])
def test_require_credentials_must_be_a_bool(registry, value):
    with pytest.raises(ConfigurationError):
        IdentityStore(registry, require_credentials=value)


def test_unauthorized_context_reveals_no_grants_or_user(store):
    store.register_agent(
        "agent-1",
        credential=secret(),
        user_id="user-1",
        grants=(ToolGrant(tool="search"),),
    )
    context = store.authenticate(request(presented="wrong"))
    assert (context.user_id, context.envelope) == (None, None)


def test_identity_ignores_the_requested_tool(store):
    store.register_agent("agent-1", credential=secret())
    a = store.authenticate(request(tool="search", presented="token-1"))
    b = store.authenticate(request(tool="delete_file", presented="token-1"))
    assert a == b


def test_identity_comes_from_the_request_identity_field(store):
    store.register_agent("agent-1", credential=secret())
    store.register_agent("admin", credential=secret("admin-token"))
    # Only request.agent_id is used; arguments cannot carry identity (C-06).
    context = store.authenticate(request("agent-1", presented="admin-token"))
    assert context.authorized is False


# ========================================================= credentials


def test_only_a_digest_is_stored(store):
    store.register_agent("agent-1", credential=secret(CANARY))
    record = store._agents["agent-1"]
    assert record.credential_digest == hashlib.sha256(CANARY.encode()).digest()
    assert CANARY not in repr(record)
    assert CANARY.encode() not in record.credential_digest
    values = [getattr(record, f) for f in record.__slots__]
    assert all(CANARY not in str(v) for v in values)


def test_credential_comparison_uses_compare_digest(store, monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((type(a), type(b), len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(identity.hmac, "compare_digest", spy)
    store.register_agent("agent-1", credential=secret())
    assert store.authenticate(request(presented="token-1")).authorized is True
    assert store.authenticate(request(presented="nope")).authorized is False
    # It also runs, on equal-length digests, when there is nothing to compare.
    store.authenticate(request("unknown", presented="token-1"))
    store.authenticate(request("unknown"))
    assert calls == [(bytes, bytes, 32, 32)] * 4


def test_no_plain_equality_on_secrets():
    source = inspect.getsource(identity)
    assert "get_secret_value() ==" not in source
    assert "digest ==" not in source


@pytest.mark.parametrize(
    "credential", ["plain-string", b"bytes", 123, SecretStr("")], ids=repr
)
def test_invalid_credentials_are_rejected(store, credential):
    with pytest.raises(RegistrationError):
        store.register_agent("agent-1", credential=credential)
    assert "agent-1" not in store._agents


def test_errors_and_reprs_never_contain_credentials(store, caplog):
    errors = []
    with caplog.at_level(logging.DEBUG):
        store.register_agent("agent-1", credential=secret(CANARY))
        for attempt in [
            {"agent_id": "agent-1", "credential": secret(CANARY)},  # duplicate
            {"agent_id": "x", "credential": CANARY},  # not a SecretStr
            {"agent_id": "y", "credential": secret(CANARY), "disabled": 1},
            {"agent_id": "z", "credential": secret(CANARY), "grants": (CANARY,)},
        ]:
            with pytest.raises(RegistrationError) as info:
                store.register_agent(**attempt)
            errors.append(info.value)
        context = store.authenticate(request(presented=CANARY))
    assert context.authorized is True
    for error in errors:
        assert CANARY not in str(error) and CANARY not in repr(error)
        assert error.__context__ is None or error.__suppress_context__
    assert CANARY not in repr(store.__dict__)
    assert CANARY not in repr(context)
    assert all(CANARY not in r.getMessage() for r in caplog.records)


def test_unicode_credentials_round_trip(store):
    store.register_agent("agent-1", credential=secret("pässwörd-ключ-\ud800"))
    assert store.authenticate(request(presented="pässwörd-ключ-\ud800")).authorized
    assert not store.authenticate(request(presented="pässwörd-ключ-")).authorized


# =========================================================== registration


def test_duplicate_agent_is_rejected_and_the_original_kept(store):
    store.register_agent("agent-1", credential=secret())
    with pytest.raises(RegistrationError):
        store.register_agent("agent-1", credential=secret("other"))
    assert store.authenticate(request(presented="token-1")).authorized is True
    assert store.authenticate(request(presented="other")).authorized is False


def test_concurrent_registration_of_one_agent_succeeds_once(store):
    class SlowDict(dict):
        def __contains__(self, key):
            found = super().__contains__(key)
            time.sleep(0.01)
            return found

    store._agents = SlowDict()
    barrier = threading.Barrier(8)
    outcomes = []

    def worker():
        barrier.wait()
        try:
            store.register_agent("agent-1", credential=secret())
            outcomes.append("ok")
        except RegistrationError:
            outcomes.append("dup")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["dup"] * 7 + ["ok"]


@pytest.mark.parametrize(
    "fields",
    [
        {"agent_id": ""},
        {"agent_id": None},
        {"agent_id": 1},
        {"agent_id": "a", "user_id": ""},
        {"agent_id": "a", "user_id": 5},
        {"agent_id": "a", "disabled": 0},
        {"agent_id": "a", "disabled": "no"},
        {"agent_id": "a", "grants": "search"},
        {"agent_id": "a", "grants": None},
        {"agent_id": "a", "grants": ({"tool": "search"},)},
        {"agent_id": "a", "grants": ("search",)},
    ],
)
def test_malformed_registrations_are_rejected(store, fields):
    with pytest.raises(RegistrationError):
        store.register_agent(**fields)


def test_no_api_replaces_removes_or_reads_agents(store):
    public = {n for n in dir(store) if not n.startswith("_")}
    assert public == {"register_agent", "authenticate"}


# ================================================================ grants


def test_agent_granted_a_registered_tool(store):
    store.register_agent(
        "agent-1", credential=secret(), grants=(ToolGrant(tool="search"),)
    )
    envelope = store.authenticate(request(presented="token-1")).envelope
    assert envelope.grant_for("search") == ToolGrant(tool="search")
    assert envelope.grant_for("read_file") is None


def test_agent_without_grants_has_an_empty_envelope(store):
    # FR-007: no envelope or no grants means nothing is granted.
    store.register_agent("agent-1", credential=secret())
    envelope = store.authenticate(request(presented="token-1")).envelope
    assert envelope.grants == ()
    assert envelope.grant_for("search") is None


def test_grant_for_an_unregistered_tool_is_rejected(store):
    for tool in ("unknown", "Search", "search "):
        with pytest.raises(RegistrationError):
            store.register_agent(
                f"agent-{tool}", credential=secret(), grants=(ToolGrant(tool=tool),)
            )


def test_duplicate_grants_are_rejected(store):
    with pytest.raises(RegistrationError):
        store.register_agent(
            "agent-1",
            credential=secret(),
            grants=(ToolGrant(tool="search"), ToolGrant(tool="search")),
        )
    assert "agent-1" not in store._agents


def test_multiple_grants_are_kept_in_order(store, ws):
    grants = (
        ToolGrant(tool="search"),
        ToolGrant(tool="read_file", allowed_path_prefixes=(str(ws),)),
        ToolGrant(tool="delete_file", allowed_path_prefixes=(str(ws),)),
    )
    store.register_agent("agent-1", credential=secret(), grants=grants)
    envelope = store.authenticate(request(presented="token-1")).envelope
    assert [g.tool for g in envelope.grants] == ["search", "read_file", "delete_file"]


def test_grants_accept_any_iterable(store):
    store.register_agent(
        "agent-1", credential=secret(), grants=[ToolGrant(tool="search")]
    )
    store.register_agent(
        "agent-2", credential=secret(), grants=iter([ToolGrant(tool="search")])
    )
    assert store.authenticate(request("agent-2", presented="token-1")).envelope.grants


def test_grant_does_not_override_destructive_metadata(store, registry, ws):
    store.register_agent(
        "agent-1",
        credential=secret(),
        grants=(ToolGrant(tool="delete_file", allowed_path_prefixes=(str(ws),)),),
    )
    assert store.authenticate(request(presented="token-1")).envelope.grant_for(
        "delete_file"
    )
    assert registry.lookup("delete_file").spec.destructive is True


def test_grant_subclass_is_rejected(store):
    class Sneaky(ToolGrant):
        pass

    with pytest.raises(RegistrationError):
        store.register_agent(
            "agent-1", credential=secret(), grants=(Sneaky(tool="search"),)
        )


def test_rate_limited_grant_is_refused_until_enforced(store):
    grant = ToolGrant(
        tool="search", rate_limit=RateLimit(max_calls=5, window_seconds=60)
    )
    with pytest.raises(ConfigurationError):
        store.register_agent("agent-1", credential=secret(), grants=(grant,))
    assert "agent-1" not in store._agents


def test_grants_returned_to_callers_cannot_change_the_store(store):
    store.register_agent(
        "agent-1", credential=secret(), grants=(ToolGrant(tool="search"),)
    )
    envelope = store.authenticate(request(presented="token-1")).envelope
    with pytest.raises(ValidationError):
        envelope.grants = ()
    with pytest.raises((TypeError, AttributeError)):
        envelope.grants[0] = ToolGrant(tool="read_file")  # tuples are immutable
    again = store.authenticate(request(presented="token-1")).envelope
    assert again.grant_for("search") is not None


# ========================================================= path constraints


def test_path_grant_prefixes_are_canonicalised(store, ws):
    alias = ws.parent / "alias"
    alias.symlink_to(ws, target_is_directory=True)
    grant = ToolGrant(tool="read_file", allowed_path_prefixes=(str(alias), str(ws)))
    store.register_agent("agent-1", credential=secret(), grants=(grant,))
    stored = store.authenticate(request(presented="token-1")).envelope.grant_for(
        "read_file"
    )
    assert stored.allowed_path_prefixes == (os.path.realpath(ws),)


def test_path_grant_with_several_prefixes(store, ws, tmp_path):
    grant = ToolGrant(
        tool="read_file", allowed_path_prefixes=(str(ws), str(tmp_path / "other"))
    )
    store.register_agent("agent-1", credential=secret(), grants=(grant,))
    stored = store.authenticate(request(presented="token-1")).envelope.grant_for(
        "read_file"
    )
    assert stored.allowed_path_prefixes == (
        os.path.realpath(ws),
        os.path.realpath(tmp_path / "other"),
    )


def test_empty_path_grant_is_kept_empty_and_warned(store, caplog):
    # D-05: an empty prefix list denies every path (policy row 3, C-08).
    with caplog.at_level(logging.WARNING, logger="sentinel.paths"):
        store.register_agent(
            "agent-1", credential=secret(), grants=(ToolGrant(tool="read_file"),)
        )
    stored = store.authenticate(request(presented="token-1")).envelope.grant_for(
        "read_file"
    )
    assert stored.allowed_path_prefixes == ()
    assert paths.is_contained("/", stored.allowed_path_prefixes) is False
    assert any("every call will be denied" in r.message for r in caplog.records)


def test_explicit_root_prefix_is_kept_and_logged(store, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.paths"):
        store.register_agent(
            "agent-1",
            credential=secret(),
            grants=(ToolGrant(tool="read_file", allowed_path_prefixes=("/",)),),
        )
    stored = store.authenticate(request(presented="token-1")).envelope.grant_for(
        "read_file"
    )
    assert stored.allowed_path_prefixes == ("/",)
    assert any("unrestricted" in r.message for r in caplog.records)


@pytest.mark.parametrize("bad", ["missing", "file", "relative"])
def test_invalid_path_prefix_is_a_configuration_error(store, ws, tmp_path, bad):
    prefix = {
        "missing": str(tmp_path / "missing"),
        "file": str(tmp_path / "file.txt"),
        "relative": "ws",
    }[bad]
    grant = ToolGrant(tool="read_file", allowed_path_prefixes=(prefix,))
    with pytest.raises(ConfigurationError):
        store.register_agent("agent-1", credential=secret(), grants=(grant,))
    assert "agent-1" not in store._agents


def test_prefixes_on_a_tool_without_paths_are_rejected(store, ws):
    grant = ToolGrant(tool="search", allowed_path_prefixes=(str(ws),))
    with pytest.raises(RegistrationError):
        store.register_agent("agent-1", credential=secret(), grants=(grant,))


def test_path_grant_is_refused_on_windows(store, ws, monkeypatch):
    fake_os = types.SimpleNamespace(name="nt", path=os.path, fsencode=os.fsencode)
    monkeypatch.setattr(paths, "os", fake_os)
    with pytest.raises(ConfigurationError):
        store.register_agent(
            "agent-1",
            credential=secret(),
            grants=(ToolGrant(tool="read_file", allowed_path_prefixes=(str(ws),)),),
        )
    # A grant for a tool without paths is unaffected (D-21).
    store.register_agent(
        "agent-2", credential=secret(), grants=(ToolGrant(tool="search"),)
    )


def test_path_logic_is_reused_not_duplicated():
    source = inspect.getsource(identity)
    assert "register_prefixes(" in source
    for duplicated in ("realpath", "is_relative_to", "PurePosixPath", "os.name"):
        assert duplicated not in source


def _code_strings_and_names(module):
    """Names and string constants used in code, ignoring docstrings."""
    tree = ast.parse(inspect.getsource(module))
    docstrings = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            if isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.alias):
            found.add(node.name)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                found.add(node.value)
    return found


def test_identity_does_no_containment_or_policy():
    used = _code_strings_and_names(identity)
    for later in ("is_contained", "Decision", "PipelineResult", "ActionDenied"):
        assert later not in used
    assert not any("UNAUTHORIZED" in u or "RESTRICTED_PATH" in u for u in used)


def test_identity_is_internal():
    assert "IdentityStore" not in sentinel.__all__
    assert not hasattr(sentinel, "IdentityStore")
