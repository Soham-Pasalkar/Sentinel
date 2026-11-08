"""Tool registry tests (C-05): FR-010, SEC-014, D-06, D-07, D-08, D-21."""

import dataclasses
import functools
import os
import threading
import time
import types

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

import sentinel
from sentinel import paths
from sentinel.exceptions import ConfigurationError, RegistrationError
from sentinel.models import ToolSpec
from sentinel.registry import RegisteredTool, ToolRegistry

CANARY = "CANARY-4b2d-not-in-errors"


class ReadArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    limit: int = 10


class LooseArgs(BaseModel):
    path: str


class AllowArgs(BaseModel):
    model_config = ConfigDict(extra="allow")

    path: str


class Spy:
    def __init__(self):
        self.calls = 0

    def sync(self, **kwargs):
        self.calls += 1
        return "ran"

    async def coro(self, **kwargs):
        self.calls += 1
        return "ran"


def read_file(path, limit=10):
    return path


async def aread_file(path, limit=10):
    return path


def register(registry, name="read_file", **overrides):
    fields = {
        "arg_schema": ReadArgs,
        "destructive": False,
        "sync_fn": read_file,
    }
    fields.update(overrides)
    return registry.register(name, **fields)


@pytest.fixture
def registry():
    return ToolRegistry()


# ------------------------------------------------------------- registration


def test_register_sync_tool_returns_spec_and_lookup_finds_it(registry):
    spec = register(registry, path_args=("path",))
    assert spec == ToolSpec(
        name="read_file", arg_schema=ReadArgs, destructive=False, path_args=("path",)
    )
    tool = registry.lookup("read_file")
    assert isinstance(tool, RegisteredTool)
    assert tool.spec is spec
    assert tool.sync_fn is read_file
    assert (tool.supports_sync, tool.supports_async) == (True, False)


def test_register_async_only_and_both_entry_points(registry):
    register(registry, "a", sync_fn=None, async_fn=aread_file)
    register(registry, "b", async_fn=aread_file)
    a, b = registry.lookup("a"), registry.lookup("b")
    assert (a.supports_sync, a.supports_async) == (False, True)
    assert (b.supports_sync, b.supports_async) == (True, True)
    assert b.async_fn is aread_file


def test_destructive_flag_is_recorded_as_declared(registry):
    assert register(registry, "rm", destructive=True).destructive is True
    assert register(registry, "ls", destructive=False).destructive is False


def test_registration_never_calls_the_tool(registry):
    spy = Spy()
    register(registry, "s", sync_fn=spy.sync, async_fn=spy.coro)
    assert spy.calls == 0


def test_specs_are_listed_in_registration_order_and_read_only(registry):
    for name in ("c", "a", "b"):
        register(registry, name)
    specs = registry.specs()
    assert isinstance(specs, tuple)
    assert [s.name for s in specs] == ["c", "a", "b"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        registry.lookup("a").spec = specs[0]
    with pytest.raises(ValidationError):  # frozen Pydantic model
        specs[0].destructive = True


def test_lookup_of_unknown_or_non_string_name_returns_none(registry):
    register(registry)
    assert registry.lookup("missing") is None
    assert registry.lookup("READ_FILE") is None
    assert registry.lookup(None) is None
    assert registry.lookup(["read_file"]) is None


# ------------------------------------------------------------ name identity


def test_duplicate_name_is_rejected_and_the_original_kept(registry):
    register(registry)
    with pytest.raises(RegistrationError):
        register(registry, destructive=True, sync_fn=lambda **kw: None)
    tool = registry.lookup("read_file")
    assert tool.sync_fn is read_file
    assert tool.spec.destructive is False
    assert len(registry.specs()) == 1


def test_no_api_replaces_or_removes_a_registration(registry):
    public = {n for n in dir(registry) if not n.startswith("_")}
    assert public == {"register", "lookup", "specs"}


def test_concurrent_registration_of_one_name_succeeds_exactly_once(registry):
    class SlowDict(dict):
        # Widens the window between the "already registered?" check and the
        # insert, so an unlocked check-then-insert would let several through.
        def __contains__(self, key):
            found = super().__contains__(key)
            time.sleep(0.01)
            return found

    registry._tools = SlowDict()
    barrier = threading.Barrier(8)
    outcomes = []

    def worker():
        barrier.wait()
        try:
            register(registry, "race")
            outcomes.append("ok")
        except RegistrationError:
            outcomes.append("dup")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["dup"] * 7 + ["ok"]


@pytest.mark.parametrize("name", ["", None, 1, b"read_file"])
def test_invalid_names_are_rejected(registry, name):
    with pytest.raises(RegistrationError):
        register(registry, name)


def test_str_subclass_name_is_rejected(registry):
    class Name(str):
        pass

    with pytest.raises(RegistrationError):
        register(registry, Name("read_file"))


# --------------------------------------------------- required metadata (D-06)


def test_missing_destructive_declaration_is_rejected(registry):
    with pytest.raises(RegistrationError):
        registry.register("t", arg_schema=ReadArgs, sync_fn=read_file)


@pytest.mark.parametrize("value", [None, 0, 1, "false", "true"])
def test_non_bool_destructive_is_rejected_not_coerced(registry, value):
    with pytest.raises(RegistrationError):
        register(registry, destructive=value)


# ---------------------------------------------------- argument schema (D-08)


def test_missing_arg_schema_is_rejected(registry):
    with pytest.raises(RegistrationError):
        registry.register("t", destructive=False, sync_fn=read_file)


@pytest.mark.parametrize(
    "schema",
    [
        None,
        ReadArgs(path="/x"),  # an instance, not a class
        dict,
        types.SimpleNamespace,
        LooseArgs,  # extra fields ignored by default: not closed
        AllowArgs,  # extra fields allowed
    ],
    ids=["none", "instance", "dict", "plain-class", "extra-ignore", "extra-allow"],
)
def test_invalid_arg_schemas_are_rejected(registry, schema):
    with pytest.raises(RegistrationError):
        register(registry, arg_schema=schema)


def test_registered_schema_forbids_extra_keys(registry):
    spec = register(registry)
    assert spec.arg_schema.model_config.get("extra") == "forbid"


# ------------------------------------------------------------- path_args


@pytest.mark.parametrize(
    "path_args",
    [("missing",), ("limit",), ("",), "path", ["path"]],
    ids=["not-in-schema", "int-field", "empty", "bare-string", "list"],
)
def test_invalid_path_args_are_rejected(registry, path_args):
    with pytest.raises(RegistrationError):
        register(registry, path_args=path_args)


def test_optional_str_field_is_not_a_valid_path_arg(registry):
    class Opt(BaseModel):
        model_config = ConfigDict(extra="forbid")

        path: str | None = None

    with pytest.raises(RegistrationError):
        register(registry, arg_schema=Opt, path_args=("path",))


# -------------------------------------------------------------- entry points


def test_no_entry_point_is_rejected(registry):
    with pytest.raises(RegistrationError):
        register(registry, sync_fn=None)


async def _agen(**kwargs):
    yield 1


def _gen(**kwargs):
    yield 1


@pytest.mark.parametrize(
    "fn",
    ["not callable", 42, aread_file, _agen, _gen],
    ids=["str", "int", "coroutine-fn", "async-gen", "generator"],
)
def test_invalid_sync_entry_points_are_rejected(registry, fn):
    with pytest.raises(RegistrationError):
        register(registry, sync_fn=fn)


@pytest.mark.parametrize(
    "fn",
    [read_file, _agen, _gen, "x", Spy().sync],
    ids=["sync-fn", "async-gen", "generator", "str", "bound-sync"],
)
def test_invalid_async_entry_points_are_rejected(registry, fn):
    with pytest.raises(RegistrationError):
        register(registry, sync_fn=None, async_fn=fn)


def test_callable_objects_methods_and_partials_are_accepted(registry):
    spy = Spy()

    class CallableTool:
        def __call__(self, **kwargs):
            return None

    register(registry, "method", sync_fn=spy.sync, async_fn=spy.coro)
    register(registry, "object", sync_fn=CallableTool())
    register(registry, "partial", sync_fn=functools.partial(read_file, limit=1))
    register(
        registry,
        "apartial",
        sync_fn=None,
        async_fn=functools.partial(aread_file, limit=1),
    )
    assert len(registry.specs()) == 4
    assert spy.calls == 0


def test_rejected_registration_leaves_the_registry_unchanged(registry):
    with pytest.raises(RegistrationError):
        register(registry, sync_fn=aread_file)
    assert registry.lookup("read_file") is None
    register(registry)  # the name is still free
    assert registry.lookup("read_file") is not None


# ------------------------------------------------------------ platform (D-21)


@pytest.fixture
def windows(monkeypatch):
    # Simulate Windows for the path guard only (see test_path_guard F20).
    fake_os = types.SimpleNamespace(name="nt", path=os.path, fsencode=os.fsencode)
    monkeypatch.setattr(paths, "os", fake_os)


def test_path_constrained_tool_is_refused_on_windows(registry, windows):
    with pytest.raises(ConfigurationError):
        register(registry, path_args=("path",))
    assert registry.lookup("read_file") is None


def test_tool_without_path_args_registers_on_windows(registry, windows):
    # D-21: the restriction applies to path-constrained tools only.
    assert register(registry).path_args == ()


def test_path_constrained_tool_registers_on_posix(registry):
    if os.name != "posix":  # pragma: no cover - CI runs Linux and macOS
        pytest.skip("POSIX-only check")
    assert register(registry, path_args=("path",)).path_args == ("path",)


# ------------------------------------------------------- errors (SEC-008)


def test_errors_never_contain_names_or_metadata(registry):
    class Canary(BaseModel):
        model_config = ConfigDict(extra="allow")

        path: str

    register(registry, CANARY)
    attempts = [
        {"name": CANARY},
        {"name": "x", "arg_schema": Canary},
        {"name": "y", "path_args": (CANARY,)},
        {"name": "z", "sync_fn": CANARY},
    ]
    for attempt in attempts:
        with pytest.raises(RegistrationError) as info:
            register(registry, **attempt)
        error = info.value
        assert CANARY not in str(error)
        assert CANARY not in repr(error)
        assert error.__cause__ is None
        assert error.__context__ is None or error.__suppress_context__


def test_registry_is_internal():
    assert not {"ToolRegistry", "RegisteredTool"} & set(sentinel.__all__)
    assert not hasattr(sentinel, "ToolRegistry")
