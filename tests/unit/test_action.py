import copy
import datetime
import decimal
import enum
import hashlib
import inspect
import os
import subprocess
import sys

import pytest

import sentinel
from sentinel.action import (
    ActionEncodingError,
    AuthorizedAction,
    action_digest,
    canonical_json,
)

CANARY = "CANARY-7f3a-not-in-errors-or-repr"

BASE = {
    "request_id": "req-1",
    "agent_id": "agent-1",
    "tool": "read_file",
    "arguments": {
        "path": "/workspace/a/b.txt",
        "count": 1,
        "ratio": 0.0,
        "name": "é",
        "opts": {"mode": "r", "limits": [1, 2, 3], "flags": {"deep": {"x": 1}}},
    },
}


def make(**overrides):
    fields = copy.deepcopy(BASE)
    fields.update(overrides)
    return AuthorizedAction(**fields)


# --- encoding


def test_canonical_encoding_matches_hand_written_document():
    action = AuthorizedAction(
        request_id="req-1",
        agent_id="agent-1",
        tool="read_file",
        arguments={
            "b": [1, 2.5, True, None],
            "a": "é",
            "nested": {"z": 0, "y": "/workspace/data.txt"},
        },
    )
    expected_document = (
        '{"agent_id":"agent-1",'
        '"arguments":{"a":"é","b":[1,2.5,true,null],'
        '"nested":{"y":"/workspace/data.txt","z":0}},'
        '"request_id":"req-1","tool":"read_file"}'
    )
    expected = hashlib.sha256(expected_document.encode("utf-8")).hexdigest()
    assert action.digest == expected
    assert action_digest("req-1", "agent-1", "read_file", action.arguments) == expected


def test_canonical_json_is_compact_sorted_and_not_ascii_escaped():
    assert canonical_json({"b": 1, "a": [True, None, "é"]}) == (
        '{"a":[true,null,"é"],"b":1}'
    )


def test_digest_input_is_exactly_the_four_action_fields():
    action = make()
    document = canonical_json(
        {
            "request_id": BASE["request_id"],
            "agent_id": BASE["agent_id"],
            "tool": BASE["tool"],
            "arguments": BASE["arguments"],
        }
    )
    assert action.digest == hashlib.sha256(document.encode("utf-8")).hexdigest()


# --- stability


def test_digest_is_stable_within_a_process():
    digests = {make().digest for _ in range(50)}
    assert len(digests) == 1


def test_digest_ignores_dict_insertion_order():
    forward = {"a": 1, "b": {"c": 2, "d": 3}}
    backward = {"b": {"d": 3, "c": 2}, "a": 1}
    assert action_digest("r", "g", "t", forward) == action_digest(
        "r", "g", "t", backward
    )


_SUBPROCESS_SCRIPT = """
import sys
from sentinel.action import action_digest
if sys.argv[1] == "forward":
    args = {"path": "/workspace/x", "opts": {"a": [1, 2.5, None], "b": True}}
else:
    args = {"opts": {"b": True, "a": [1, 2.5, None]}, "path": "/workspace/x"}
print(action_digest("req-9", "agent-9", "read_file", args))
"""


def test_digest_is_identical_across_processes_and_hash_seeds():
    expected = action_digest(
        "req-9",
        "agent-9",
        "read_file",
        {"path": "/workspace/x", "opts": {"a": [1, 2.5, None], "b": True}},
    )
    seen = set()
    for seed in ("0", "1", "4242", "random"):
        for order in ("forward", "backward"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            result = subprocess.run(  # noqa: S603 - fixed argv: this interpreter, a literal script
                [sys.executable, "-I", "-c", _SUBPROCESS_SCRIPT, order],
                capture_output=True,
                text=True,
                env=env,
                check=True,
                timeout=60,
            )
            seen.add(result.stdout.strip())
    assert seen == {expected}


# --- nested changes


def _variant(mutate):
    arguments = copy.deepcopy(BASE["arguments"])
    mutate(arguments)
    return make(arguments=arguments).digest


NESTED_CHANGES = {
    "deep leaf value": lambda a: a["opts"]["flags"]["deep"].update(x=2),
    "list order": lambda a: a["opts"].update(limits=[1, 3, 2]),
    "int to str": lambda a: a.update(count="1"),
    "int to float": lambda a: a.update(count=1.0),
    "int to bool": lambda a: a.update(count=True),
    "int to None": lambda a: a.update(count=None),
    "added key": lambda a: a["opts"].update(extra=None),
    "removed key": lambda a: a["opts"].pop("mode"),
    "renamed nested key": lambda a: a["opts"]["flags"].update(deep={"X": 1}),
    "path component": lambda a: a.update(path="/workspace/a/c.txt"),
    "path trailing slash": lambda a: a.update(path="/workspace/a/b.txt/"),
    "decomposed unicode": lambda a: a.update(name="é"),
    "empty list to empty dict": lambda a: a["opts"].update(limits={}),
    "negative zero": lambda a: a.update(ratio=-0.0),
}


def test_every_nested_change_alters_the_digest():
    base = make().digest
    digests = {name: _variant(mutate) for name, mutate in NESTED_CHANGES.items()}
    assert base not in digests.values()
    assert len(set(digests.values())) == len(digests)


@pytest.mark.parametrize("field", ["request_id", "agent_id", "tool"])
def test_identity_fields_alter_the_digest(field):
    assert make(**{field: BASE[field] + "-other"}).digest != make().digest


# --- tool_call_id


def test_tool_call_id_is_not_part_of_an_action():
    assert "tool_call_id" not in inspect.signature(AuthorizedAction).parameters
    assert "tool_call_id" not in inspect.signature(action_digest).parameters
    with pytest.raises(TypeError):
        AuthorizedAction(tool_call_id="call_1", **copy.deepcopy(BASE))


# --- rejection


class _Text(str):
    pass


class _Level(enum.IntEnum):
    LOW = 1


class _Secretive:
    def __repr__(self):
        return CANARY


def _cyclic_list():
    value = []
    value.append(value)
    return value


def _cyclic_dict():
    value = {}
    value["self"] = value
    return value


UNSUPPORTED_VALUES = {
    "set": {CANARY},
    "frozenset": frozenset({1}),
    "tuple": (1, 2),
    "bytes": b"x",
    "bytearray": bytearray(b"x"),
    "datetime": datetime.datetime(2026, 1, 1),
    "decimal": decimal.Decimal("1.5"),
    "custom object": _Secretive(),
    "nan": float("nan"),
    "inf": float("inf"),
    "negative inf": float("-inf"),
    "str subclass": _Text(CANARY),
    "int subclass": _Level.LOW,
    "lone surrogate": "\ud800",
    "cyclic list": _cyclic_list(),
    "cyclic dict": _cyclic_dict(),
    "int beyond digit limit": 10**5000,
    "int dict key": {1: "x"},
    "surrogate dict key": {"\ud800": 1},
}


@pytest.mark.parametrize("name", list(UNSUPPORTED_VALUES))
def test_unsupported_values_are_rejected_nested_and_top_level(name):
    value = UNSUPPORTED_VALUES[name]
    with pytest.raises(ActionEncodingError) as top_level:
        make(arguments={"value": value})
    with pytest.raises(ActionEncodingError):
        make(arguments={"outer": [{"inner": value}]})
    with pytest.raises(ActionEncodingError):
        action_digest("r", "g", "t", {"value": value})
    assert CANARY not in str(top_level.value)


@pytest.mark.parametrize("arguments", [[], None, "x", ({"a": 1},)])
def test_arguments_must_be_a_dict(arguments):
    with pytest.raises(ActionEncodingError):
        make(arguments=arguments)


@pytest.mark.parametrize("field", ["request_id", "agent_id", "tool"])
@pytest.mark.parametrize("value", ["", None, 7, _Text("x")])
def test_identity_fields_must_be_non_empty_str(field, value):
    with pytest.raises(ActionEncodingError):
        make(**{field: value})


def test_supported_values_round_trip_with_types_preserved():
    arguments = {
        "s": "x",
        "i": 1,
        "f": 1.0,
        "b": True,
        "n": None,
        "l": [1, 1.0, False, None, [], {}],
        "d": {"k": {"m": -0.0}},
    }
    restored = make(arguments=arguments).arguments
    assert restored == arguments
    assert type(restored["i"]) is int
    assert type(restored["f"]) is float
    assert type(restored["b"]) is bool
    assert [type(v) for v in restored["l"][:3]] == [int, float, bool]


# --- immutability


def test_record_rejects_assignment_and_deletion():
    action = make()
    with pytest.raises(AttributeError):
        action.tool = "delete_file"
    with pytest.raises(AttributeError):
        action.digest = "0" * 64
    with pytest.raises(AttributeError):
        del action.request_id


def test_mutating_inputs_or_returned_arguments_does_not_change_the_record():
    arguments = copy.deepcopy(BASE["arguments"])
    action = make(arguments=arguments)
    digest = action.digest
    arguments["opts"]["flags"]["deep"]["x"] = 999
    returned = action.arguments
    returned["path"] = "/etc/shadow"
    assert action.digest == digest
    assert action.arguments == BASE["arguments"]


def test_repr_omits_argument_values():
    action = make(arguments={"token": CANARY})
    assert CANARY not in repr(action)
    assert action.digest in repr(action)


def test_equality_and_hash_follow_the_canonical_action():
    assert make() == make()
    assert hash(make()) == hash(make())
    assert make() != make(tool="other_tool")


def test_action_module_is_not_part_of_the_public_package_api():
    assert "AuthorizedAction" not in sentinel.__all__
    assert not hasattr(sentinel, "AuthorizedAction")
