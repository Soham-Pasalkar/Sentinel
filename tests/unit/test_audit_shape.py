"""G-3 audit confidentiality: bounded schema keys, structural summaries,
identifier rules and path metadata (``sentinel.audit_shape``; owner-approved
2026-11-18).

Behaviour is established with spies on the module's own helpers (``_keys``,
``_top_key``, ``_make_labels``, ``_type_label``) and with hostile objects that
record every method call, not only by checking the final summary.
"""

from pathlib import PurePosixPath

import pydantic
import pytest
from pydantic import AliasChoices, AliasPath, BaseModel, ConfigDict, Field, create_model

from sentinel import audit_shape as shape
from sentinel.audit_shape import (
    INVALID,
    MAX_FIELDS,
    MAX_KEY_CANDIDATES,
    PATH_ANALYSIS_LIMIT,
    UNREGISTERED,
    SchemaTooLargeError,
    identity_problem,
    path_canonicalised,
    path_metadata,
    schema_keys,
    summarize_arguments,
    valid_tool_name,
)


def test_constants_are_the_approved_values():
    assert (MAX_FIELDS, MAX_KEY_CANDIDATES, shape.MAX_REQUEST_KEYS) == (100, 100, 100)
    assert (PATH_ANALYSIS_LIMIT, shape.MAX_IDENTITY_CHARS) == (4096, 128)
    assert (INVALID, UNREGISTERED) == ("[invalid]", "[unregistered]")


# ------------------------------------------------------------ identifiers


@pytest.mark.parametrize(
    ("value", "problem"),
    [
        ("a", None),
        ("x" * 128, None),
        ("agent-ü-1 with spaces", None),
        ("x" * 129, "too long"),
        ("", "empty"),
        ("a\x00b", "control character"),
        ("a\nb", "control character"),
        ("a\x7fb", "control character"),
        ("a\x85b", "control character"),  # C1 control
        (None, "not a string"),
        (42, "not a string"),
        (b"bytes", "not a string"),
    ],
)
def test_identity_rules(value, problem):
    assert identity_problem(value) == problem


def test_str_subclass_is_not_an_identity():
    class Sub(str):
        pass

    assert identity_problem(Sub("a")) == "not a string"


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("read_file", True),
        ("a", True),
        ("A-z_09", True),
        ("x" * 64, True),
        ("x" * 65, False),
        ("", False),
        ("read.file", False),
        ("read file", False),
        ("tööl", False),
        (None, False),
    ],
)
def test_tool_name_rule(name, ok):
    assert valid_tool_name(name) is ok


# ----------------------------------------------------------- schema keys


def model(n, **config):
    fields = {f"f{i}": (str, ...) for i in range(n)}
    return create_model(
        f"M{n}", __config__=ConfigDict(extra="forbid", **config), **fields
    )


def test_one_hundred_fields_are_accepted_and_101_are_not():
    keys = schema_keys(model(100), ())
    assert len(keys.accepted) == 100
    with pytest.raises(SchemaTooLargeError):
        schema_keys(model(101), ())


class Aliased(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plain: str
    renamed: str = Field(alias="Renamed")
    choice: str = Field(
        validation_alias=AliasChoices("c1", "c-2", AliasPath("deep", 0))
    )
    nested: str = Field(validation_alias=AliasPath("outer", "inner"))


def test_accepted_keys_follow_the_installed_pydantic_alias_rules():
    assert pydantic.VERSION.startswith("2.")
    keys = schema_keys(Aliased, ())
    # "renamed" itself is not accepted (validation by name is off); an
    # AliasPath contributes its first element when it is a str.
    assert keys.accepted == {"plain", "Renamed", "c1", "c-2", "deep", "outer"}
    assert dict(keys.labels) == {
        "Renamed": "Renamed",
        "c-2": "#1",  # not an identifier: its sorted position
        "c1": "c1",
        "deep": "deep",
        "outer": "outer",
        "plain": "plain",
    }


def test_installed_pydantic_alias_shapes_are_pinned():
    # The bounded counting relies on these shapes (pydantic 2.14 line).
    fields = Aliased.model_fields
    assert fields["renamed"].alias == "Renamed"
    assert fields["renamed"].validation_alias == "Renamed"
    assert type(fields["choice"].validation_alias.choices) is list
    assert type(fields["nested"].validation_alias.path) is list
    data = {"plain": "a", "Renamed": "b", "c-2": "c", "outer": {"inner": "d"}}
    Aliased.model_validate(data, strict=True)
    with pytest.raises(pydantic.ValidationError):  # the field name is not accepted
        Aliased.model_validate({**data, "renamed": "b"}, strict=True)
    # Pydantic itself refuses an AliasPath whose first item is not a str.
    with pytest.raises(Exception):  # noqa: B017 - pydantic_core.SchemaError
        create_model(
            "Bad",
            __config__=ConfigDict(extra="forbid"),
            x=(str, Field(validation_alias=AliasPath(0, "x"))),
        )


def test_validation_by_name_adds_the_field_name():
    class ByName(BaseModel):
        model_config = ConfigDict(extra="forbid", validate_by_name=True)

        renamed: str = Field(alias="Renamed")

    assert schema_keys(ByName, ()).accepted == {"renamed", "Renamed"}


def big_choices(n):
    return create_model(
        "Big",
        __config__=ConfigDict(extra="forbid"),
        x=(str, Field(validation_alias=AliasChoices(*[f"k{i}" for i in range(n)]))),
    )


def test_candidate_bound_counts_duplicates(monkeypatch):
    dup = create_model(
        "Dup",
        __config__=ConfigDict(extra="forbid"),
        x=(str, Field(validation_alias=AliasChoices(*["same"] * 101))),
    )
    with pytest.raises(SchemaTooLargeError):
        schema_keys(dup, ())
    fits = create_model(
        "Fits",
        __config__=ConfigDict(extra="forbid"),
        x=(str, Field(validation_alias=AliasChoices(*["same"] * 100))),
    )
    assert schema_keys(fits, ()).accepted == {"same"}


def test_exactly_100_candidates_fit_and_101_do_not():
    assert len(schema_keys(big_choices(100), ()).accepted) == 100
    with pytest.raises(SchemaTooLargeError):
        schema_keys(big_choices(101), ())


def test_huge_alias_choices_are_rejected_without_enumeration(monkeypatch):
    calls = {"top_key": 0, "labels": 0}
    real_top, real_labels = shape._top_key, shape._make_labels

    def top(candidate):
        calls["top_key"] += 1
        return real_top(candidate)

    def labels(keys):
        calls["labels"] += 1
        return real_labels(keys)

    monkeypatch.setattr(shape, "_top_key", top)
    monkeypatch.setattr(shape, "_make_labels", labels)
    huge = big_choices(1)
    huge.model_fields["x"].validation_alias.choices = ["k"] * 1_000_000
    with pytest.raises(SchemaTooLargeError):
        schema_keys(huge, ())
    # Counting used len() only: no candidate was examined, nothing labelled.
    assert calls == {"top_key": 0, "labels": 0}


def test_labels_are_made_only_after_the_bound_holds(monkeypatch):
    order = []
    real_labels = shape._make_labels
    monkeypatch.setattr(
        shape, "_make_labels", lambda keys: order.append(len(keys)) or real_labels(keys)
    )
    schema_keys(model(3), ())
    assert order == [3]
    order.clear()
    with pytest.raises(SchemaTooLargeError):
        schema_keys(model(101), ())
    assert order == []


def test_alias_choices_subclass_list_is_refused_without_iteration():
    iterated = []

    class Recording(list):
        def __iter__(self):
            iterated.append(True)
            return super().__iter__()

        def __len__(self):
            iterated.append(True)
            return super().__len__()

    m = big_choices(2)
    m.model_fields["x"].validation_alias.choices = Recording(["a", "b"])
    with pytest.raises(SchemaTooLargeError):
        schema_keys(m, ())
    assert iterated == []


def test_unsupported_alias_forms_are_refused():
    class Odd:
        pass

    m = model(1)
    m.model_fields["f0"].validation_alias = Odd()
    with pytest.raises(SchemaTooLargeError):
        schema_keys(m, ())

    class Sub(AliasChoices):
        pass

    n = model(1)
    n.model_fields["f0"].validation_alias = Sub("a")
    with pytest.raises(SchemaTooLargeError):
        schema_keys(n, ())


def test_a_key_shared_by_two_fields_is_refused():
    shared = create_model(
        "Shared",
        __config__=ConfigDict(extra="forbid"),
        x=(str, Field(validation_alias=AliasChoices("k", "a"))),
        y=(str, Field(validation_alias=AliasChoices("k", "b"))),
    )
    with pytest.raises(SchemaTooLargeError):
        schema_keys(shared, ())


def test_path_labels_use_the_field_name_the_gateway_reads():
    class P(BaseModel):
        model_config = ConfigDict(extra="forbid")

        path: str
        other: int

    assert schema_keys(P, ("path",)).paths == (("path", "path"),)


# -------------------------------------------------------------- summary


class Simple(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    note: str
    data: dict
    items: list
    flag: bool


KEYS = schema_keys(Simple, ("path",))


def test_declared_undeclared_and_absent_keys():
    args = {"note": "secret text", "flag": True, "extra": "never read", "data": {}}
    out = summarize_arguments(args, KEYS)
    assert out == {
        "type": "object",
        "count": 4,
        "declared": {
            "data": {"type": "object", "size": 0},
            "flag": {"type": "boolean", "size": None},
            "note": {"type": "string", "size": 11},
        },
        "undeclared_count": 1,
    }


def test_zero_one_100_and_101_keys(monkeypatch):
    iterations = []
    real = shape._keys
    monkeypatch.setattr(shape, "_keys", lambda d: iterations.append(len(d)) or real(d))
    assert summarize_arguments({}, KEYS) == {
        "type": "object",
        "count": 0,
        "declared": {},
        "undeclared_count": 0,
    }
    assert summarize_arguments({"note": "x"}, KEYS)["declared"] == {
        "note": {"type": "string", "size": 1}
    }
    hundred = {f"k{i}": i for i in range(100)}
    assert summarize_arguments(hundred, KEYS)["undeclared_count"] == 100
    iterations.clear()
    over = {f"k{i}": i for i in range(101)}
    assert summarize_arguments(over, KEYS) == {
        "type": "object",
        "count": 101,
        "oversized": True,
    }
    assert iterations == []  # length checked before any key was inspected


def test_large_dictionary_is_never_iterated(monkeypatch):
    iterations = []
    monkeypatch.setattr(shape, "_keys", lambda d: iterations.append(1) or iter(d))
    out = summarize_arguments({f"k{i}": i for i in range(200_000)}, KEYS)
    assert out == {"type": "object", "count": 200_000, "oversized": True}
    assert iterations == []


def test_undeclared_values_are_never_read(monkeypatch):
    seen = []
    real = shape._type_label
    monkeypatch.setattr(shape, "_type_label", lambda k: seen.append(k) or real(k))
    summarize_arguments({"note": "x", "u1": object(), "u2": [1]}, KEYS)
    assert seen == [str]  # only the declared value's type was examined


def test_unregistered_tool_gives_type_and_count_only():
    assert summarize_arguments({"a": 1, "b": 2}, None) == {"type": "object", "count": 2}


@pytest.mark.parametrize(
    ("value", "label"),
    [
        ([1, 2], "array"),
        ("text", "string"),
        (3, "number"),
        (2.5, "number"),
        (True, "boolean"),
        (None, "null"),
        ((1,), "other"),
        (b"x", "other"),
    ],
)
def test_non_dict_arguments_give_a_type_label_only(value, label):
    assert summarize_arguments(value, KEYS) == {"type": label}


def test_nested_values_are_not_traversed():
    deep = {"a": {"b": {"c": "secret"}}}
    out = summarize_arguments({"data": deep, "items": [[["x"]]]}, KEYS)
    assert out["declared"] == {
        "data": {"type": "object", "size": 1},
        "items": {"type": "array", "size": 1},
    }


def test_summary_is_deterministic_and_bounded():
    args = {"note": "a", "path": "/x", "data": {}, "items": [], "flag": False}
    reordered = dict(reversed(list(args.items())))
    assert summarize_arguments(args, KEYS) == summarize_arguments(reordered, KEYS)
    assert list(summarize_arguments(args, KEYS)["declared"]) == sorted(
        summarize_arguments(args, KEYS)["declared"]
    )
    wide = model(100)
    keys = schema_keys(wide, ())
    out = summarize_arguments({f"f{i}": "v" * 10_000 for i in range(100)}, keys)
    assert len(out["declared"]) == 100
    assert len(str(out)) < 10_000  # bounded regardless of value sizes


# ---------------------------------------------------- hostile objects


class Recorder:
    calls: list = []


class Meta(type):
    def __instancecheck__(cls, obj):
        Recorder.calls.append("__instancecheck__")
        return False

    def __eq__(cls, other):
        Recorder.calls.append("meta __eq__")
        return False

    def __hash__(cls):
        Recorder.calls.append("meta __hash__")
        return 0


class Hostile(metaclass=Meta):
    def __len__(self):
        Recorder.calls.append("__len__")
        return 1

    def __getitem__(self, key):
        Recorder.calls.append("__getitem__")
        return "x"

    def __iter__(self):
        Recorder.calls.append("__iter__")
        return iter(())

    def __eq__(self, other):
        Recorder.calls.append("__eq__")
        return False

    def __hash__(self):
        Recorder.calls.append("__hash__")
        return hash("note")

    def __repr__(self):
        Recorder.calls.append("__repr__")
        return "hostile"

    def __str__(self):
        Recorder.calls.append("__str__")
        return "hostile"

    @property
    def __class__(self):
        Recorder.calls.append("__class__")
        return dict


class HostileStr(str):
    def __eq__(self, other):
        Recorder.calls.append("str __eq__")
        return False

    def __hash__(self):
        Recorder.calls.append("str __hash__")
        return hash("note")

    def __len__(self):
        Recorder.calls.append("str __len__")
        return 1


class HostileDict(dict):
    def __len__(self):
        Recorder.calls.append("dict __len__")
        return 0

    def __iter__(self):
        Recorder.calls.append("dict __iter__")
        return iter(())

    def __getitem__(self, key):
        Recorder.calls.append("dict __getitem__")
        return None


class HostileList(list):
    def __len__(self):
        Recorder.calls.append("list __len__")
        return 0


def hostile_cases():
    key = HostileStr("note")
    return {
        "arguments object": Hostile(),
        "dict subclass": HostileDict(note="x"),
        "list subclass": HostileList([1]),
        "hostile value": {
            "note": Hostile(),
            "data": HostileDict(),
            "items": HostileList(),
        },
        "str subclass value": {"note": HostileStr("x")},
        "hostile key": {Hostile(): 1, "note": "x"},
        "str subclass key colliding with a declared key": {key: 1},
    }


@pytest.mark.parametrize("name", list(hostile_cases()))
def test_summarizer_calls_no_method_of_request_objects(name):
    args = hostile_cases()[name]
    Recorder.calls.clear()
    out = summarize_arguments(args, KEYS)
    paths = path_metadata(args, KEYS)
    assert Recorder.calls == []
    assert "hostile" not in str(out) + str(paths)


def test_hostile_objects_are_described_by_labels_and_flags_only():
    cases = hostile_cases()
    assert summarize_arguments(cases["arguments object"], KEYS) == {"type": "other"}
    assert summarize_arguments(cases["dict subclass"], KEYS) == {"type": "other"}
    out = summarize_arguments(cases["hostile value"], KEYS)
    assert out["declared"] == {
        "data": {"type": "other", "size": None},
        "items": {"type": "other", "size": None},
        "note": {"type": "other", "size": None},
    }
    assert summarize_arguments(cases["hostile key"], KEYS)["nonstring_keys"] is True
    assert summarize_arguments(
        cases["str subclass key colliding with a declared key"], KEYS
    ) == {"type": "object", "count": 1, "nonstring_keys": True}


# ---------------------------------------------------------------- paths


@pytest.mark.parametrize(
    "path",
    [
        "/a/b/c",
        "//a//b",
        "/a/./b/",
        "/a/../b",
        "/a/b/..",
        "/",
        "relative/x",
        "/x\\y",  # a backslash is an ordinary character on POSIX
    ],
)
def test_path_metadata_follows_pureposixpath(path):
    parts = PurePosixPath(path).parts
    rooted = bool(parts) and parts[0].startswith("/")
    assert path_metadata({"path": path}, KEYS) == {
        "path": {
            "length": len(path),
            "components": len(parts) - int(rooted),
            "has_dotdot": ".." in parts,
        }
    }


def test_path_analysis_stops_above_4096_characters():
    at_limit = "/" + "a" * (PATH_ANALYSIS_LIMIT - 1)
    over = "/" + "a" * PATH_ANALYSIS_LIMIT
    assert path_metadata({"path": at_limit}, KEYS)["path"]["components"] == 1
    assert path_metadata({"path": over}, KEYS)["path"] == {
        "length": PATH_ANALYSIS_LIMIT + 1,
        "components": None,
        "has_dotdot": None,
    }


def test_path_metadata_for_non_strings_and_absent_paths():
    assert path_metadata({"path": 5}, KEYS)["path"] == {
        "length": None,
        "components": None,
        "has_dotdot": None,
    }
    assert path_metadata({}, KEYS)["path"]["length"] is None
    assert path_metadata("not a dict", KEYS) == {}
    assert path_metadata({"path": "/x"}, None) == {}


def test_path_canonicalised_compares_in_memory():
    assert path_canonicalised({"path": "/a/../b"}, {"path": "/b"}, KEYS) == {
        "path": True
    }
    assert path_canonicalised({"path": "/b"}, {"path": "/b"}, KEYS) == {"path": False}
    long = "/" + "a" * PATH_ANALYSIS_LIMIT
    assert path_canonicalised({"path": long}, {"path": long}, KEYS) == {"path": None}
    assert path_canonicalised({"path": 1}, {"path": "/b"}, KEYS) == {"path": None}
    assert path_canonicalised({"path": "/b"}, {"path": "/b"}, None) == {}


def test_too_many_fields_are_refused_before_counting(monkeypatch):
    counted = []
    monkeypatch.setattr(shape, "_count", lambda *a: counted.append(a) or 1)
    with pytest.raises(SchemaTooLargeError):
        schema_keys(model(101), ())
    assert counted == []


def test_unsupported_alias_is_refused_while_counting(monkeypatch):
    examined = []
    monkeypatch.setattr(shape, "_top_key", lambda c: examined.append(c))

    class Odd:
        pass

    m = model(2)
    m.model_fields["f1"].validation_alias = Odd()
    with pytest.raises(SchemaTooLargeError):
        schema_keys(m, ())
    assert examined == []  # rejected before any candidate was examined


def test_non_identifier_path_names_get_positional_labels():
    m = create_model(
        "P", __config__=ConfigDict(extra="forbid"), **{"bad-name": (str, ...)}
    )
    assert schema_keys(m, ("bad-name",)).paths == (("bad-name", "#0"),)
    assert path_metadata({"bad-name": "/a/b"}, schema_keys(m, ("bad-name",))) == {
        "#0": {"length": 4, "components": 2, "has_dotdot": False}
    }


def test_path_metadata_is_empty_for_oversized_or_nonstring_key_arguments(monkeypatch):
    iterations = []
    real = shape._keys
    monkeypatch.setattr(shape, "_keys", lambda d: iterations.append(1) or real(d))
    assert path_metadata({f"k{i}": "/x" for i in range(101)}, KEYS) == {}
    assert iterations == []  # length checked before any key was inspected
    assert path_metadata({1: "/x", "path": "/y"}, KEYS) == {}
