"""Audit confidentiality (G-3; owner-approved 2026-11-18).

What the audit may record about a request, without its content:

* ``schema_keys`` computes, once at tool registration, the accepted top-level
  argument keys of a tool's schema and their sanitised labels, within fixed
  bounds (at most 100 fields and 100 key candidates, duplicates counted).
  Oversized schemas, unsupported alias forms and keys shared between fields
  are refused before any key is collected or sorted.
* ``summarize_arguments`` reduces a request's raw ``arguments`` to bounded
  structural metadata: JSON type labels, sizes and counts, keyed only by the
  schema's sanitised labels. It never reads undeclared values, never recurses,
  inspects at most 100 keys (and none if there are more), and never calls
  ``repr``, ``str``, ``isinstance``, equality or hashing on request objects
  other than exact built-in ``str``/``dict``/``list`` values: every type test
  is ``type(x) is <built-in>``.
* ``path_metadata`` and ``path_canonicalised`` describe path arguments with
  the same POSIX semantics as ``paths.py`` (``PurePosixPath``), for exact
  ``str`` values of at most 4,096 characters, without keeping the path.
* ``identity_problem`` and ``valid_tool_name`` are the identifier rules for
  ``agent_id``, ``session_id`` and tool names.

The guarantee covers this module's handling of argument objects. The outer
request mapping is built by trusted application code (C1.2) and its methods
are called by the pipeline as before. This module is internal.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from pydantic import AliasChoices, AliasPath

__all__ = [
    "INVALID",
    "MAX_FIELDS",
    "MAX_IDENTITY_CHARS",
    "MAX_KEY_CANDIDATES",
    "MAX_REQUEST_KEYS",
    "PATH_ANALYSIS_LIMIT",
    "UNREGISTERED",
    "SchemaKeys",
    "SchemaTooLargeError",
    "identity_problem",
    "path_canonicalised",
    "path_metadata",
    "schema_keys",
    "summarize_arguments",
    "valid_tool_name",
]

#: Registration bounds (C-05/D-08 amendment).
MAX_FIELDS = 100
MAX_KEY_CANDIDATES = 100
#: Request keys inspected by the summary (the I-19 item bound).
MAX_REQUEST_KEYS = 100
#: Sentinel's own path-analysis bound (characters), not an OS limit.
PATH_ANALYSIS_LIMIT = 4096
#: Identifier bound for ``agent_id`` and ``session_id``.
MAX_IDENTITY_CHARS = 128

#: Placeholders stored instead of a value that may not be persisted.
INVALID = "[invalid]"
UNREGISTERED = "[unregistered]"

_TOOL_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
_LABEL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


class SchemaTooLargeError(ValueError):
    """The schema exceeds the registration bounds or uses unsupported aliases."""


# ------------------------------------------------------------ identifiers


def identity_problem(value: object) -> str | None:
    """Why ``value`` is not a valid ``agent_id``/``session_id``, or ``None``.

    Exact ``str``, 1 to 128 characters, no control characters (Unicode
    category ``Cc``). The length is checked before any character.
    """
    if type(value) is not str:
        return "not a string"
    if not value:
        return "empty"
    if len(value) > MAX_IDENTITY_CHARS:
        return "too long"
    if any(unicodedata.category(char) == "Cc" for char in value):
        return "control character"
    return None


def valid_tool_name(value: object) -> bool:
    """Whether ``value`` is a valid tool name: ``[A-Za-z0-9_-]{1,64}``."""
    return (
        type(value) is str
        and len(value) <= 64
        and _TOOL_NAME.fullmatch(value) is not None
    )


# ----------------------------------------------------------- schema keys


@dataclass(frozen=True, slots=True)
class SchemaKeys:
    """A tool schema's accepted top-level keys and their audit labels."""

    accepted: frozenset[str]
    #: Accepted keys in sorted order, with their sanitised labels.
    labels: tuple[tuple[str, str], ...]
    #: Path arguments: (the key the gateway reads, i.e. the field name, label).
    paths: tuple[tuple[str, str], ...]
    #: Accepted keys whose label is a name (not ``#n``), mapped to that label.
    #: Built once here, at registration; the detector names a top-level
    #: argument in FINDING evidence only through this map (F-1).
    named: Mapping[str, str] = dataclass_field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        """Build the read-only ``named`` map from ``labels`` (once)."""
        named = {key: label for key, label in self.labels if not label.startswith("#")}
        object.__setattr__(self, "named", MappingProxyType(named))


def _choices(alias: AliasChoices) -> list[object] | tuple[object, ...]:
    choices = alias.choices
    if type(choices) is not list and type(choices) is not tuple:
        raise SchemaTooLargeError("unsupported alias form")
    return choices


def _count(name: str, field: Any, by_name: bool) -> int:
    """Key candidates of one field, without enumerating any collection."""
    alias = field.validation_alias
    if alias is None:
        if field.alias is None:
            return 1
        if type(field.alias) is not str:
            raise SchemaTooLargeError("unsupported alias form")
        return 1 + int(by_name)
    count = int(by_name)
    if type(alias) is str or type(alias) is AliasPath:
        return count + 1
    if type(alias) is AliasChoices:
        return count + len(_choices(alias))
    raise SchemaTooLargeError("unsupported alias form")


def _top_key(candidate: object) -> str | None:
    """The top-level key a candidate accepts, if it is one."""
    if type(candidate) is str:
        return candidate
    if type(candidate) is AliasPath:
        path = candidate.path
        if (type(path) is not list and type(path) is not tuple) or not path:
            raise SchemaTooLargeError("unsupported alias form")
        first = path[0]
        return first if type(first) is str else None
    raise SchemaTooLargeError("unsupported alias form")


def _candidates(name: str, field: Any, by_name: bool) -> list[object]:
    alias = field.validation_alias
    if alias is None:
        if field.alias is None:
            return [name]
        return [field.alias, name] if by_name else [field.alias]
    found: list[object] = [name] if by_name else []
    if type(alias) is AliasChoices:
        found.extend(_choices(alias))
    else:
        found.append(alias)
    return found


def _label(key: str, position: int) -> str:
    return key if _LABEL.fullmatch(key) else f"#{position}"


def _make_labels(keys: list[str]) -> tuple[tuple[str, str], ...]:
    ordered = sorted(keys)
    return tuple((key, _label(key, i)) for i, key in enumerate(ordered))


def schema_keys(arg_schema: Any, path_args: tuple[str, ...]) -> SchemaKeys:
    """Bounded accepted keys and labels of a closed Pydantic schema.

    1. At most ``MAX_FIELDS`` fields (``len`` only).
    2. Key candidates are counted with ``len`` and exact type checks only;
       counting stops as soon as the total exceeds ``MAX_KEY_CANDIDATES``,
       so no alias collection is iterated before the bound holds.
    3. Only then are the (at most 100) candidates collected; a key accepted
       by two different fields is refused.
    4. Only then are the keys sorted and labelled.

    Raises:
        SchemaTooLargeError: a bound is exceeded, an alias form is not one of
            ``str``, ``AliasPath`` or ``AliasChoices`` (exact types, with
            ``str``/``AliasPath`` choices), or keys conflict.
    """
    fields = arg_schema.model_fields
    if type(fields) is not dict or len(fields) > MAX_FIELDS:
        raise SchemaTooLargeError("too many fields")
    config = arg_schema.model_config
    by_name = bool(config.get("validate_by_name") or config.get("populate_by_name"))
    total = 0
    for name, field in fields.items():
        total += _count(name, field, by_name)
        if total > MAX_KEY_CANDIDATES:
            raise SchemaTooLargeError("too many accepted keys")
    owner: dict[str, str] = {}
    for name, field in fields.items():
        for candidate in _candidates(name, field, by_name):
            key = _top_key(candidate)
            if key is None:
                continue
            if owner.get(key, name) != name:
                raise SchemaTooLargeError("an accepted key belongs to two fields")
            owner[key] = name
    paths = tuple((name, _label(name, i)) for i, name in enumerate(path_args))
    return SchemaKeys(
        accepted=frozenset(owner), labels=_make_labels(list(owner)), paths=paths
    )


# -------------------------------------------------------------- summary


def _type_label(kind: type) -> str:
    """The JSON type label of an exact built-in type; ``other`` otherwise."""
    if kind is bool:
        return "boolean"
    if kind is int or kind is float:
        return "number"
    if kind is str:
        return "string"
    if kind is list:
        return "array"
    if kind is dict:
        return "object"
    if kind is type(None):
        return "null"
    return "other"


def _size(value: object, kind: type) -> int | None:
    if kind is str or kind is list or kind is dict:
        return len(value)
    return None


def _keys(mapping: dict[Any, Any]) -> Any:
    """Iterate an exact ``dict``'s keys (a test seam; no user code runs)."""
    return iter(mapping)


def summarize_arguments(arguments: object, keys: SchemaKeys | None) -> dict[str, Any]:
    """Bounded structural metadata for raw ``arguments``, without content.

    * not an exact ``dict``: ``{"type": label}`` only;
    * more than 100 keys: ``{"type", "count", "oversized": true}``; checked
      with ``len`` before any key is inspected, and not a partial summary;
    * a key that is not an exact ``str``: ``{"type", "count",
      "nonstring_keys": true}``;
    * unregistered tool (``keys is None``): ``{"type", "count"}``;
    * otherwise ``declared`` maps each label of a schema-declared key present
      in the request to ``{"type", "size"}`` (no recursion), and
      ``undeclared_count`` counts the other keys, whose values are never read.
    """
    kind = type(arguments)
    if kind is not dict:
        return {"type": _type_label(kind)}
    count = len(arguments)
    summary: dict[str, Any] = {"type": "object", "count": count}
    if count > MAX_REQUEST_KEYS:
        summary["oversized"] = True
        return summary
    for key in _keys(arguments):
        if type(key) is not str:
            summary["nonstring_keys"] = True
            return summary
    if keys is None:
        return summary
    declared: dict[str, Any] = {}
    for key, label in keys.labels:
        # Every key in ``arguments`` is an exact str: built-in comparisons only.
        if key in arguments:
            value = arguments[key]
            value_kind = type(value)
            declared[label] = {
                "type": _type_label(value_kind),
                "size": _size(value, value_kind),
            }
    summary["declared"] = declared
    summary["undeclared_count"] = count - len(declared)
    return summary


# ---------------------------------------------------------------- paths


def path_metadata(arguments: object, keys: SchemaKeys | None) -> dict[str, Any]:
    """Length, component count and ``..`` presence of each path argument.

    Uses ``PurePosixPath`` parts, as the containment check does. Only exact
    ``str`` values of at most 4,096 characters are analysed; otherwise only
    the length (or nothing) is given. The path itself is never returned.
    """
    if keys is None or not keys.paths or type(arguments) is not dict:
        return {}
    if len(arguments) > MAX_REQUEST_KEYS:
        return {}
    for key in _keys(arguments):
        if type(key) is not str:
            return {}
    out: dict[str, Any] = {}
    for name, label in keys.paths:
        entry: dict[str, Any] = {"length": None, "components": None, "has_dotdot": None}
        if name in arguments:
            value = arguments[name]
            if type(value) is str:
                entry["length"] = len(value)
                if len(value) <= PATH_ANALYSIS_LIMIT:
                    parts = PurePosixPath(value).parts
                    rooted = bool(parts) and parts[0].startswith("/")
                    entry["components"] = len(parts) - int(rooted)
                    entry["has_dotdot"] = ".." in parts
        out[label] = entry
    return out


def path_canonicalised(
    original: object, validated: dict[str, Any], keys: SchemaKeys | None
) -> dict[str, bool | None]:
    """Whether canonicalisation changed each path argument (after validation).

    ``original`` is the request's ``arguments`` (an exact ``dict`` once the
    gateway accepted it); ``validated`` holds the canonical values. Compared in
    memory for exact ``str`` values of at most 4,096 characters; ``None``
    otherwise. Neither path is returned.
    """
    if keys is None or not keys.paths or type(original) is not dict:
        return {}
    out: dict[str, bool | None] = {}
    for name, label in keys.paths:
        before = original.get(name)
        after = validated.get(name)
        if (
            type(before) is str
            and type(after) is str
            and len(before) <= PATH_ANALYSIS_LIMIT
        ):
            out[label] = before != after
        else:
            out[label] = None
    return out
