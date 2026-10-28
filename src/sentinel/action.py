"""Authorized action record, canonical action encoding and action digest (C-03a).

An *authorized action* is the one exact, validated tool call that a decision
covers (decision record C1.4, D-07). This module provides:

* ``canonical_json`` - the canonical JSON encoding of plain JSON-compatible data;
* ``action_digest`` - the SHA-256 digest of an action's canonical encoding;
* ``AuthorizedAction`` - an immutable record of one action and its digest.

The digest covers ``request_id``, ``agent_id``, the registered tool name (the
tool's identity) and the canonical arguments, including any resolved path
values they contain. A framework ``tool_call_id`` is deliberately not part of an
action; it is used only by the separate duplicate-call guard (D-31).

Only these value types are accepted, by exact type: ``str``, ``int``, finite
``float``, ``bool``, ``None``, ``list``, and ``dict`` with ``str`` keys.
Anything else is rejected with ``ActionEncodingError``; nothing is converted to
a string. Error messages never include the rejected values.

This module is internal: it is not exported from ``sentinel`` and has no stable
public API in v1.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from sentinel.exceptions import InvalidRequestError

__all__ = [
    "ActionEncodingError",
    "AuthorizedAction",
    "action_digest",
    "canonical_json",
]

_SCALAR_TYPES = (str, int, bool, type(None))


class ActionEncodingError(InvalidRequestError, ValueError):
    """Raised when a value cannot be part of an authorized action.

    An ``InvalidRequestError`` (maps to ``INVALID_REQUEST``) that remains a
    ``ValueError`` for compatibility with C-03a callers.
    """


def _check(value: Any, depth: int, active: set[int]) -> None:
    """Validate that ``value`` is plain JSON-compatible data, by exact type."""
    kind = type(value)
    if kind in _SCALAR_TYPES:
        return
    if kind is float:
        if not math.isfinite(value):
            raise ActionEncodingError(f"non-finite float at depth {depth}")
        return
    if kind is list or kind is dict:
        marker = id(value)
        if marker in active:
            raise ActionEncodingError(f"cyclic {kind.__name__} at depth {depth}")
        active.add(marker)
        try:
            if kind is list:
                for item in value:
                    _check(item, depth + 1, active)
            else:
                for key, item in value.items():
                    if type(key) is not str:
                        raise ActionEncodingError(
                            f"dict key of type {type(key).__name__} at depth {depth}"
                        )
                    _check(item, depth + 1, active)
        finally:
            active.discard(marker)
        return
    raise ActionEncodingError(
        f"unsupported value of type {kind.__name__} at depth {depth}"
    )


def canonical_json(value: Any) -> str:
    """Return the canonical JSON encoding of plain JSON-compatible ``value``.

    The encoding uses sorted keys, no insignificant whitespace, no ASCII
    escaping and no NaN or infinity, and is guaranteed to be valid UTF-8.

    Raises:
        ActionEncodingError: if ``value`` contains an unsupported type, a
            non-finite float, a non-``str`` dict key, a cycle, a string that
            cannot be encoded as UTF-8, or an integer too large to encode.
    """
    try:
        _check(value, 0, set())
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        text.encode("utf-8")
    except ActionEncodingError:
        raise
    except RecursionError:
        raise ActionEncodingError("value is nested too deeply to encode") from None
    except UnicodeEncodeError:
        raise ActionEncodingError("string is not encodable as UTF-8") from None
    except ValueError:
        raise ActionEncodingError("value cannot be encoded") from None
    return text


def _require_identifier(name: str, value: Any) -> str:
    """Return ``value`` if it is a non-empty ``str``; otherwise reject it."""
    if type(value) is not str or not value:
        raise ActionEncodingError(f"{name} must be a non-empty str")
    return value


def _action_document(
    request_id: str, agent_id: str, tool: str, arguments: dict[str, Any]
) -> str:
    """Return the canonical encoding of an action's digest input."""
    if type(arguments) is not dict:
        raise ActionEncodingError("arguments must be a dict")
    return canonical_json(
        {
            "agent_id": _require_identifier("agent_id", agent_id),
            "arguments": arguments,
            "request_id": _require_identifier("request_id", request_id),
            "tool": _require_identifier("tool", tool),
        }
    )


def action_digest(
    request_id: str, agent_id: str, tool: str, arguments: dict[str, Any]
) -> str:
    """Return the SHA-256 hex digest of an action's canonical encoding.

    The digest input is exactly ``request_id``, ``agent_id``, ``tool`` (the
    registered tool name) and ``arguments``. It is deterministic across
    processes and changes when any nested argument value changes.

    Raises:
        ActionEncodingError: if any field is unsupported (see ``canonical_json``).
    """
    document = _action_document(request_id, agent_id, tool, arguments)
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


class AuthorizedAction:
    """Immutable record of one exact, validated action and its digest.

    The arguments are stored in canonical form. Reading ``arguments`` returns a
    fresh copy, so neither the caller's input nor a returned value can change
    the record after construction. The repr omits argument values.
    """

    __slots__ = ("_agent_id", "_canonical_arguments", "_digest", "_request_id", "_tool")

    def __init__(
        self, *, request_id: str, agent_id: str, tool: str, arguments: dict[str, Any]
    ) -> None:
        """Validate and record an action.

        Raises:
            ActionEncodingError: if any field is unsupported (see ``canonical_json``).
        """
        document = _action_document(request_id, agent_id, tool, arguments)
        object.__setattr__(self, "_request_id", request_id)
        object.__setattr__(self, "_agent_id", agent_id)
        object.__setattr__(self, "_tool", tool)
        object.__setattr__(self, "_canonical_arguments", canonical_json(arguments))
        object.__setattr__(
            self, "_digest", hashlib.sha256(document.encode("utf-8")).hexdigest()
        )

    def __setattr__(self, name: str, value: Any) -> None:
        """Reject attribute assignment: the record is immutable."""
        raise AttributeError(f"{type(self).__name__} is immutable")

    def __delattr__(self, name: str) -> None:
        """Reject attribute deletion: the record is immutable."""
        raise AttributeError(f"{type(self).__name__} is immutable")

    @property
    def request_id(self) -> str:
        """The request this action belongs to."""
        return self._request_id

    @property
    def agent_id(self) -> str:
        """The trusted agent identity that requested the action."""
        return self._agent_id

    @property
    def tool(self) -> str:
        """The registered tool name, which defines the tool's identity."""
        return self._tool

    @property
    def arguments(self) -> dict[str, Any]:
        """A fresh copy of the canonical arguments."""
        return json.loads(self._canonical_arguments)

    @property
    def digest(self) -> str:
        """The SHA-256 hex digest of the action's canonical encoding."""
        return self._digest

    def __eq__(self, other: object) -> bool:
        """Two actions are equal when their canonical encodings are equal."""
        if not isinstance(other, AuthorizedAction):
            return NotImplemented
        return self._digest == other._digest

    def __hash__(self) -> int:
        """Hash by digest, consistent with equality."""
        return hash(self._digest)

    def __repr__(self) -> str:
        """Represent the action without its argument values."""
        return (
            f"{type(self).__name__}(request_id={self._request_id!r}, "
            f"agent_id={self._agent_id!r}, tool={self._tool!r}, "
            f"digest={self._digest!r})"
        )
