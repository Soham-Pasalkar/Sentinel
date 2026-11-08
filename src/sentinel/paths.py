"""Path guard: canonicalisation and pure containment (C-04; contract C2).

Implements decision record C2 as approved in D-05, D-18 and D-21:

* ``canonicalise`` - validates a request path (C2.3: ``str``, non-empty, no
  NUL, absolute) and resolves it with ``os.path.realpath(strict=False)``
  (C2.4). Relative paths and ``~`` are refused, never resolved against the
  working directory or expanded.
* ``is_contained`` - the one pure containment check (C2.5, C2.8): whole path
  components, never string prefixes; the prefix directory itself is contained;
  an empty prefix set contains nothing (D-05).
* ``register_prefixes`` - validates and canonicalises grant prefixes at
  registration (C2.1, C2.2): each must be absolute, exist and be a directory.
  An empty or missing list is allowed but logged, and denies every call;
  unrestricted access exists only as the explicit root ``"/"``, also logged.
* ``reverify`` - the proxy's re-resolution immediately before invocation
  (C2.7): the path must resolve to the same canonical value and still be
  contained.
* ``require_path_support`` - refuses path-constrained tools on Windows (D-21).

Request-path errors raise ``InvalidRequestError`` (``INVALID_REQUEST``, an
operational refusal); configuration errors raise ``ConfigurationError``.
Neither message, nor any log record, contains a path value (SEC-008).

This is path-argument authorization, not a sandbox or filesystem isolation.
Not defended (C2 limitations): the window between ``reverify`` and the tool's
own ``open``; hard links; paths a tool derives internally; case-insensitive
filesystems (a differently cased path fails closed); mount boundaries.

This module is internal: it is not exported from ``sentinel``. The gateway
(C-06), grants (C-07), policy (C-08) and proxy (C-10) are its callers.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import PurePosixPath

from sentinel.exceptions import ConfigurationError, InvalidRequestError

__all__ = [
    "canonicalise",
    "is_contained",
    "register_prefixes",
    "require_path_support",
    "reverify",
]

_LOG = logging.getLogger(__name__)

_ROOT = "/"


def require_path_support() -> None:
    """Refuse path-constrained tools on Windows (D-21).

    Raises:
        ConfigurationError: on Windows, where C2's POSIX path semantics do not
            apply.
    """
    if os.name == "nt":
        raise ConfigurationError("path-constrained tools are not supported on Windows")


def _absolute_path_problem(path: object) -> str | None:
    """Return why ``path`` is not a usable absolute path, or ``None``."""
    if type(path) is not str:
        return "must be a string"
    if not path:
        return "is empty"
    if "\x00" in path:
        return "contains a NUL character"
    if not path.startswith("/"):
        return "must be absolute"
    try:
        os.fsencode(path)
    except UnicodeEncodeError:
        return "is not encodable"
    return None


def canonicalise(path: str) -> str:
    """Validate a request path and return its canonical form (C2.3, C2.4).

    Resolves ``..`` and every symlink in the existing part of the path; a
    non-existent leaf is allowed (write tools).

    Args:
        path: the path argument from the request.

    Returns:
        The canonical absolute path.

    Raises:
        InvalidRequestError: the value is not a string, is empty, contains NUL,
            is relative (including ``~``), or cannot be encoded.
    """
    problem = _absolute_path_problem(path)
    if problem is not None:
        raise InvalidRequestError(f"path argument {problem}")
    return os.path.realpath(path)


def is_contained(canonical: str, prefixes: Iterable[str]) -> bool:
    """Return whether ``canonical`` equals or lies under one of ``prefixes``.

    Pure: no filesystem access. Compares whole path components (C2.5), so
    ``/safe-other`` is not under ``/safe``. Fails closed: a non-string or
    relative value, or one with a ``..`` component, is never contained, and an
    empty prefix set contains nothing (D-05).

    Args:
        canonical: a path returned by ``canonicalise``.
        prefixes: prefixes returned by ``register_prefixes``.
    """
    if type(canonical) is not str or not canonical.startswith("/"):
        return False
    candidate = PurePosixPath(canonical)
    if ".." in candidate.parts:
        return False
    return any(
        type(prefix) is str
        and prefix.startswith("/")
        and candidate.is_relative_to(PurePosixPath(prefix))
        for prefix in prefixes
    )


def _canonical_prefix(prefix: str) -> str:
    """Validate one grant prefix and return its canonical form (C2.1)."""
    problem = _absolute_path_problem(prefix)
    if problem is not None:
        raise ConfigurationError(f"path prefix {problem}")
    try:
        resolved = os.path.realpath(prefix, strict=True)
    except OSError:
        # The OSError text names the path; suppress it (SEC-008).
        raise ConfigurationError("path prefix does not exist") from None
    if not os.path.isdir(resolved):
        raise ConfigurationError("path prefix is not a directory")
    return resolved


def register_prefixes(prefixes: Iterable[str] | None) -> tuple[str, ...]:
    """Validate and canonicalise the allowed prefixes of a path grant.

    Args:
        prefixes: the grant's ``allowed_path_prefixes``. ``None`` (missing) and
            an empty collection are accepted but deny every call (D-05).

    Returns:
        The canonical prefixes, de-duplicated, in their original order.

    Raises:
        ConfigurationError: on Windows (D-21); if ``prefixes`` is a single
            string rather than a collection; or if any prefix is not an
            absolute, existing directory.
    """
    require_path_support()
    if prefixes is None:
        prefixes = ()
    elif isinstance(prefixes, str | bytes):
        raise ConfigurationError("path prefixes must be a collection of paths")
    result = tuple(dict.fromkeys(_canonical_prefix(p) for p in prefixes))
    if not result:
        _LOG.warning("path grant has no allowed prefixes; every call will be denied")
    elif _ROOT in result:
        _LOG.warning("path grant includes the root prefix; path access is unrestricted")
    return result


def reverify(canonical: str, prefixes: Iterable[str]) -> bool:
    """Re-resolve a canonical path immediately before invocation (C2.7).

    Returns ``True`` only if the path still resolves to exactly ``canonical``
    and is still contained. ``False`` means the proxy must not invoke the tool
    (``decision=None``, ``RESTRICTED_PATH``). This narrows, but does not
    remove, the time-of-check/time-of-use window: the tool's own ``open`` runs
    later.

    Args:
        canonical: the canonical path recorded in the authorized action.
        prefixes: the grant's canonical prefixes.
    """
    try:
        again = canonicalise(canonical)
    except InvalidRequestError:
        return False
    return again == canonical and is_contained(again, prefixes)
