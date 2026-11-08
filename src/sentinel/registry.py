"""Tool registry (C-05; decision record C1.3, FR-010, SEC-014).

The registry is the authoritative source of security-relevant tool metadata
(D-15, approved part). Each registration holds a ``ToolSpec`` and, beside it,
never inside it, the tool's callables: a sync callable, an async callable, or
both (rev. 3, D-12). The registered name is the tool's identity (D-07): names
are unique and a registration can never be replaced or removed.

Rules enforced at registration:

* ``arg_schema`` is required, must be a Pydantic model class and must forbid
  extra fields (D-08). Strict validation of request arguments against it is
  the gateway's job (C-06).
* ``destructive`` is required and must be a ``bool``; there is no default
  (D-06).
* ``path_args`` must name top-level ``str`` fields of the schema (C1.3).
  Registering a path-constrained tool on Windows raises
  ``ConfigurationError`` (D-21); tools without ``path_args`` are unaffected.
* The sync callable must be a plain callable: coroutine, generator and async
  generator functions are refused, because calling them would not run the
  tool body. The async callable must be a coroutine function.

Nothing registered is ever called during registration. Errors carry fixed
text only, never names, schemas or callables (SEC-008). Allowed path
prefixes belong to grants (C-07), not to tool registration.

This module is internal: it is not exported from ``sentinel``.
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ValidationError

from sentinel.exceptions import RegistrationError
from sentinel.models import ToolSpec
from sentinel.paths import require_path_support

__all__ = ["RegisteredTool", "ToolRegistry"]

_MISSING: Any = object()


@dataclass(frozen=True, slots=True)
class RegisteredTool:
    """One registration: the tool's metadata and its entry points."""

    spec: ToolSpec
    sync_fn: Callable[..., Any] | None
    async_fn: Callable[..., Any] | None

    @property
    def supports_sync(self) -> bool:
        """Whether the tool has a sync entry point."""
        return self.sync_fn is not None

    @property
    def supports_async(self) -> bool:
        """Whether the tool has an async entry point."""
        return self.async_fn is not None


def _check_sync(fn: object) -> None:
    """Refuse a sync entry point that would not run the tool body."""
    if not callable(fn):
        raise RegistrationError("sync entry point is not callable")
    if (
        inspect.iscoroutinefunction(fn)
        or inspect.isasyncgenfunction(fn)
        or inspect.isgeneratorfunction(fn)
    ):
        raise RegistrationError("sync entry point must be a plain function")


def _check_async(fn: object) -> None:
    """Require a coroutine function as the async entry point."""
    if not inspect.iscoroutinefunction(fn):
        raise RegistrationError("async entry point must be a coroutine function")


class ToolRegistry:
    """In-memory registry of tools, keyed by their unique registered name.

    Registration is thread-safe. There is no API to replace or remove a
    registration (D-07, SEC-014).
    """

    def __init__(self) -> None:
        """Create an empty registry."""
        self._tools: dict[str, RegisteredTool] = {}
        self._lock = threading.Lock()

    def register(
        self,
        name: str,
        *,
        arg_schema: type[BaseModel] = _MISSING,
        destructive: bool = _MISSING,
        path_args: tuple[str, ...] = (),
        sync_fn: Callable[..., Any] | None = None,
        async_fn: Callable[..., Any] | None = None,
    ) -> ToolSpec:
        """Register a tool and return its ``ToolSpec``.

        Args:
            name: the tool's unique name and identity.
            arg_schema: Pydantic model class for the arguments; must forbid
                extra fields. Required.
            destructive: whether the tool is destructive. Required, no default.
            path_args: names of top-level ``str`` schema fields holding paths.
            sync_fn: the sync entry point, if any.
            async_fn: the async entry point (a coroutine function), if any.

        Raises:
            RegistrationError: a required field is missing; the name is not a
                non-empty ``str`` or is already registered; the metadata is
                invalid; or no valid entry point is given.
            ConfigurationError: a path-constrained tool on Windows (D-21).
        """
        if type(name) is not str or not name:
            raise RegistrationError("tool name must be a non-empty string")
        if arg_schema is _MISSING:
            raise RegistrationError("arg_schema is required")
        if destructive is _MISSING:
            raise RegistrationError("destructive must be declared explicitly")
        if sync_fn is None and async_fn is None:
            raise RegistrationError("a sync or async entry point is required")
        if sync_fn is not None:
            _check_sync(sync_fn)
        if async_fn is not None:
            _check_async(async_fn)
        try:
            spec = ToolSpec(
                name=name,
                arg_schema=arg_schema,
                destructive=destructive,
                path_args=path_args,
            )
        except ValidationError:
            # Input values are hidden, but field names and rule text are not
            # needed by callers; keep the message fixed (SEC-008).
            raise RegistrationError("invalid tool metadata") from None
        if spec.path_args:
            require_path_support()
        tool = RegisteredTool(spec=spec, sync_fn=sync_fn, async_fn=async_fn)
        with self._lock:
            if name in self._tools:
                raise RegistrationError("tool name is already registered")
            self._tools[name] = tool
        return spec

    def lookup(self, name: str) -> RegisteredTool | None:
        """Return the registration for ``name``, or ``None`` if there is none."""
        if type(name) is not str:
            return None
        return self._tools.get(name)

    def specs(self) -> tuple[ToolSpec, ...]:
        """Return every registered ``ToolSpec``, in registration order."""
        with self._lock:
            return tuple(tool.spec for tool in self._tools.values())
