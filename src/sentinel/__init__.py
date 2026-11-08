"""Sentinel: a runtime security layer between AI agents and the tools they invoke.

The supported entry point is ``SentinelClient``: register tools, register
agents with whole-tool grants, then evaluate each tool call. A call runs only
if policy allows it, and every step is recorded in an append-only (through
Sentinel's API only, not tamper-proof) local audit log.

Pre-release: detection (C-13), output filtering (C-14), rate limits (C-15)
and framework adapters (C-16) are not implemented yet. See the README for
limitations. Everything not listed in ``__all__`` is internal.
"""

from sentinel.client import AuditEvent, SentinelClient
from sentinel.config import SentinelConfig
from sentinel.exceptions import (
    AuditUnavailableError,
    ConfigurationError,
    InvalidRequestError,
    RegistrationError,
    SentinelError,
)
from sentinel.models import Decision, Execution, PipelineResult, Severity, ToolGrant
from sentinel.policy import SecurityPolicy

__all__ = [
    "AuditEvent",
    "AuditUnavailableError",
    "ConfigurationError",
    "Decision",
    "Execution",
    "InvalidRequestError",
    "PipelineResult",
    "RegistrationError",
    "SecurityPolicy",
    "SentinelClient",
    "SentinelConfig",
    "SentinelError",
    "Severity",
    "ToolGrant",
    "__version__",
]

__version__ = "0.1.0.dev0"
