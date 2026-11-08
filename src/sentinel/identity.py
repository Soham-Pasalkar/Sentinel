"""Identity and capability lookup (C-07; decision record C1.2, D-04, D-24b).

``IdentityStore`` holds the agents registered by trusted application code and
turns a validated ``SecurityRequest`` into a ``SecurityContext``: whether the
agent is authorized (known, enabled, credential satisfied) and, if so, its
``CapabilityEnvelope``. It produces facts, never decisions: an unknown,
disabled or unauthenticated agent gives ``authorized=False``, which policy row
1 (C-08) turns into DENY ``UNAUTHORIZED_AGENT``. Identity never looks at the
requested tool or its arguments.

Credentials (D-04, FR-006; interpretation I-4): configured per agent, passed
as a non-empty ``SecretStr`` and stored only as a SHA-256 digest. With
``require_credentials=True`` (the default), an agent without a credential is
never authorized. A presented token is hashed and compared with
``hmac.compare_digest``; the comparison also runs against a fixed digest when
there is nothing to compare with, so the work done does not depend on whether
the agent exists (best effort, not a timing guarantee). Plain SHA-256 suits
high-entropy tokens such as API keys, not passwords.

Grants (D-24b; interpretations I-1 to I-3): a grant covers one whole registered
tool. At registration every grant must name a tool in the ``ToolRegistry``;
a path tool's prefixes are validated and canonicalised by
``paths.register_prefixes`` (empty or missing: warning, every path denied;
``("/",)``: logged); prefixes on a tool without ``path_args`` are refused;
a grant with a ``rate_limit`` is refused until C-15 enforces it. Path
containment is policy's (C-08).

Registration is setup-time only (I-7): agents cannot be replaced, removed or
re-enabled, and no record or credential digest is ever returned. Errors and
``repr`` never contain credentials. This module is internal.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

from pydantic import SecretStr, ValidationError

from sentinel.exceptions import ConfigurationError, RegistrationError
from sentinel.models import (
    CapabilityEnvelope,
    SecurityContext,
    SecurityRequest,
    ToolGrant,
)
from sentinel.paths import register_prefixes
from sentinel.registry import ToolRegistry

__all__ = ["IdentityStore"]

# Compared against when there is no stored digest, and used in place of a
# missing token, so a comparison always runs. Neither can match a real token's
# digest except with negligible probability, and a match is never accepted
# unless the agent has a credential and a token was presented.
_NO_CREDENTIAL = hashlib.sha256(b"sentinel:no-stored-credential").digest()
_NO_TOKEN = hashlib.sha256(b"sentinel:no-presented-token").digest()


def _digest(secret: str) -> bytes:
    """Return the SHA-256 digest of a secret's UTF-8 encoding."""
    return hashlib.sha256(secret.encode("utf-8", "surrogatepass")).digest()


@dataclass(frozen=True, slots=True)
class _AgentRecord:
    """One registered agent. Never returned to callers."""

    agent_id: str
    user_id: str | None
    disabled: bool
    envelope: CapabilityEnvelope
    credential_digest: bytes | None = field(default=None, repr=False)


class IdentityStore:
    """In-memory registry of agents, their credentials and their grants."""

    def __init__(self, registry: ToolRegistry, *, require_credentials: bool = True):
        """Create an empty store.

        Args:
            registry: the tool registry that grants must refer to.
            require_credentials: whether every agent must present a matching
                credential (D-04 default ``True``; the pipeline passes the
                policy's value, interpretation I-6).

        Raises:
            ConfigurationError: ``require_credentials`` is not a ``bool``.
        """
        if type(require_credentials) is not bool:
            raise ConfigurationError("require_credentials must be a bool")
        self._registry = registry
        self._require_credentials = require_credentials
        self._agents: dict[str, _AgentRecord] = {}
        self._lock = threading.Lock()

    def register_agent(
        self,
        agent_id: str,
        *,
        credential: SecretStr | None = None,
        user_id: str | None = None,
        disabled: bool = False,
        grants: Iterable[ToolGrant] = (),
    ) -> None:
        """Register an agent once, by trusted application code.

        Args:
            agent_id: the agent's unique identifier.
            credential: the agent's credential, if any; stored as a digest only.
            user_id: the user the agent acts for, if any.
            disabled: a disabled agent is never authorized.
            grants: the agent's ``ToolGrant``s, at most one per tool.

        Raises:
            RegistrationError: a malformed field; a duplicate agent; a grant
                that is not a ``ToolGrant``, names an unregistered tool, repeats
                a tool, or gives prefixes for a tool without path arguments.
            ConfigurationError: a grant carries a rate limit (not enforced
                before C-15), or a path prefix is invalid (C2.1) or used on
                Windows (D-21).
        """
        if type(agent_id) is not str or not agent_id:
            raise RegistrationError("agent_id must be a non-empty string")
        if user_id is not None and (type(user_id) is not str or not user_id):
            raise RegistrationError("user_id must be a non-empty string or None")
        if type(disabled) is not bool:
            raise RegistrationError("disabled must be a bool")
        digest = None
        if credential is not None:
            if not isinstance(credential, SecretStr):
                raise RegistrationError("credential must be a SecretStr")
            secret = credential.get_secret_value()
            if type(secret) is not str or not secret:
                raise RegistrationError("credential must be a non-empty string")
            digest = _digest(secret)
        if isinstance(grants, str | bytes) or not isinstance(grants, Iterable):
            raise RegistrationError("grants must be a collection of ToolGrant")
        checked = tuple(self._check_grant(grant) for grant in grants)
        try:
            envelope = CapabilityEnvelope(agent_id=agent_id, grants=checked)
        except ValidationError:
            raise RegistrationError("invalid grants") from None
        record = _AgentRecord(
            agent_id=agent_id,
            user_id=user_id,
            disabled=disabled,
            envelope=envelope,
            credential_digest=digest,
        )
        with self._lock:
            if agent_id in self._agents:
                raise RegistrationError("agent is already registered")
            self._agents[agent_id] = record

    def _check_grant(self, grant: object) -> ToolGrant:
        """Validate one grant against the registry and canonicalise its paths."""
        if type(grant) is not ToolGrant:
            raise RegistrationError("each grant must be a ToolGrant")
        tool = self._registry.lookup(grant.tool)
        if tool is None:
            raise RegistrationError("grant names a tool that is not registered")
        if grant.rate_limit is not None:
            raise ConfigurationError("rate limits are not enforced in this version")
        if tool.spec.path_args:
            prefixes = register_prefixes(grant.allowed_path_prefixes)
        elif grant.allowed_path_prefixes:
            raise RegistrationError("path prefixes given for a tool without paths")
        else:
            prefixes = ()
        return ToolGrant(tool=grant.tool, allowed_path_prefixes=prefixes)

    def authenticate(self, request: SecurityRequest) -> SecurityContext:
        """Return the authentication facts for ``request.agent_id``.

        Never raises for an unknown, disabled or unauthenticated agent: those
        give ``authorized=False`` with no envelope and no ``user_id``.
        """
        record = self._agents.get(request.agent_id)
        token = request.auth_token
        presented = _NO_TOKEN if token is None else _digest(token.get_secret_value())
        stored = None if record is None else record.credential_digest
        matches = hmac.compare_digest(
            presented, _NO_CREDENTIAL if stored is None else stored
        )
        if record is None or record.disabled:
            authorized = False
        elif stored is not None:
            authorized = token is not None and matches
        else:
            authorized = not self._require_credentials
        if not authorized:
            return SecurityContext(agent_id=request.agent_id, authorized=False)
        return SecurityContext(
            agent_id=request.agent_id,
            user_id=record.user_id,
            authorized=True,
            envelope=record.envelope,
        )
