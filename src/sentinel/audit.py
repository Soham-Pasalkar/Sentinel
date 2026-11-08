"""Audit logger, masking and reconstruction (C-09).

Implements decision record C1.7, C4.3 and C4.4 with D-09, D-24f and D-29,
plus interpretations I-18 to I-23.

* ``AuditLogger.record(event_type, *, request_id, ...)`` builds one C4.2 row,
  checks the field rules (I-22), masks and truncates ``detail`` (I-18, I-19),
  and commits it through the ``AuditStore``. It returns only after the commit.
  If the commit fails it writes a masked best-effort record to ``logging`` and
  re-raises ``AuditUnavailableError``: the fallback never counts as success.
* ``mask(value)`` returns a masked, bounded, JSON-native copy (never mutates).
* ``diagnostics_detail(diagnostics)`` turns proxy ``Diagnostics`` into the D-29
  fields only: no message text, traceback, locals, argument values or paths.
* ``reconstruct(rows)`` classifies each request's execution from committed
  rows alone, per C4.4, and refuses inconsistent sequences (I-23).

Events state what happened (D-24f): the policy decision, an operational
refusal or internal error, the execution state and output release stay
distinct. Masking is heuristic: it cannot recognise every secret (D-29).
This module is internal; it does not build ``PipelineResult`` (C-11).
"""

from __future__ import annotations

import json
import logging
import math
import re
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import SecretStr

from sentinel.exceptions import AuditIntegrityError, AuditUnavailableError
from sentinel.models import (
    NON_POLICY_REASONS,
    NULL_DECISION_CODES,
    Decision,
    Execution,
)
from sentinel.proxy import Diagnostics
from sentinel.store import SCHEMA_VERSION, AuditRow, AuditStore

__all__ = [
    "DECISION",
    "ERROR",
    "EVENT_TYPES",
    "EXECUTION_STARTED",
    "FINDING",
    "IDENTITY_RESOLVED",
    "MASK",
    "MAX_CHARS",
    "OUTPUT_FILTERED",
    "OUTPUT_WITHHELD",
    "REQUEST_COMPLETED",
    "REQUEST_RECEIVED",
    "TRUNCATED",
    "AuditLogger",
    "RequestState",
    "diagnostics_detail",
    "mask",
    "reconstruct",
]

_LOG = logging.getLogger(__name__)

# ------------------------------------------------------------ event types

REQUEST_RECEIVED = "REQUEST_RECEIVED"
IDENTITY_RESOLVED = "IDENTITY_RESOLVED"
FINDING = "FINDING"
DECISION = "DECISION"
EXECUTION_STARTED = "EXECUTION_STARTED"
OUTPUT_FILTERED = "OUTPUT_FILTERED"
OUTPUT_WITHHELD = "OUTPUT_WITHHELD"
REQUEST_COMPLETED = "REQUEST_COMPLETED"
ERROR = "ERROR"

#: The C4.3 / FR-012 enumeration.
EVENT_TYPES = frozenset(
    {
        REQUEST_RECEIVED,
        IDENTITY_RESOLVED,
        FINDING,
        DECISION,
        EXECUTION_STARTED,
        OUTPUT_FILTERED,
        OUTPUT_WITHHELD,
        REQUEST_COMPLETED,
        ERROR,
    }
)

# ------------------------------------------------- masking (I-18, I-19)

MASK = "[MASKED]"
TRUNCATED = "…[truncated]"
MAX_CHARS = 1024
MAX_ITEMS = 100
MAX_DEPTH = 8

_SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "accesskey",
    "privatekey",
    "credential",
    "authorization",
    "cookie",
    "sessionkey",
)
_PATTERNS = tuple(
    re.compile(p)
    for p in (
        # PEM private key, up to its END line (or the end of the text).
        r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?"
        r"(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}",
        r"\bsk-[A-Za-z0-9_-]{16,}",
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
        r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}",
    )
)


def _sensitive_key(key: str) -> bool:
    normalised = re.sub(r"[\s_.\-]", "", key.lower())
    return any(part in normalised for part in _SENSITIVE_KEY_PARTS)


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(limit - len(TRUNCATED), 0)] + TRUNCATED


def _clean_text(text: str, limit: int) -> str:
    """Replace lone surrogates, mask token shapes, then truncate."""
    text = text.encode("utf-8", "replace").decode("utf-8")
    for pattern in _PATTERNS:
        text = pattern.sub(MASK, text)
    return _truncate(text, limit)


def _mask(value: Any, depth: int, limit: int) -> Any:
    kind = type(value)
    if value is None or kind is bool or kind is int:
        return value
    if kind is float:
        if not math.isfinite(value):
            raise ValueError("audit detail contains a non-finite number")
        return value
    if kind is str:
        return _clean_text(value, limit)
    if kind is SecretStr:
        return MASK
    if kind is list or kind is tuple:
        if depth >= MAX_DEPTH:
            return TRUNCATED
        items = [_mask(v, depth + 1, limit) for v in value[:MAX_ITEMS]]
        if len(value) > MAX_ITEMS:
            items.append(TRUNCATED)
        return items
    if kind is dict:
        if depth >= MAX_DEPTH:
            return TRUNCATED
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if type(key) is not str:
                raise ValueError("audit detail keys must be strings")
            if index >= MAX_ITEMS:
                out[TRUNCATED] = len(value) - MAX_ITEMS
                break
            clean_key = _clean_text(key, limit)
            out[clean_key] = (
                MASK if _sensitive_key(key) else _mask(item, depth + 1, limit)
            )
        return out
    raise ValueError("audit detail value is not JSON-native")


def mask(value: Any, *, limit: int = MAX_CHARS) -> Any:
    """Return a masked, truncated, JSON-native copy of ``value`` (I-18, I-19).

    Raises:
        ValueError: ``value`` contains a non-JSON-native value, a non-string
            key or a non-finite number. Values are never converted with
            ``repr``.
    """
    return _mask(value, 0, limit)


def diagnostics_detail(diagnostics: Diagnostics) -> dict[str, Any]:
    """Return the D-29 fields of proxy diagnostics, and nothing else.

    ``request_id``, ``tool`` and the error code go in their own columns.
    """
    if type(diagnostics) is not Diagnostics:
        raise TypeError("diagnostics must be proxy Diagnostics")
    return {
        "exception_type": diagnostics.exception_type,
        "module": diagnostics.module,
        "function": diagnostics.function,
        "line": diagnostics.line,
        "stage": diagnostics.stage,
    }


# ----------------------------------------------------------------- logger


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _optional_text(value: object, field: str) -> None:
    if value is not None and (type(value) is not str or not value):
        raise ValueError(f"{field} must be a non-empty string or None")


class AuditLogger:
    """Builds, masks and commits audit events, one commit per event."""

    def __init__(
        self,
        store: AuditStore,
        *,
        clock: Callable[[], datetime] = _utc_now,
        max_chars: int = MAX_CHARS,
    ) -> None:
        """Create a logger.

        Args:
            store: the audit store events are committed to.
            clock: returns the event time; must be timezone-aware UTC.
            max_chars: the truncation limit for stored strings (NFR-017).
        """
        if type(store) is not AuditStore:
            raise TypeError("store must be an AuditStore")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if type(max_chars) is not int or max_chars < len(TRUNCATED) + 1:
            raise ValueError("max_chars is too small")
        self._store = store
        self._clock = clock
        self._max_chars = max_chars

    @property
    def store(self) -> AuditStore:
        """The audit store in use."""
        return self._store

    def record(
        self,
        event_type: str,
        *,
        request_id: str,
        agent_id: str | None = None,
        session_id: str | None = None,
        tool: str | None = None,
        decision: Decision | None = None,
        reason: str | None = None,
        policy_version: str | None = None,
        action_digest: str | None = None,
        execution: Execution | None = None,
        detail: Mapping[str, Any] | None = None,
    ) -> AuditRow:
        """Commit one event and return the committed row (with ``seq``).

        Raises:
            ValueError / TypeError: the event breaks the C4.2 / I-22 rules
                (a programming error; nothing is written).
            AuditUnavailableError: the event could not be committed; a masked
                record was attempted through ``logging``.
        """
        self._check(event_type, request_id, decision, reason, action_digest, execution)
        for value, name in (
            (agent_id, "agent_id"),
            (session_id, "session_id"),
            (tool, "tool"),
            (reason, "reason"),
            (policy_version, "policy_version"),
            (action_digest, "action_digest"),
        ):
            _optional_text(value, name)
        if detail is not None and not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping or None")
        detail_json = None
        if detail is not None:
            detail_json = json.dumps(
                mask(dict(detail), limit=self._max_chars),
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        now = self._clock()
        if type(now) is not datetime or now.utcoffset() != timedelta(0):
            raise ValueError("audit clock must return a timezone-aware UTC datetime")
        row = AuditRow(
            seq=None,
            event_id=str(uuid.uuid4()),
            request_id=request_id,
            event_type=event_type,
            occurred_at=now.isoformat(),
            agent_id=agent_id,
            session_id=session_id,
            tool=tool,
            decision=None if decision is None else decision.value,
            reason=reason,
            policy_version=policy_version,
            action_digest=action_digest,
            execution=None if execution is None else execution.value,
            detail=detail_json,
            schema_version=SCHEMA_VERSION,
        )
        try:
            seq = self._store.insert(row)
        except AuditUnavailableError:
            self._fallback(row)
            raise
        return AuditRow(**{**_as_dict(row), "seq": seq})

    @staticmethod
    def _check(
        event_type: object,
        request_id: object,
        decision: object,
        reason: object,
        action_digest: object,
        execution: object,
    ) -> None:
        """The C4.2 / C1.6 field rules (I-22)."""
        if type(event_type) is not str or event_type not in EVENT_TYPES:
            raise ValueError("unknown audit event type")
        if type(request_id) is not str or not request_id:
            raise ValueError("request_id must be a non-empty string")
        if decision is not None and type(decision) is not Decision:
            raise TypeError("decision must be a Decision or None")
        if execution is not None and type(execution) is not Execution:
            raise TypeError("execution must be an Execution or None")
        if decision is not None and event_type not in (DECISION, REQUEST_COMPLETED):
            raise ValueError("only DECISION and REQUEST_COMPLETED carry a decision")
        if event_type == DECISION and decision is None:
            raise ValueError("a DECISION event needs a decision")
        if (execution is None) != (event_type != REQUEST_COMPLETED):
            raise ValueError("execution is required on, and only on, REQUEST_COMPLETED")
        if event_type == EXECUTION_STARTED and action_digest is None:
            raise ValueError("EXECUTION_STARTED needs an action_digest")
        if event_type == ERROR and reason is None:
            raise ValueError("an ERROR event needs an error code")
        if decision in (Decision.DENY, Decision.REQUIRE_APPROVAL):
            if reason in NON_POLICY_REASONS:
                raise ValueError("an operational refusal is not a policy decision")
        if event_type == REQUEST_COMPLETED:
            if (
                decision is not Decision.ALLOW
                and execution is not Execution.NOT_STARTED
            ):
                raise ValueError("only an allowed request can have started")
            if decision is None and reason not in NULL_DECISION_CODES:
                raise ValueError("a NULL decision needs a refusal or error code")

    @staticmethod
    def _fallback(row: AuditRow) -> None:
        """Best-effort masked record of an uncommitted event (C1.7)."""
        try:
            payload = {
                "event_type": row.event_type,
                "request_id": row.request_id,
                "tool": row.tool,
                "decision": row.decision,
                "reason": row.reason,
                "execution": row.execution,
                "detail": row.detail,  # already masked and truncated
            }
            _LOG.warning(
                "audit event not committed: %s",
                json.dumps(payload, sort_keys=True, ensure_ascii=False),
            )
        except Exception:  # noqa: S110 - best effort; the caller gets the audit error
            pass


def _as_dict(row: AuditRow) -> dict[str, Any]:
    return {name: getattr(row, name) for name in AuditRow.__slots__}


# --------------------------------------------------- reconstruction (C4.4)


@dataclass(frozen=True, slots=True)
class RequestState:
    """What the committed audit rows establish about one request (C4.4).

    ``basis`` names the C4.4 row: ``no_decision`` or ``not_allowed`` (not
    executed, guaranteed), ``not_started`` (allowed, no EXECUTION_STARTED:
    not executed, guaranteed), ``recorded`` (as REQUEST_COMPLETED says) or
    ``no_completion`` (EXECUTION_STARTED without REQUEST_COMPLETED: unknown).
    """

    request_id: str
    decision: Decision | None
    execution: Execution
    basis: str
    completed: bool
    completed_decision: Decision | None
    reason: str | None
    output: str | None


def _decision(value: str | None) -> Decision | None:
    try:
        return None if value is None else Decision(value)
    except ValueError:
        raise AuditIntegrityError("audit row has an unknown decision") from None


def _execution(value: str | None) -> Execution | None:
    try:
        return None if value is None else Execution(value)
    except ValueError:
        raise AuditIntegrityError("audit row has an unknown execution state") from None


def _reconstruct_one(request_id: str, rows: list[AuditRow]) -> RequestState:
    if rows[0].event_type != REQUEST_RECEIVED:
        raise AuditIntegrityError("request does not start with REQUEST_RECEIVED")
    decision_row = started_row = completed_row = None
    output = None
    for row in rows:
        kind = row.event_type
        if kind not in EVENT_TYPES:
            raise AuditIntegrityError("audit row has an unknown event type")
        if completed_row is not None and kind != ERROR:
            raise AuditIntegrityError("event after REQUEST_COMPLETED")
        if kind == REQUEST_RECEIVED and row is not rows[0]:
            raise AuditIntegrityError("more than one REQUEST_RECEIVED")
        elif kind == DECISION:
            if decision_row is not None:
                raise AuditIntegrityError("more than one DECISION")
            decision_row = row
        elif kind == EXECUTION_STARTED:
            if started_row is not None:
                raise AuditIntegrityError("more than one EXECUTION_STARTED")
            if (
                decision_row is None
                or _decision(decision_row.decision) is not Decision.ALLOW
                or decision_row.action_digest != row.action_digest
            ):
                raise AuditIntegrityError("EXECUTION_STARTED without a matching allow")
            started_row = row
        elif kind in (OUTPUT_FILTERED, OUTPUT_WITHHELD):
            if started_row is None or output is not None:
                raise AuditIntegrityError("output event without EXECUTION_STARTED")
            output = "filtered" if kind == OUTPUT_FILTERED else "withheld"
        elif kind == REQUEST_COMPLETED:
            completed_row = row

    decision = None if decision_row is None else _decision(decision_row.decision)
    if decision_row is not None and decision is None:
        raise AuditIntegrityError("DECISION row without a decision")
    completed_decision = None
    reason = None
    if completed_row is not None:
        completed_decision = _decision(completed_row.decision)
        reason = completed_row.reason
        recorded = _execution(completed_row.execution)
        if recorded is None:
            raise AuditIntegrityError("REQUEST_COMPLETED without an execution state")
        if completed_decision is not None and completed_decision is not decision:
            raise AuditIntegrityError("REQUEST_COMPLETED contradicts the DECISION")
        if started_row is None and recorded is not Execution.NOT_STARTED:
            raise AuditIntegrityError("execution reported without EXECUTION_STARTED")

    if decision is None:
        execution, basis = Execution.NOT_STARTED, "no_decision"
    elif decision is not Decision.ALLOW:
        execution, basis = Execution.NOT_STARTED, "not_allowed"
    elif started_row is None:
        execution, basis = Execution.NOT_STARTED, "not_started"
    elif completed_row is not None:
        execution, basis = recorded, "recorded"
    else:
        execution, basis = Execution.UNKNOWN, "no_completion"
    return RequestState(
        request_id=request_id,
        decision=decision,
        execution=execution,
        basis=basis,
        completed=completed_row is not None,
        completed_decision=completed_decision,
        reason=reason,
        output=output,
    )


def reconstruct(rows: Iterable[AuditRow]) -> dict[str, RequestState]:
    """Classify every request in ``rows`` from the committed events alone.

    Rows are grouped by ``request_id`` and ordered by ``seq``. The result is
    ordered by each request's first event. Never consults policy or the
    registry.

    Raises:
        AuditIntegrityError: a request's events are inconsistent (I-23).
    """
    grouped: dict[str, list[AuditRow]] = {}
    for row in rows:
        if type(row) is not AuditRow or type(row.seq) is not int:
            raise AuditIntegrityError("reconstruction needs committed audit rows")
        grouped.setdefault(row.request_id, []).append(row)
    states = []
    for request_id, items in grouped.items():
        items.sort(key=lambda r: r.seq)
        states.append((items[0].seq, _reconstruct_one(request_id, items)))
    states.sort(key=lambda pair: pair[0])
    return {state.request_id: state for _, state in states}
