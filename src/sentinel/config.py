"""Pipeline configuration (C-11; interpretation I-31).

``SentinelConfig`` carries only already-approved settings: the audit store
path (D-11), the identity credential requirement (D-04, I-6) and the
``tool_call_id`` guard defaults (D-31). Invalid values raise
``ConfigurationError``. This module is internal.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sentinel.exceptions import ConfigurationError
from sentinel.proxy import DEFAULT_GUARD_CAPACITY, DEFAULT_GUARD_TTL_SECONDS
from sentinel.store import DEFAULT_AUDIT_DB_PATH

__all__ = ["SentinelConfig"]


class SentinelConfig(BaseModel):
    """Settings for ``build_pipeline``."""

    model_config = ConfigDict(
        frozen=True, strict=True, extra="forbid", hide_input_in_errors=True
    )

    audit_db_path: Annotated[str, Field(min_length=1)] = DEFAULT_AUDIT_DB_PATH
    require_credentials: bool = True
    guard_ttl_seconds: Annotated[float, Field(gt=0, allow_inf_nan=False)] = (
        DEFAULT_GUARD_TTL_SECONDS
    )
    guard_capacity: Annotated[int, Field(gt=0)] = DEFAULT_GUARD_CAPACITY

    def __init__(self, /, **data: Any) -> None:
        """Validate the settings; raise ``ConfigurationError`` if invalid."""
        try:
            super().__init__(**data)
        except ValidationError:
            raise ConfigurationError("invalid Sentinel configuration") from None
