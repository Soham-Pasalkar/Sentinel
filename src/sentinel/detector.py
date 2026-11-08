"""Detector stub (C-11; FR-014 M1).

``NullDetector.analyze(request, context)`` returns no findings. Heuristic
detection is C-13. No findings is never an authorization: identity, grant,
path and destructive checks still apply (D-15). There is no Tool-Abuse
detector in v1 (D-15). This module is internal.
"""

from __future__ import annotations

from sentinel.models import SecurityContext, SecurityFinding, SecurityRequest

__all__ = ["NullDetector"]


class NullDetector:
    """The M1 detector: it finds nothing."""

    def analyze(
        self, request: SecurityRequest, context: SecurityContext
    ) -> tuple[SecurityFinding, ...]:
        """Return no findings."""
        return ()
