"""C-13 corpus measurements (DC; testing strategy §17; owner 2026-11-18).

Counts on the stated corpus only (``tests/data/detector_corpus.py``), never
a general detection rate. The exact numbers are pinned, so any change in
detection behaviour shows up here and must be reflected in the testing
strategy.
"""

import collections
import importlib.util
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sentinel.detector import HeuristicDetector
from sentinel.models import SecurityRequest, Severity

_PATH = Path(__file__).resolve().parents[1] / "data" / "detector_corpus.py"
_spec = importlib.util.spec_from_file_location("detector_corpus", _PATH)
corpus = importlib.util.module_from_spec(_spec)
sys.modules["detector_corpus"] = corpus
_spec.loader.exec_module(corpus)

DETECTOR = HeuristicDetector()
_RULE = re.compile(r"rule=(\S+)")


def hits(text):
    request = SecurityRequest(
        request_id="r-1",
        received_at=datetime(2026, 11, 18, tzinfo=UTC),
        agent_id="agent",
        session_id="session",
        tool="tool",
        arguments={"text": text},
    )
    return [
        (_RULE.match(f.evidence).group(1), f.severity)
        for f in DETECTOR.analyze(request, None)
    ]


def blocked(text):
    return any(severity >= Severity.HIGH for _, severity in hits(text))


def test_benign_corpus_size_and_categories():
    assert sorted(corpus.BENIGN) == [
        "code",
        "config",
        "docs_placeholders",
        "email",
        "logs",
        "multilingual",
        "records",
        "security_discussion",
    ]
    assert all(len(items) == 50 for items in corpus.BENIGN.values())


@pytest.mark.parametrize("category", sorted(corpus.BENIGN))
def test_no_benign_string_is_blocked_at_the_default_threshold(category):
    offending = [
        text
        for text in corpus.BENIGN[category]
        if blocked(text) and text not in corpus.KNOWN_BENIGN_BLOCKS
    ]
    assert offending == []


def test_benign_audit_only_findings_are_the_measured_ones():
    # MEDIUM/LOW findings on benign text are allowed (audited, not blocking);
    # they are counted so that drift is visible.
    counted = collections.Counter(
        (category, rule, severity.name)
        for category, items in corpus.BENIGN.items()
        for text in items
        for rule, severity in hits(text)
    )
    assert counted == {
        ("security_discussion", "PI-01", "MEDIUM"): 5,
        ("docs_placeholders", "SD-11", "MEDIUM"): 5,
    }


def test_every_malicious_string_is_detected_by_its_rule():
    assert len(corpus.MALICIOUS) == 165
    missed = [
        (rule, text)
        for rule, text in corpus.MALICIOUS
        if rule not in {r for r, _ in hits(text)}
    ]
    assert missed == []


def test_malicious_strings_blocked_at_the_default_threshold():
    # The rest match MEDIUM rules only (audited, not blocking), by design.
    assert sum(blocked(text) for _, text in corpus.MALICIOUS) == 90


def test_documented_evasions_are_not_blocked():
    # Known limits (D-24h): each of these attacks passes the default policy.
    assert len(corpus.EVASION) == 26
    assert [name for name, text in corpus.EVASION if blocked(text)] == []
    with_findings = sorted(name for name, text in corpus.EVASION if hits(text))
    assert with_findings == ["html entities", "hyphenated"]
