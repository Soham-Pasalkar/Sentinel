"""Heuristic detection (C-13; FR-014, D-24e, D-24h; owner 2026-11-18).

``HeuristicDetector.analyze(request, context)`` scans every ``str`` key and
value of the validated tool arguments and returns ``SecurityFinding``s.

* **Advisory only (D-24h).** A finding is a signal, never a decision. Only
  the policy engine decides: it denies when a finding's severity reaches
  ``deny_at_severity`` (C1.5 row 4). No findings is never an authorization:
  identity, grant, path and destructive checks still apply (D-15). Detection
  reduces risk; it does not reliably detect, and cannot prevent, prompt
  injection or data leakage.
* **Fail closed, without a new authority (D-24e).** If the scan cannot cover
  every string within its limits (depth, number of values, characters), or
  meets a value it cannot inspect, it returns a ``SCAN_INCOMPLETE`` finding of
  severity ``CRITICAL``, which every threshold denies. Nothing is truncated
  and passed on. An exception raised here is an internal error: the pipeline
  reports ``decision=None``, ``INTERNAL_ERROR`` (C1.8, Q-03c).
* **Public codes are coarse (OD-5):** ``PROMPT_INJECTION``,
  ``SENSITIVE_DATA``, ``SCAN_INCOMPLETE``. The rule that matched (``PI-*``,
  ``SD-*``, ``SC-01``) is recorded only in the audit ``evidence``.
* **Evidence holds no argument content:** the rule, the match count, the
  first location and the offset and length of the match. A location names a
  top-level argument only by the sanitised label that the registered tool's
  schema defines (``SchemaKeys.named``, computed at registration; G-3, F-1);
  any other top-level key, and every nested key, is given by its sorted
  position (``#n``). No location is derived from a request-supplied key, so a
  schema whose validators accept undeclared keys cannot place one in the
  audit. Without schema keys (no resolver, or an unregistered tool) every
  top-level key is positional.
* **Deterministic and bounded:** keys are visited in sorted order; one
  finding per rule; prompt-injection phrases are matched over tokens without
  regular expressions; sensitive-data patterns use a literal anchor and only
  bounded or possessive quantifiers (Python 3.11+), so they cannot backtrack
  catastrophically. Results are deterministic for a given Python (Unicode
  database) version.

There is no Tool-Abuse detector (D-15) and no anomaly detection in v1. This
module is internal.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from sentinel.audit_shape import SchemaKeys
from sentinel.models import SecurityContext, SecurityFinding, SecurityRequest, Severity

__all__ = [
    "MAX_SCAN_CHARS",
    "MAX_SCAN_DEPTH",
    "MAX_SCAN_VALUES",
    "PROMPT_INJECTION",
    "RULES",
    "SCAN_INCOMPLETE",
    "SENSITIVE_DATA",
    "HeuristicDetector",
    "NullDetector",
]

#: Public finding codes (policy reasons; OD-2, OD-5).
PROMPT_INJECTION = "PROMPT_INJECTION"
SENSITIVE_DATA = "SENSITIVE_DATA"
SCAN_INCOMPLETE = "SCAN_INCOMPLETE"

#: Scan limits (OD-4): fixed in v1, not configurable.
MAX_SCAN_DEPTH = 32  # nesting depth of a scanned value; top-level values are 1
MAX_SCAN_VALUES = 10_000  # keys, values and containers visited
MAX_SCAN_CHARS = 1_000_000  # NFKC-normalised characters scanned in total


@dataclass(frozen=True, slots=True)
class Rule:
    """One catalogue entry: its stable id, public code and severity."""

    rule_id: str
    code: str
    severity: Severity


#: The approved catalogue (OD-3; PI-04 MEDIUM by the owner's decision).
RULES: dict[str, Rule] = {
    r.rule_id: r
    for r in (
        Rule("PI-01", PROMPT_INJECTION, Severity.MEDIUM),  # override phrase
        Rule("PI-02", PROMPT_INJECTION, Severity.MEDIUM),  # exfiltration directive
        Rule("PI-03", PROMPT_INJECTION, Severity.HIGH),  # PI-01 and PI-02 together
        Rule("PI-04", PROMPT_INJECTION, Severity.MEDIUM),  # model control tokens
        Rule("PI-05", PROMPT_INJECTION, Severity.MEDIUM),  # invisible text
        Rule("SD-01", SENSITIVE_DATA, Severity.CRITICAL),  # PEM private key
        Rule("SD-02", SENSITIVE_DATA, Severity.HIGH),  # AWS access key id
        Rule("SD-03", SENSITIVE_DATA, Severity.HIGH),  # GitHub token
        Rule("SD-04", SENSITIVE_DATA, Severity.HIGH),  # Slack token
        Rule("SD-05", SENSITIVE_DATA, Severity.HIGH),  # Stripe live secret
        Rule("SD-06", SENSITIVE_DATA, Severity.HIGH),  # JSON web token
        Rule("SD-07", SENSITIVE_DATA, Severity.HIGH),  # credentials in a URL
        Rule("SD-08", SENSITIVE_DATA, Severity.MEDIUM),  # payment card
        Rule("SD-09", SENSITIVE_DATA, Severity.MEDIUM),  # US SSN
        Rule("SD-10", SENSITIVE_DATA, Severity.HIGH),  # bearer token
        Rule("SD-11", SENSITIVE_DATA, Severity.MEDIUM),  # password assignment
        Rule("SC-01", SCAN_INCOMPLETE, Severity.CRITICAL),  # scan not complete
    )
}


class NullDetector:
    """A detector that finds nothing (the M1 stub; kept for tests)."""

    def analyze(
        self, request: SecurityRequest, context: SecurityContext
    ) -> tuple[SecurityFinding, ...]:
        """Return no findings."""
        return ()


# ------------------------------------------------------------ text rules

# Characters removed before matching (explicit list, so the result does not
# depend on the Unicode version's Cf table): soft hyphen, Arabic letter mark,
# Mongolian vowel separator, zero-width and directional marks, word joiner
# and invisible operators, bidi embeddings and isolates, BOM, tag characters.
_INVISIBLE = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
# PI-05 on the raw text: tag characters outside emoji flag sequences, and
# bidirectional embedding, override and isolate controls.
_FLAG_SEQUENCE = re.compile("\U0001f3f4[\U000e0061-\U000e007a]{1,8}+\U000e007f")
_PI05 = re.compile("[\U000e0000-\U000e007f\u202a-\u202e\u2066-\u2069]")

# PI-01: verb, then at most 3 tokens, then a scope word, then at most 2
# tokens, then an instruction noun.
_PI01_VERBS = frozenset({"ignore", "disregard", "forget", "override", "bypass"})
_PI01_SCOPES = frozenset(
    {"previous", "prior", "above", "earlier", "preceding", "all", "your", "system"}
)
_PI01_OBJECTS = frozenset(
    {
        "instructions",
        "instruction",
        "prompt",
        "prompts",
        "rules",
        "guidelines",
        "directions",
    }
)
# PI-02: an exfiltration verb, a secret noun and a destination, in one string.
_PI02_VERBS = frozenset(
    {
        "send",
        "email",
        "mail",
        "upload",
        "post",
        "forward",
        "exfiltrate",
        "paste",
        "transmit",
        "leak",
    }
)
_PI02_SECRET_WORDS = frozenset(
    {
        "password",
        "passwords",
        "passwd",
        "credential",
        "credentials",
        "secret",
        "secrets",
        "apikey",
        "api_key",
        "token",
        "tokens",
    }
)
_PI02_SECRET_PAIRS = frozenset(
    {("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key")}
)
_PI02_SECRET_PATHS = re.compile(
    r"\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.env\b|\.aws/|\.netrc\b"
)
_PI02_DESTINATION = re.compile(
    r"(?<=[\w.+-])@[\w-]{1,63}+(?:\.[\w-]{1,63}+)++|\bhttps?://"
)
_PI04 = re.compile(
    "|".join(
        re.escape(token)
        for token in (
            "<|im_start|>",
            "<|im_end|>",
            "<|system|>",
            "<|endoftext|>",
            "<|start_header_id|>",
            "<|end_header_id|>",
            "<|eot_id|>",
            "<<sys>>",
            "[inst]",
            "[/inst]",
        )
    )
)
_TOKEN = re.compile(r"\w+")

# Sensitive data, matched on the NFKC text with invisible characters removed
# (case preserved). Literal anchors; bounded or possessive quantifiers only.
_SD_PATTERNS: dict[str, re.Pattern[str]] = {
    "SD-01": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        r"\s*+(?:[A-Za-z0-9+/=]{16}\s*+){4}"
    ),
    "SD-02": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "SD-03": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "SD-04": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,200}+"),
    "SD-05": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,99}+"),
    "SD-06": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,256}+\.eyJ[A-Za-z0-9_-]{10,8192}+"
        r"\.[A-Za-z0-9_-]{16,1024}+"
    ),
    "SD-07": re.compile(
        r"\b[a-z][a-z0-9+.-]{1,20}+://([^\s:/@]{1,64}+):([^\s@/]{1,128}+)@",
        re.IGNORECASE,
    ),
    # Contiguous digits, or the 4-4-4-4 and 4-6-5 groupings.
    "SD-08": re.compile(
        r"(?<!\d)(?:\d{13,19}+|\d{4}(?:[ -]\d{4}){3}|\d{4}[ -]\d{6}[ -]\d{5})"
        r"(?!\d)"
    ),
    "SD-09": re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"),
    "SD-10": re.compile(r"\bbearer\s++([A-Za-z0-9._~+/=-]{20,512}+)", re.IGNORECASE),
    "SD-11": re.compile(
        r"\b(?:password|passwd|pwd|secret|api[_-]?key)\s*+[:=]\s*+\S{8,128}+",
        re.IGNORECASE,
    ),
}
#: Documentation placeholders that are not secrets.
_AWS_EXAMPLE_KEYS = frozenset({"AKIAIOSFODNN7EXAMPLE"})
_PLACEHOLDER_PASSWORDS = frozenset({"password", "pass", "secret", "changeme"})
_CARD_PREFIXES = re.compile(
    r"4|5[1-5]|2(?:22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)|3[47]|6011|65"
)


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _sd_accept(rule_id: str, match: re.Match[str]) -> bool:
    """Rule-specific checks that a regular expression cannot express."""
    if rule_id == "SD-02":
        return match.group(0) not in _AWS_EXAMPLE_KEYS
    if rule_id == "SD-07":
        password = match.group(2)
        return not (
            password.lower() in _PLACEHOLDER_PASSWORDS
            or (password.startswith("<") and password.endswith(">"))
        )
    if rule_id == "SD-08":
        digits = re.sub(r"[ -]", "", match.group(0))
        return (
            13 <= len(digits) <= 19
            and _CARD_PREFIXES.match(digits) is not None
            and _luhn(digits)
        )
    if rule_id == "SD-09":
        area, group, serial = match.groups()
        return not (
            area in ("000", "666")
            or area.startswith("9")
            or group == "00"
            or serial == "0000"
        )
    if rule_id == "SD-10":
        token = match.group(1)
        return any(c.isdigit() for c in token) and any(c.isalpha() for c in token)
    return True


def _pi01(tokens: list[str]) -> int | None:
    """Index of the first token of an override phrase, or ``None``."""
    count = len(tokens)
    for i, token in enumerate(tokens):
        if token not in _PI01_VERBS:
            continue
        for j in range(i + 1, min(i + 5, count)):
            if tokens[j] in _PI01_SCOPES:
                for k in range(j + 1, min(j + 4, count)):
                    if tokens[k] in _PI01_OBJECTS:
                        return i
    return None


def _pi02(tokens: list[str], lowered: str) -> int | None:
    """Index of the first exfiltration verb, if all three parts are present."""
    verb = next((i for i, t in enumerate(tokens) if t in _PI02_VERBS), None)
    if verb is None or _PI02_DESTINATION.search(lowered) is None:
        return None
    has_secret = (
        any(t in _PI02_SECRET_WORDS for t in tokens)
        or any(pair in _PI02_SECRET_PAIRS for pair in itertools.pairwise(tokens))
        or _PI02_SECRET_PATHS.search(lowered) is not None
    )
    return verb if has_secret else None


# ----------------------------------------------------------------- scan


class _Incomplete(Exception):
    """The scan stopped before covering every value."""

    def __init__(self, limit: str, location: str) -> None:
        super().__init__(limit)
        self.limit = limit
        self.location = location


@dataclass
class _Hit:
    count: int
    location: str
    offset: int
    length: int


@dataclass
class _Scan:
    """One request's scan state: budgets and per-rule hits."""

    values: int = 0
    chars: int = 0
    hits: dict[str, _Hit] = field(default_factory=dict)
    active: set[int] = field(default_factory=set)

    def hit(self, rule_id: str, location: str, offset: int, length: int) -> None:
        current = self.hits.get(rule_id)
        if current is None:
            self.hits[rule_id] = _Hit(1, location, offset, length)
        else:
            current.count += 1

    def visit(self, value: object, depth: int, location: str) -> None:
        if depth > MAX_SCAN_DEPTH:
            raise _Incomplete("depth", location)
        self.values += 1
        if self.values > MAX_SCAN_VALUES:
            raise _Incomplete("values", location)
        kind = type(value)
        if kind is str:
            self.scan_string(value, location)
        elif kind in (int, float, bool, type(None)):
            return
        elif kind is dict or kind is list:
            marker = id(value)
            if marker in self.active:
                raise _Incomplete("cycle", location)
            self.active.add(marker)
            try:
                if kind is list:
                    for index, item in enumerate(value):
                        self.visit(item, depth + 1, f"{location}[{index}]")
                else:
                    self.visit_dict(value, depth, location)
            finally:
                self.active.discard(marker)
        else:
            raise _Incomplete("unsupported_value", location)

    def ordered_keys(self, mapping: dict[object, object], location: str) -> list[str]:
        """Bounded preflight, then the keys in sorted order (resource guard).

        Before any per-key work, the dictionary must fit the remaining value
        budget (each entry costs at least two values: its key and its value;
        ``len`` is O(1)). Only then are the keys iterated once, to reject
        non-``str`` keys and to check that their raw lengths fit the remaining
        character budget, which bounds the comparison work of the sort. A
        dictionary that fails either check is never sorted or scanned; the
        scan stops with ``SCAN_INCOMPLETE``.
        """
        if 2 * len(mapping) > MAX_SCAN_VALUES - self.values:
            raise _Incomplete("values", location)
        key_chars = 0
        for key in mapping:
            if type(key) is not str:
                raise _Incomplete("unsupported_value", location)
            key_chars += len(key)
        if key_chars > MAX_SCAN_CHARS - self.chars:
            raise _Incomplete("chars", location)
        return sorted(mapping)

    def visit_dict(
        self, mapping: dict[object, object], depth: int, location: str
    ) -> None:
        for position, key in enumerate(self.ordered_keys(mapping, location)):
            child = f"{location}.#{position}"
            self.values += 1
            if self.values > MAX_SCAN_VALUES:
                raise _Incomplete("values", child)
            self.scan_string(key, f"{child}(key)")
            self.visit(mapping[key], depth + 1, child)

    def scan_string(self, raw: str, location: str) -> None:
        remaining = MAX_SCAN_CHARS - self.chars
        if len(raw) > remaining:
            raise _Incomplete("chars", location)
        normalised = unicodedata.normalize("NFKC", raw)
        if len(normalised) > remaining:
            raise _Incomplete("chars", location)
        self.chars += len(normalised)

        # PI-05 on the raw text, before invisible characters are removed.
        found = _PI05.search(_FLAG_SEQUENCE.sub("", raw))
        if found is not None:
            self.hit("PI-05", location, found.start(), 1)

        text = _INVISIBLE.sub("", normalised)
        for rule_id, pattern in _SD_PATTERNS.items():
            for match in pattern.finditer(text):
                if _sd_accept(rule_id, match):
                    self.hit(rule_id, location, match.start(), len(match.group(0)))

        lowered = text.casefold()
        spans = [(m.start(), m.group(0)) for m in _TOKEN.finditer(lowered)]
        tokens = [token for _, token in spans]
        override = _pi01(tokens)
        if override is not None:
            self.hit("PI-01", location, spans[override][0], len(spans[override][1]))
        exfiltration = _pi02(tokens, lowered)
        if exfiltration is not None:
            start, token = spans[exfiltration]
            self.hit("PI-02", location, start, len(token))
        if override is not None and exfiltration is not None:
            start, token = spans[override]
            self.hit("PI-03", location, start, len(token))
        control = _PI04.search(lowered)
        if control is not None:
            self.hit("PI-04", location, control.start(), len(control.group(0)))


def _top_level(name: str, position: int, named: Mapping[str, str]) -> str:
    """A top-level location, never the request-supplied key itself (F-1).

    The schema's label for a key in ``named``, else the key's sorted position.
    """
    label = named.get(name)
    if label is None:
        return f"arguments.#{position}"
    return f"arguments.{label}"


_NO_NAMES: Mapping[str, str] = {}


class HeuristicDetector:
    """The C-13 detector: advisory findings over argument strings.

    ``schema_keys`` resolves a tool name to its cached ``SchemaKeys`` (the
    pipeline passes the registry's; G-3, F-1). It is used only to label
    top-level locations in evidence; detection itself does not depend on it.
    """

    def __init__(
        self, schema_keys: Callable[[str], SchemaKeys | None] | None = None
    ) -> None:
        """Keep the optional tool-name to ``SchemaKeys`` resolver."""
        self._schema_keys = schema_keys

    def _names(self, tool: object) -> Mapping[str, str]:
        if self._schema_keys is None or type(tool) is not str:
            return _NO_NAMES
        keys = self._schema_keys(tool)
        return _NO_NAMES if keys is None else keys.named

    def analyze(
        self, request: SecurityRequest, context: SecurityContext
    ) -> tuple[SecurityFinding, ...]:
        """Return findings for ``request.arguments``; never a decision."""
        scan = _Scan()
        incomplete: _Incomplete | None = None
        try:
            arguments = request.arguments
            if type(arguments) is not dict:
                raise _Incomplete("unsupported_value", "arguments")
            named = self._names(request.tool)
            for position, name in enumerate(scan.ordered_keys(arguments, "arguments")):
                location = _top_level(name, position, named)
                scan.values += 1
                if scan.values > MAX_SCAN_VALUES:
                    raise _Incomplete("values", location)
                scan.scan_string(name, f"{location}(key)")
                scan.visit(arguments[name], 1, location)
        except _Incomplete as stop:
            incomplete = stop
        findings = [
            SecurityFinding(
                code=RULES[rule_id].code,
                severity=RULES[rule_id].severity,
                evidence=(
                    f"rule={rule_id} count={h.count} first={h.location} "
                    f"offset={h.offset} length={h.length}"
                ),
            )
            for rule_id, h in scan.hits.items()
        ]
        if incomplete is not None:
            findings.append(
                SecurityFinding(
                    code=SCAN_INCOMPLETE,
                    severity=Severity.CRITICAL,
                    evidence=(
                        f"rule=SC-01 limit={incomplete.limit} at={incomplete.location}"
                    ),
                )
            )
        findings.sort(key=lambda f: (-f.severity, f.code, f.evidence))
        return tuple(findings)
