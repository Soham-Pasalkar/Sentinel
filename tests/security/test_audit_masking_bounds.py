"""G-1 (2026-11-18): audit masking is linear in the text length and still
masks everything it masked before (C-09; I-18, I-19; SEC-008).

The previous JWT-like pattern,
``\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}``, required
two later segments after an unbounded first one. On text like ``eyJ-eyJ-…``
every start scanned to the end of the run and backtracked: quadratic time
(measured 0.013 s / 0.051 s / 0.206 s at 8k / 16k / 32k characters before the
fix). Masking runs on raw request text before any validation, so this was
reachable from a single model-controlled argument or tool name.

* ``test_new_jwt_mask_covers_everything_the_old_one_masked`` checks, over an
  exhaustive small grammar of token-like strings, that every character the old
  pattern masked is masked by the new one (masking only grows).
* The adversarial tests run every pattern on crafted inputs: first a fast
  128,000-character check, so a regression fails quickly, then 1,000,000
  characters against a generous ceiling relative to masking plain text of the
  same size. They guard against regressions; the linearity claim rests on the
  patterns' structure (documented in ``audit.py``), not on timings.
"""

import itertools
import re
import time

import pytest

from sentinel.audit import _PATTERNS, MASK, mask

OLD_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
NEW_JWT = _PATTERNS[-1]


def _spans(pattern, text):
    return [m.span() for m in pattern.finditer(text)]


def _covered(span, spans):
    start, end = span
    return all(any(s <= i < e for s, e in spans) for i in range(start, end))


# ------------------------------------------------- coverage is preserved

_PIECES = ["eyJ", "aaaaa", "ab", "-", ".", " "]
_CORES = [
    "eyJaaaaa.bbbbb.ccccc",
    "eyJa-b_c.d-e-f.g_h-i",
    "eyJaaaaaaa.bbbbb.ccccc.ddddd",
]


def _around(max_prefix, max_suffix):
    for core in _CORES:
        for i in range(max_prefix + 1):
            for prefix in itertools.product(_PIECES, repeat=i):
                for j in range(max_suffix + 1):
                    for suffix in itertools.product(_PIECES, repeat=j):
                        yield "".join(prefix) + core + "".join(suffix)


def test_new_jwt_mask_covers_everything_the_old_one_masked():
    # Every JWT-shaped core with every prefix of up to 4 pieces and suffix of
    # up to 3 pieces (3 x 1,555 x 259 = 1,208,235 strings): each character the
    # old pattern masked is masked by the new one.
    checked = 0
    for text in _around(4, 3):
        old = _spans(OLD_JWT, text)
        if old:
            new = _spans(NEW_JWT, text)
            for span in old:
                assert _covered(span, new), (text, span, new)
            checked += 1
    # 824,397 have an old match (a prefix ending in a word character leaves
    # no word boundary before the core).
    assert checked == 824_397


@pytest.mark.parametrize(
    "text",
    [
        # Found while reviewing the candidate fix with "{0,2}" segments: a
        # real JWT after a short token-like prefix stays fully masked.
        "eyJaaaaa.bb.eyJccccc.ddddd.eeeee",
        "x eyJaaaaa.eyJbbbbb.ccccc.ddddd y",
        "eyJaaa-eyJbbbbb.ccccc.ddddd",
        "prefix.eyJhbGciOi.eyJzdWIi.c2lnbmF0dXJl.extra",
    ],
)
def test_layouts_around_a_real_jwt_stay_masked(text):
    for span in _spans(OLD_JWT, text):
        assert _covered(span, _spans(NEW_JWT, text))


def _jwt():
    header = "ey" + "JhbGciOiJIUzI1NiJ9"
    payload = "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
    return header + "." + payload + "." + "dozjgNryP4J3jVmNHl0w5N"


# Every format the audit value patterns supported before G-1, built from
# fragments so no complete credential-shaped literal is committed.
SUPPORTED = {
    "jwt": _jwt(),
    "jwt-like token": "ey" + "J" + "abcdefgh",
    "aws access key id": "AK" + "IA" + "ABCDEFGHIJKLMNOP",
    "github token": "gh" + "p_" + "a1" * 18,
    "github oauth token": "gh" + "o_" + "B" * 24,
    "sk- api key": "s" + "k-" + "x9" * 16,
    "slack token": "xo" + "xb-" + "1234567890-abcdefghij",
    "bearer token": "Bearer " + "abc123" + "def456ghi789",
    "pem private key": "-----BEGIN RSA PRIVATE " + "KEY-----\nMIIBabc\n"
    "-----END RSA PRIVATE " + "KEY-----",
    "unterminated pem": "-----BEGIN PRIVATE " + "KEY-----\nMIIBabc (cut)",
}


@pytest.mark.parametrize("name", sorted(SUPPORTED))
def test_supported_formats_are_still_masked(name):
    secret = SUPPORTED[name]
    out = mask({"note": f"before {secret} after"})["note"]
    assert MASK in out
    assert secret not in out
    assert out.startswith("before ")


def test_masking_still_precedes_truncation():
    secret = _jwt()
    out = mask({"v": "x" * 1_000 + " " + secret})["v"]
    assert secret[:12] not in out


def test_text_without_tokens_is_unchanged():
    text = "eyes eyJ eyJab eyJab. find files about bears"
    assert mask({"q": text}) == {"q": text}


# ------------------------------------------------------ adversarial inputs

ADVERSARIAL = {
    "jwt prefixes with hyphens": lambda n: "eyJ-" * (n // 4),
    "jwt dotted near-miss": lambda n: "eyJaaaaa." * (n // 9),
    "jwt short segments": lambda n: "eyJab." * (n // 6),
    "pem header without key": lambda n: "-----BEGIN " + "A" * n,
    "pem headers": lambda n: "-----BEGIN PRIVATE KEY-----" * (n // 27),
    "pem with end attempts": lambda n: (
        "-----BEGIN PRIVATE KEY-----" + "-----END A" * (n // 10)
    ),
    "bearer then whitespace": lambda n: "bearer" + " " * n + "!",
    "bearer repeated": lambda n: "bearer " * (n // 7),
    "aws prefixes": lambda n: "AKIA" * (n // 4),
    "github prefixes": lambda n: "ghp_" * (n // 4),
    "sk prefixes": lambda n: "sk-" * (n // 3),
    "slack prefixes": lambda n: "xoxb-" * (n // 5),
}


def _seconds(text):
    start = time.perf_counter()
    mask({"v": text})
    return time.perf_counter() - start


@pytest.mark.parametrize("build", ADVERSARIAL.values(), ids=ADVERSARIAL.keys())
def test_adversarial_masking_is_fast_at_128k(build):
    # Fast regression check: linear masking takes milliseconds here; the old
    # JWT pattern took about 3 seconds on "eyJ-" input of this size.
    assert _seconds(build(128_000)) < 1.0


@pytest.mark.parametrize("build", ADVERSARIAL.values(), ids=ADVERSARIAL.keys())
def test_adversarial_masking_at_one_million_characters(build):
    text = build(1_000_000)
    assert 990_000 <= len(text) <= 1_000_100
    baseline = min(_seconds("a" * len(text)) for _ in range(3))
    elapsed = min(_seconds(text) for _ in range(2))
    # Generous: linear inputs measure within 2x of plain text locally.
    assert elapsed < 25 * baseline + 1.0
