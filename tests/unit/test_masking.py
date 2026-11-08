"""Masking and truncation tests (C-09): SEC-008, NFR-017, D-29; I-18, I-19;
AT-12 and AT-32 (audit part).

Masking is heuristic (D-29): these tests pin the recorded rules; they do not
claim that every secret can be recognised.
"""

import copy
import importlib.util
import json
import logging
import os
import uuid
from datetime import UTC, datetime

import pytest
from pydantic import SecretStr

from sentinel.audit import (
    ERROR,
    MASK,
    MAX_CHARS,
    TRUNCATED,
    AuditLogger,
    diagnostics_detail,
    mask,
)
from sentinel.models import TOOL_FAILED
from sentinel.proxy import Diagnostics, _diagnostics
from sentinel.store import AuditStore

T0 = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)


@pytest.fixture
def canary():
    return "CANARY-" + uuid.uuid4().hex


# ============================================================ key names


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Password",
        "user_password",
        "passwd",
        "passphrase",
        "secret",
        "client_secret",
        "SECRET_VALUE",
        "token",
        "access_token",
        "refresh-token",
        "api_key",
        "apiKey",
        "API-KEY",
        "x.api.key",
        "aws_access_key",
        "private_key",
        "privateKey",
        "credential",
        "credentials",
        "Authorization",
        "cookie",
        "Set-Cookie",
        "session_key",
    ],
)
def test_sensitive_key_names_mask_the_whole_value(key, canary):
    for value in (canary, {"nested": canary}, [canary], 12345):
        masked = mask({key: value})
        assert masked == {key: MASK}


@pytest.mark.parametrize(
    "key", ["query", "path", "author", "count", "tokenizer_name_x"]
)
def test_ordinary_keys_keep_their_values(key):
    # "tokenizer..." contains "token": over-masking is accepted (fails closed).
    masked = mask({key: "value"})
    expected = MASK if "token" in key else "value"
    assert masked == {key: expected}


def test_nested_dicts_and_lists_are_masked_recursively(canary):
    data = {
        "outer": {"inner": [{"password": canary}, {"items": [{"api_key": canary}]}]},
        "list": [[{"secret": canary}], "plain"],
    }
    text = json.dumps(mask(data))
    assert canary not in text
    assert mask(data)["list"][1] == "plain"


def test_secretstr_is_masked(canary):
    assert mask({"anything": SecretStr(canary)}) == {"anything": MASK}
    assert mask([SecretStr(canary)]) == [MASK]


# ======================================================== value patterns


@pytest.mark.parametrize(
    "shape",
    [
        "Bearer {c}",
        "bearer {c}.abc",
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + "a" * 36,
        "gho_" + "B" * 24,
        "sk-" + "x" * 32,
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIB{c}\n-----END RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n{c} (unterminated)",
    ],
)
def test_token_shapes_in_values_are_masked(shape, canary):
    value = shape.format(c=canary)
    masked = mask({"note": f"before {value} after"})["note"]
    assert MASK in masked
    assert canary not in masked
    assert masked.startswith("before ")


def test_patterns_are_masked_in_keys_too(canary):
    masked = mask({f"Bearer {canary}": "x"})
    assert all(canary not in k for k in masked)


def test_plain_text_is_unchanged():
    assert mask({"q": "find files about bears"}) == {"q": "find files about bears"}


# ============================================================ truncation


@pytest.mark.parametrize(
    ("length", "expected"),
    [
        (MAX_CHARS - 1, MAX_CHARS - 1),
        (MAX_CHARS, MAX_CHARS),
        (MAX_CHARS + 1, MAX_CHARS),
        (10**6, MAX_CHARS),
    ],
)
def test_strings_are_bounded_at_1024_with_a_marker(length, expected):
    out = mask({"v": "x" * length})["v"]
    assert len(out) == expected
    assert out.endswith(TRUNCATED) == (length > MAX_CHARS)


def test_one_megabyte_argument_is_bounded():
    # NFR-017.
    big = {"blob": "y" * 1_000_000, "items": ["z" * 5000] * 10_000}
    out = json.dumps(mask(big))
    assert len(out) < 200_000


def test_containers_keep_at_most_100_entries():
    out = mask({"l": list(range(150)), "d": {str(i): i for i in range(150)}})
    assert len(out["l"]) == 101 and out["l"][-1] == TRUNCATED
    assert len(out["d"]) == 101 and out["d"][TRUNCATED] == 50


def test_nesting_is_capped_and_cycles_terminate():
    deep = current = {}
    for _ in range(20):
        current["n"] = {}
        current = current["n"]
    text = json.dumps(mask(deep), ensure_ascii=False)
    assert text.count("{") <= 9 and TRUNCATED in text
    cyclic = []
    cyclic.append(cyclic)
    assert TRUNCATED in json.dumps(mask(cyclic), ensure_ascii=False)


def test_mask_precedes_truncation(canary):
    # A secret straddling the limit is masked before the cut, so no prefix of
    # it survives.
    value = "x" * (MAX_CHARS - 20) + f" Bearer {canary}"
    out = mask({"v": value})["v"]
    assert canary[:10] not in out


def test_masking_runs_before_truncation_so_no_token_prefix_survives(canary):
    # Cut first, this token would keep only 10 characters after "ghp_", below
    # the pattern's minimum of 20, and that prefix would be stored unmasked.
    secret = uuid.uuid4().hex + "ZZZZ"  # GitHub-token alphabet: no hyphens
    keep = MAX_CHARS - len(TRUNCATED)
    value = "x" * (keep - len("ghp_") - 10 - 1) + " ghp_" + secret
    out = mask({"v": value})["v"]
    assert secret[:10] not in out
    assert MASK in out


def test_custom_limit():
    assert (
        mask({"v": "abcdefghijklmnopqrstuvwxyz"}, limit=20)["v"]
        == "abcdefgh" + TRUNCATED
    )


# =================================================== unicode and malformed


def test_unicode_is_kept_and_lone_surrogates_are_replaced():
    out = mask({"name": "é漢字🙂", "bad": "a\ud800b"})
    assert out["name"] == "é漢字🙂"
    assert "\ud800" not in out["bad"]
    json.dumps(out, ensure_ascii=False).encode("utf-8")  # encodable


@pytest.mark.parametrize(
    "bad",
    [
        {"x": object()},
        {"x": {1}},
        {"x": b"bytes"},
        {"x": float("inf")},
        {"x": float("nan")},
        {3: "k"},
        {"x": datetime.now()},
    ],
    ids=["object", "set", "bytes", "inf", "nan", "int-key", "datetime"],
)
def test_non_json_values_are_refused_never_repr(bad):
    with pytest.raises(ValueError) as info:
        mask(bad)
    assert "object at 0x" not in str(info.value)


def test_masking_never_mutates_caller_data(canary):
    data = {"password": canary, "list": [{"token": canary}], "t": (1, 2)}
    before = copy.deepcopy(data)
    mask(data)
    assert data == before


def test_tuples_become_lists_and_scalars_pass_through():
    assert mask({"t": (1, "a"), "n": None, "b": True, "f": 1.5, "i": -3}) == {
        "t": [1, "a"],
        "n": None,
        "b": True,
        "f": 1.5,
        "i": -3,
    }


# ======================================================== diagnostics D-29


def test_diagnostics_detail_has_only_the_d29_fields():
    d = Diagnostics("builtins.ValueError", "pkg.mod", "fn", 12, "tool")
    assert diagnostics_detail(d) == {
        "exception_type": "builtins.ValueError",
        "module": "pkg.mod",
        "function": "fn",
        "line": 12,
        "stage": "tool",
    }
    with pytest.raises(TypeError):
        diagnostics_detail({"exception_type": "x"})


def test_tool_exception_from_a_module_at_an_absolute_path_leaks_nothing(
    tmp_path, canary, caplog
):
    # AT-32 (audit part): message, frame-local value, traceback and absolute
    # path are absent from every audit row and log record.
    module_file = tmp_path / f"tool_{canary[-8:]}.py"
    module_file.write_text(
        "def tool(arg):\n"
        f"    local_secret = {canary!r}\n"
        f"    message = 'failed with ' + local_secret + ' at ' + {str(tmp_path)!r}\n"
        "    raise RuntimeError(message)\n"
    )
    spec = importlib.util.spec_from_file_location("abs_path_tool", module_file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    try:
        mod.tool("x")
    except RuntimeError as exc:
        diag = _diagnostics(exc, "tool")
    with AuditStore(tmp_path / "a.db") as store, caplog.at_level(logging.DEBUG):
        logger = AuditLogger(store, clock=lambda: T0)
        logger.record(
            ERROR,
            request_id="r",
            tool="tool",
            reason=TOOL_FAILED,
            detail=diagnostics_detail(diag),
        )
        rows = store.read()
        store.close()
        with pytest.raises(Exception):  # noqa: B017 - fallback path also checked
            logger.record(
                ERROR,
                request_id="r",
                tool="tool",
                reason=TOOL_FAILED,
                detail=diagnostics_detail(diag),
            )
    stored = json.dumps([r.detail for r in rows]) + repr(rows)
    logged = " ".join(r.getMessage() for r in caplog.records)
    for sink in (stored, logged):
        assert canary not in sink
        assert "failed with" not in sink
        assert "Traceback" not in sink
        assert str(tmp_path) not in sink
        assert os.sep + "tool_" not in sink
    detail = json.loads(rows[0].detail)
    assert detail == {
        "exception_type": "builtins.RuntimeError",
        "module": "abs_path_tool",
        "function": "tool",
        "line": 4,
        "stage": "tool",
    }
    assert (rows[0].request_id, rows[0].tool, rows[0].reason) == (
        "r",
        "tool",
        TOOL_FAILED,
    )


def test_no_secret_reaches_stored_serialization(tmp_path, canary):
    with AuditStore(tmp_path / "a.db") as store:
        logger = AuditLogger(store, clock=lambda: T0)
        logger.record(
            "REQUEST_RECEIVED",
            request_id="r",
            detail={
                "arguments": {
                    "password": canary,
                    "q": f"token is ghp_{canary[-20:]}x{'a' * 20}",
                },
                "auth_token": SecretStr(canary),
                "headers": [{"Authorization": f"Bearer {canary}"}],
            },
        )
        conn_rows = store._conn.execute("SELECT * FROM audit_events").fetchall()
    assert canary not in repr(conn_rows)
