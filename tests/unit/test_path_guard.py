"""Path guard tests: testing_strategy.md §5 (F1-F20) at function level (C-04).

Cases that need later components are covered here only at function level:
F7/F8/F9 as ``InvalidRequestError`` (the gateway maps it to ``decision=None``,
``INVALID_REQUEST`` in C-06); F14/F16 through ``reverify`` (the proxy wiring
and spy counts are C-10); F19 as "contains nothing" plus the registration
warning (the policy DENY ``RESTRICTED_PATH`` is C-08).
"""

import logging
import os
import types

import pytest

import sentinel
from sentinel import paths
from sentinel.exceptions import (
    ActionDenied,
    ConfigurationError,
    InvalidRequestError,
    SentinelError,
)
from sentinel.paths import (
    canonicalise,
    is_contained,
    register_prefixes,
    require_path_support,
    reverify,
)

CANARY = "CANARY-9c1e-not-in-errors-or-logs"


@pytest.fixture
def fs(tmp_path):
    """ws/ (the allowed prefix), ws2/ (sibling), outside/ (forbidden).

    ``root`` is deliberately the *unresolved* ``tmp_path``: on macOS it lies
    under ``/var`` -> ``/private/var``, which exercises canonicalisation of both
    the prefix and the request.
    """
    ws = tmp_path / "ws"
    (ws / "sub" / "deep").mkdir(parents=True)
    (ws / "a.txt").write_text("inside")
    (ws / "sub" / "data.txt").write_text("inside")
    (ws / "sub" / "deep" / "x.txt").write_text("inside")
    (tmp_path / "ws2").mkdir()
    (tmp_path / "ws2" / "x").write_text("sibling")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    (outside / "data.txt").write_text("outside")
    prefixes = register_prefixes([str(ws)])
    return {
        "root": tmp_path,
        "ws": ws,
        "ws_real": os.path.realpath(ws),
        "outside": outside,
        "prefixes": prefixes,
    }


def allowed(path, prefixes):
    return is_contained(canonicalise(str(path)), prefixes)


# --------------------------------------------------------------- matrix F1-F20


def test_f1_absolute_path_inside_is_allowed_and_resolved(fs):
    canonical = canonicalise(str(fs["ws"] / "a.txt"))
    assert canonical == os.path.join(fs["ws_real"], "a.txt")
    assert os.path.isabs(canonical)
    assert is_contained(canonical, fs["prefixes"])


def test_f2_parent_traversal_out_of_the_prefix_is_denied(fs):
    path = str(fs["ws"]) + "/../outside/secret.txt"
    canonical = canonicalise(path)
    assert ".." not in canonical.split("/")
    assert not is_contained(canonical, fs["prefixes"])


def test_f3_sibling_prefix_is_not_contained(fs):
    assert not allowed(fs["root"] / "ws2" / "x", fs["prefixes"])
    # Pure form of the same confusion: string prefix would say "contained".
    assert not is_contained("/safe-other/x", ("/safe",))
    assert not is_contained("/safe-other", ("/safe",))
    assert is_contained("/safe/other", ("/safe",))


def test_f4_file_symlink_to_outside_is_denied(fs):
    link = fs["ws"] / "link"
    link.symlink_to(fs["outside"] / "secret.txt")
    assert not allowed(link, fs["prefixes"])


def test_f5_directory_symlink_to_outside_is_denied(fs):
    dirlink = fs["ws"] / "dirlink"
    dirlink.symlink_to(fs["outside"], target_is_directory=True)
    assert not allowed(dirlink / "secret.txt", fs["prefixes"])
    assert not allowed(dirlink, fs["prefixes"])


def test_f6_symlink_staying_inside_is_allowed_with_resolved_target(fs):
    inner = fs["ws"] / "inner"
    inner.symlink_to(fs["ws"] / "a.txt")
    canonical = canonicalise(str(inner))
    assert canonical == os.path.join(fs["ws_real"], "a.txt")
    assert is_contained(canonical, fs["prefixes"])


@pytest.mark.parametrize("path", ["a.txt", "./a.txt", "ws/a.txt", "../x", "."])
def test_f7_relative_paths_are_refused_not_resolved(path, fs, monkeypatch):
    # Even with the prefix as the working directory, nothing is resolved.
    monkeypatch.chdir(fs["ws"])
    with pytest.raises(InvalidRequestError):
        canonicalise(path)


@pytest.mark.parametrize("path", ["", "\x00", "/ws/a\x00.txt"])
def test_f8_empty_and_nul_paths_are_refused(path):
    with pytest.raises(InvalidRequestError):
        canonicalise(path)


@pytest.mark.parametrize("path", ["~/.ssh/id_rsa", "~", "~root/.ssh/id_rsa"])
def test_f9_tilde_is_refused_and_never_expanded(path, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    with pytest.raises(InvalidRequestError):
        canonicalise(path)


def test_f10_nonexistent_leaf_inside_is_allowed(fs):
    canonical = canonicalise(str(fs["ws"] / "new.txt"))
    assert not os.path.exists(canonical)
    assert canonical == os.path.join(fs["ws_real"], "new.txt")
    assert is_contained(canonical, fs["prefixes"])


def test_f11_nonexistent_leaf_under_symlinked_parent_to_outside_is_denied(fs):
    outlink = fs["ws"] / "outlink"
    outlink.symlink_to(fs["outside"], target_is_directory=True)
    assert not allowed(outlink / "new.txt", fs["prefixes"])


def test_f12_symlinked_prefix_is_canonicalised_on_both_sides(fs):
    alias = fs["root"] / "alias"
    alias.symlink_to(fs["ws"], target_is_directory=True)
    prefixes = register_prefixes([str(alias)])
    assert prefixes == (fs["ws_real"],)
    assert allowed(alias / "a.txt", prefixes)
    assert allowed(fs["ws"] / "a.txt", prefixes)
    assert not allowed(fs["outside"] / "secret.txt", prefixes)


def test_f13_prefix_directory_itself_is_contained(fs):
    assert allowed(fs["ws"], fs["prefixes"])
    assert allowed(str(fs["ws"]) + "/", fs["prefixes"])


def test_f14_forged_escaping_path_fails_reverification(fs):
    # Function level: an escaping path never passes the proxy re-check, even
    # if policy was bypassed. Proxy wiring and spy counts are C-10.
    escaping = canonicalise(str(fs["outside"] / "secret.txt"))
    assert not reverify(escaping, fs["prefixes"])
    assert not reverify(str(fs["ws"]) + "/../outside/secret.txt", fs["prefixes"])
    assert not reverify("relative/path", fs["prefixes"])


@pytest.mark.xfail(
    strict=True,
    reason="T-07 residual risk: a symlink swap after reverify and before the "
    "tool's open is not detected (C2 limitation)",
)
def test_f15_symlink_swap_after_reverify_is_not_detected(fs):
    canonical = canonicalise(str(fs["ws"] / "sub" / "data.txt"))
    assert reverify(canonical, fs["prefixes"])
    # The swap happens after the last check, before the tool opens the file.
    (fs["ws"] / "sub").rename(fs["ws"] / "sub_old")
    (fs["ws"] / "sub").symlink_to(fs["outside"], target_is_directory=True)
    with open(canonical) as handle:
        assert handle.read() == "inside"


def test_f16_path_changed_between_gateway_and_proxy_is_refused(fs):
    canonical = canonicalise(str(fs["ws"] / "sub" / "data.txt"))
    assert is_contained(canonical, fs["prefixes"])  # policy would ALLOW
    assert reverify(canonical, fs["prefixes"])
    (fs["ws"] / "sub").rename(fs["ws"] / "sub_old")
    (fs["ws"] / "sub").symlink_to(fs["outside"], target_is_directory=True)
    assert not reverify(canonical, fs["prefixes"])


def test_f17_limitation_hardlink_not_detected(fs):
    # Documented limitation (C2): a hard link inside a prefix to a file outside
    # is indistinguishable by path. A future fix must update this deliberately.
    hl = fs["ws"] / "hl"
    try:
        os.link(fs["outside"] / "secret.txt", hl)
    except OSError as exc:  # pragma: no cover - filesystem without hard links
        pytest.skip(f"hard links unsupported here: {type(exc).__name__}")
    assert allowed(hl, fs["prefixes"])
    assert hl.read_text() == "secret"


def test_f18_missing_or_file_prefix_is_a_configuration_error(fs):
    with pytest.raises(ConfigurationError):
        register_prefixes([str(fs["root"] / "does-not-exist")])
    with pytest.raises(ConfigurationError):
        register_prefixes([str(fs["ws"] / "a.txt")])
    with pytest.raises(ConfigurationError):
        register_prefixes([str(fs["ws"]), str(fs["root"] / "missing")])


@pytest.mark.parametrize("prefixes", [[], (), None])
def test_f19_empty_or_missing_prefixes_deny_everything_and_warn(prefixes, fs, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.paths"):
        result = register_prefixes(prefixes)
    assert result == ()
    assert any("every call will be denied" in r.message for r in caplog.records)
    assert not allowed(fs["ws"] / "a.txt", result)
    assert not allowed(fs["ws"], result)
    assert not is_contained("/", result)
    assert not reverify(canonicalise(str(fs["ws"] / "a.txt")), result)


def test_f20_path_tools_are_refused_on_windows(fs, monkeypatch):
    # Simulate Windows for the path guard only: patching the global os.name
    # would also switch pathlib (and pytest) to Windows semantics.
    fake_os = types.SimpleNamespace(name="nt", path=os.path, fsencode=os.fsencode)
    monkeypatch.setattr(paths, "os", fake_os)
    with pytest.raises(ConfigurationError):
        require_path_support()
    with pytest.raises(ConfigurationError):
        register_prefixes([str(fs["ws"])])
    with pytest.raises(ConfigurationError):
        register_prefixes([])


# ------------------------------------------------------------ further C2 rules


def test_posix_platforms_are_supported():
    if os.name != "posix":  # pragma: no cover - CI runs Linux and macOS
        pytest.skip("POSIX-only check")
    require_path_support()


def test_explicit_root_prefix_is_the_only_unrestricted_grant(fs, caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.paths"):
        prefixes = register_prefixes(["/"])
    assert prefixes == ("/",)
    assert any("unrestricted" in r.message for r in caplog.records)
    assert allowed(fs["outside"] / "secret.txt", prefixes)
    assert allowed("/", prefixes)
    with pytest.raises(InvalidRequestError):
        canonicalise("relative.txt")


def test_nested_paths_inside_are_allowed(fs):
    assert allowed(fs["ws"] / "sub" / "deep" / "x.txt", fs["prefixes"])
    assert allowed(fs["ws"] / "sub" / ".." / "a.txt", fs["prefixes"])


def test_traversal_that_returns_inside_is_allowed(fs):
    path = str(fs["ws"]) + "/../ws/a.txt"
    assert allowed(path, fs["prefixes"])


def test_several_prefixes_and_duplicates(fs):
    prefixes = register_prefixes([str(fs["ws"]), fs["ws_real"], str(fs["outside"])])
    assert prefixes == (fs["ws_real"], os.path.realpath(fs["outside"]))
    assert allowed(fs["outside"] / "secret.txt", prefixes)
    assert not allowed(fs["root"] / "ws2" / "x", prefixes)


@pytest.mark.parametrize(
    "bad",
    [
        "relative",
        "",
        "~",
        "/with\x00nul",
        b"/bytes",
        None,
        123,
    ],
)
def test_invalid_prefix_values_are_configuration_errors(bad):
    with pytest.raises(ConfigurationError):
        register_prefixes([bad])


def test_a_single_string_is_not_accepted_as_a_prefix_collection(fs):
    # Iterating "/" character by character would silently register the root
    # prefix, i.e. unrestricted access; iterating "/ws" would try "/", "w", "s".
    with pytest.raises(ConfigurationError):
        register_prefixes("/")
    with pytest.raises(ConfigurationError):
        register_prefixes(str(fs["ws"]))
    with pytest.raises(ConfigurationError):
        register_prefixes(b"/")


@pytest.mark.parametrize(
    "value", [None, 1, b"/ws/a.txt", ["/ws"], "/ws/\ud800"], ids=repr
)
def test_non_string_or_unencodable_request_paths_are_refused(value):
    with pytest.raises(InvalidRequestError):
        canonicalise(value)


def test_str_subclass_request_path_is_refused():
    class Sneaky(str):
        pass

    with pytest.raises(InvalidRequestError):
        canonicalise(Sneaky("/ws/a.txt"))


def test_containment_is_pure_and_fails_closed_on_non_canonical_input():
    prefixes = ("/ws",)
    assert is_contained("/ws", prefixes)
    assert is_contained("/ws/a/b", prefixes)
    assert not is_contained("/ws/../etc/passwd", prefixes)
    assert not is_contained("ws/a", prefixes)
    assert not is_contained("", prefixes)
    assert not is_contained(None, prefixes)
    assert not is_contained("/ws/a", ())
    assert not is_contained("/ws/a", ("", "ws", None))
    assert is_contained("/ws/a", iter(["/other", "/ws"]))


def test_containment_does_no_filesystem_access(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("filesystem accessed")

    monkeypatch.setattr(os, "stat", boom)
    monkeypatch.setattr(os, "lstat", boom)
    assert is_contained("/ws/a", ("/ws",))
    assert not is_contained("/other", ("/ws",))


def test_case_mismatch_fails_closed():
    # Documented limitation on case-insensitive filesystems: denied, not allowed.
    assert not is_contained("/WS/a.txt", ("/ws",))


def test_reverify_accepts_an_unchanged_contained_path(fs):
    canonical = canonicalise(str(fs["ws"] / "sub" / "data.txt"))
    assert reverify(canonical, fs["prefixes"])
    assert reverify(canonicalise(str(fs["ws"] / "new.txt")), fs["prefixes"])


def test_reverify_refuses_a_path_that_newly_resolves_elsewhere(fs):
    # Non-canonical input (a live symlink) is refused even when contained.
    inner = fs["ws"] / "inner"
    inner.symlink_to(fs["ws"] / "a.txt")
    assert not reverify(str(inner), fs["prefixes"])


# ------------------------------------------------------ errors and visibility


def test_errors_and_logs_never_contain_path_values(tmp_path, caplog):
    secret_dir = tmp_path / CANARY
    secret_dir.mkdir()
    errors = []
    with caplog.at_level(logging.DEBUG, logger="sentinel.paths"):
        for bad in [str(secret_dir / "missing"), str(secret_dir / "f")]:
            if bad.endswith("f"):
                (secret_dir / "f").write_text("x")
            with pytest.raises(ConfigurationError) as info:
                register_prefixes([bad])
            errors.append(info.value)
        for bad in [CANARY, f"/{CANARY}\x00", f"~/{CANARY}"]:
            with pytest.raises(InvalidRequestError) as info:
                canonicalise(bad)
            errors.append(info.value)
        register_prefixes([])
        register_prefixes(["/"])
    for error in errors:
        assert CANARY not in str(error)
        assert CANARY not in repr(error)
        # The OSError (whose text names the path) must not be chained.
        assert error.__cause__ is None
        assert error.__context__ is None or error.__suppress_context__
    for record in caplog.records:
        assert CANARY not in record.getMessage()


def test_refusals_are_sentinel_errors_not_policy_denials():
    for cls in (InvalidRequestError, ConfigurationError):
        assert issubclass(cls, SentinelError)
        assert not issubclass(cls, ActionDenied)


def test_path_guard_is_internal():
    assert sentinel.__all__ == ["__version__"]
    assert not hasattr(sentinel, "canonicalise")
