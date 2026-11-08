"""Policy engine tests (C-08): C1.5 truth table P1-P8, precedence pairs,
determinism; D-24a, D-24b, D-24c, D-06, D-15; SEC-001, SEC-019.

Paths are given in canonical form: policy does no path resolution (testing
§4). Proxy re-verification (C-10) and result mapping (C-11) are not tested.
"""

import builtins
import copy
import itertools
import os
import socket
import time
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

import sentinel
from sentinel import policy as policy_module
from sentinel.action import AuthorizedAction
from sentinel.exceptions import ConfigurationError
from sentinel.models import (
    ALLOWED,
    CAPABILITY_EXCEEDED,
    DESTRUCTIVE_TOOL,
    NON_POLICY_REASONS,
    RATE_LIMIT_EXCEEDED,
    RESTRICTED_PATH,
    UNAUTHORIZED_AGENT,
    UNAUTHORIZED_TOOL,
    CapabilityEnvelope,
    Decision,
    SecurityContext,
    SecurityDecision,
    SecurityFinding,
    SecurityRequest,
    Severity,
    ToolGrant,
    ToolSpec,
)
from sentinel.policy import PolicyEngine, SecurityPolicy

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=UTC)
WS = "/ws"


class PathArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class CopyArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    src: str
    dst: str


class QueryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: str


SPECS = {
    "read_file": ToolSpec(
        name="read_file", arg_schema=PathArgs, destructive=False, path_args=("path",)
    ),
    "delete_file": ToolSpec(
        name="delete_file", arg_schema=PathArgs, destructive=True, path_args=("path",)
    ),
    "copy": ToolSpec(
        name="copy", arg_schema=CopyArgs, destructive=False, path_args=("src", "dst")
    ),
    "search": ToolSpec(name="search", arg_schema=QueryArgs, destructive=False),
}

DEFAULT_ARGS = {
    "read_file": {"path": "/ws/a.txt"},
    "delete_file": {"path": "/ws/a.txt"},
    "copy": {"src": "/ws/a.txt", "dst": "/ws/b.txt"},
    "search": {"query": "q"},
}

DEFAULT_GRANTS = (
    ToolGrant(tool="read_file", allowed_path_prefixes=(WS,)),
    ToolGrant(tool="delete_file", allowed_path_prefixes=(WS,)),
)


def finding(code, severity):
    return SecurityFinding(code=code, severity=severity, evidence="masked")


class Case:
    """Consistent policy inputs for one request."""

    def __init__(
        self,
        tool="read_file",
        arguments=None,
        authorized=True,
        grants=DEFAULT_GRANTS,
        agent_id="agent-1",
        request_id="req-1",
        envelope=True,
    ):
        arguments = DEFAULT_ARGS[tool] if arguments is None else arguments
        self.action = AuthorizedAction(
            request_id=request_id, agent_id=agent_id, tool=tool, arguments=arguments
        )
        self.request = SecurityRequest(
            request_id=request_id,
            received_at=NOW,
            agent_id=agent_id,
            session_id="sess-1",
            tool=tool,
            arguments=self.action.arguments,
        )
        if authorized and envelope:
            env = CapabilityEnvelope(agent_id=agent_id, grants=tuple(grants))
        else:
            env = None
        self.context = SecurityContext(
            agent_id=agent_id, authorized=authorized, envelope=env
        )
        self.tool_spec = SPECS[tool]

    def evaluate(self, findings=(), policy=None, **overrides):
        engine = PolicyEngine(policy or SecurityPolicy(version="test-1"))
        inputs = {
            "request": self.request,
            "context": self.context,
            "findings": findings,
            "tool_spec": self.tool_spec,
            "action": self.action,
        }
        inputs.update(overrides)
        action = inputs.pop("action")
        return engine.evaluate(**inputs, action=action)


def outcome(decision):
    return (decision.decision, decision.reason)


DENY, ALLOW, APPROVE = Decision.DENY, Decision.ALLOW, Decision.REQUIRE_APPROVAL
HIGH_PI = finding("PROMPT_INJECTION", Severity.HIGH)


# ============================================== truth table (testing §4)


@pytest.mark.parametrize(
    ("row", "case", "findings", "expected"),
    [
        ("P1", {"authorized": False}, (), (DENY, UNAUTHORIZED_AGENT)),
        ("P2", {"tool": "search"}, (), (DENY, UNAUTHORIZED_TOOL)),
        ("P3", {"arguments": {"path": "/etc/passwd"}}, (), (DENY, RESTRICTED_PATH)),
        ("P4", {}, (HIGH_PI,), (DENY, "PROMPT_INJECTION")),
        ("P5", {}, (finding("SENSITIVE", Severity.MEDIUM),), (ALLOW, ALLOWED)),
        ("P6", {"tool": "delete_file"}, (), (APPROVE, DESTRUCTIVE_TOOL)),
        ("P8", {}, (), (ALLOW, ALLOWED)),
    ],
)
def test_truth_table(row, case, findings, expected):
    assert outcome(Case(**case).evaluate(findings)) == expected


def test_p7_destructive_without_approval_requirement_is_allowed():
    policy = SecurityPolicy(version="v", require_approval_for_destructive=False)
    decision = Case(tool="delete_file").evaluate(policy=policy)
    assert outcome(decision) == (ALLOW, ALLOWED)


def test_p5_records_findings_but_no_risk_score():
    decision = Case().evaluate((finding("SENSITIVE", Severity.MEDIUM),))
    assert decision.finding_codes == ("SENSITIVE",)
    assert decision.risk_score is None  # I-11: no approved formula


# ===================================================== precedence pairs


@pytest.mark.parametrize(
    ("case", "findings", "expected"),
    [
        ({"authorized": False, "tool": "search"}, (HIGH_PI,), UNAUTHORIZED_AGENT),
        (
            {"tool": "copy", "arguments": {"src": "/etc/x", "dst": "/etc/y"}},
            (),
            UNAUTHORIZED_TOOL,
        ),
        ({"arguments": {"path": "/etc/passwd"}}, (HIGH_PI,), RESTRICTED_PATH),
        ({"tool": "delete_file"}, (HIGH_PI,), "PROMPT_INJECTION"),
        ({"tool": "delete_file", "arguments": {"path": "/etc/x"}}, (), RESTRICTED_PATH),
    ],
    ids=[
        "unauthorized+ungranted+high",
        "ungranted+path",
        "path+high",
        "destructive+high",
        "destructive+path",
    ],
)
def test_precedence_pairs_return_the_earlier_row(case, findings, expected):
    decision = Case(**case).evaluate(findings)
    assert decision.decision is DENY
    assert decision.reason == expected


def test_two_high_findings_break_ties_by_smallest_code():
    findings = (finding("ZETA", Severity.HIGH), finding("ALPHA", Severity.HIGH))
    decision = Case().evaluate(findings)
    assert outcome(decision) == (DENY, "ALPHA")
    assert decision.finding_codes == ("ALPHA", "ZETA")


def test_critical_threshold_denies_with_the_critical_code():
    policy = SecurityPolicy(version="v", deny_at_severity=Severity.CRITICAL)
    findings = (
        finding("AAA_HIGH", Severity.HIGH),
        finding("ZZZ_CRIT", Severity.CRITICAL),
    )
    decision = Case().evaluate(findings, policy=policy)
    assert outcome(decision) == (DENY, "ZZZ_CRIT")


def test_high_below_a_critical_threshold_does_not_deny():
    policy = SecurityPolicy(version="v", deny_at_severity=Severity.CRITICAL)
    decision = Case().evaluate((HIGH_PI,), policy=policy)
    assert outcome(decision) == (ALLOW, ALLOWED)


# ============================================================== identity


def test_unauthorized_agent_is_denied_whatever_else_holds():
    decision = Case(authorized=False, tool="search").evaluate()
    assert outcome(decision) == (DENY, UNAUTHORIZED_AGENT)
    assert Case(authorized=False).context.envelope is None


def test_authorized_agent_with_no_envelope_has_no_grants():
    case = Case(envelope=False)
    assert case.context.authorized and case.context.envelope is None
    assert outcome(case.evaluate()) == (DENY, UNAUTHORIZED_TOOL)


def test_context_for_another_agent_is_refused_not_decided():
    case = Case()
    other = SecurityContext(agent_id="agent-2", authorized=True)
    with pytest.raises(ValueError):
        case.evaluate(context=other)


# ================================================== grants (D-24a, D-24b)


def test_explicit_grant_is_necessary_not_sufficient():
    # Granted, but the path is outside: a grant alone never means ALLOW.
    assert outcome(Case(arguments={"path": "/etc/passwd"}).evaluate()) == (
        DENY,
        RESTRICTED_PATH,
    )
    # Granted and destructive: approval, not ALLOW.
    assert Case(tool="delete_file").evaluate().decision is APPROVE


def test_missing_grant_is_denied_even_with_an_empty_envelope():
    case = Case(tool="search", grants=())
    assert outcome(case.evaluate()) == (DENY, UNAUTHORIZED_TOOL)


def test_registration_alone_grants_nothing():
    # Every tool in SPECS is "registered"; only explicit grants count.
    for tool in SPECS:
        decision = Case(tool=tool, grants=()).evaluate()
        assert outcome(decision) == (DENY, UNAUTHORIZED_TOOL)


@pytest.mark.parametrize("granted", ["Read_File", "read_file ", "read", "read_files"])
def test_grant_names_must_match_exactly(granted):
    case = Case(grants=(ToolGrant(tool=granted, allowed_path_prefixes=(WS,)),))
    assert outcome(case.evaluate()) == (DENY, UNAUTHORIZED_TOOL)


def test_grant_matching_is_case_sensitive_for_mixed_case_names():
    SPECS["ReadFile"] = ToolSpec(
        name="ReadFile", arg_schema=QueryArgs, destructive=False
    )
    DEFAULT_ARGS["ReadFile"] = {"query": "q"}
    try:
        for granted in ("readfile", "READFILE", "Readfile"):
            case = Case(tool="ReadFile", grants=(ToolGrant(tool=granted),))
            assert outcome(case.evaluate()) == (DENY, UNAUTHORIZED_TOOL)
        case = Case(tool="ReadFile", grants=(ToolGrant(tool="ReadFile"),))
        assert outcome(case.evaluate()) == (ALLOW, ALLOWED)
    finally:
        del SPECS["ReadFile"], DEFAULT_ARGS["ReadFile"]


def test_grant_for_another_tool_does_not_cover_this_one():
    case = Case(
        tool="search",
        grants=(ToolGrant(tool="read_file", allowed_path_prefixes=(WS,)),),
    )
    assert outcome(case.evaluate()) == (DENY, UNAUTHORIZED_TOOL)


def test_granted_non_path_tool_is_allowed():
    case = Case(tool="search", grants=(ToolGrant(tool="search"),))
    assert outcome(case.evaluate()) == (ALLOW, ALLOWED)


def test_missing_grant_never_allows_across_all_inputs():
    severities = [None, *Severity]
    for tool, severity, approval in itertools.product(SPECS, severities, (True, False)):
        findings = () if severity is None else (finding("F", severity),)
        policy = SecurityPolicy(version="v", require_approval_for_destructive=approval)
        decision = Case(tool=tool, grants=()).evaluate(findings, policy=policy)
        assert decision.decision is DENY


# ================================================================ paths


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/ws/a.txt", ALLOW),
        ("/ws", ALLOW),  # the prefix directory itself
        ("/ws/sub/deep/x", ALLOW),
        ("/etc/passwd", DENY),
        ("/ws-other/x", DENY),  # sibling-prefix confusion
        ("/wsx", DENY),
        ("/", DENY),
        ("/WS/a.txt", DENY),  # case differs: fails closed
    ],
)
def test_path_containment(path, expected):
    decision = Case(arguments={"path": path}).evaluate()
    assert decision.decision is expected
    if expected is DENY:
        assert decision.reason == RESTRICTED_PATH


def test_empty_prefix_list_denies_every_path():
    case = Case(grants=(ToolGrant(tool="read_file"),), arguments={"path": "/ws/a.txt"})
    assert outcome(case.evaluate()) == (DENY, RESTRICTED_PATH)
    case = Case(grants=(ToolGrant(tool="read_file"),), arguments={"path": "/"})
    assert outcome(case.evaluate()) == (DENY, RESTRICTED_PATH)


def test_explicit_root_prefix_allows_every_absolute_path():
    grants = (ToolGrant(tool="read_file", allowed_path_prefixes=("/",)),)
    for path in ("/", "/etc/passwd", "/ws/a.txt"):
        assert (
            Case(grants=grants, arguments={"path": path}).evaluate().decision is ALLOW
        )


def test_multiple_prefixes():
    grants = (ToolGrant(tool="read_file", allowed_path_prefixes=("/ws", "/data")),)
    assert (
        Case(grants=grants, arguments={"path": "/data/x"}).evaluate().decision is ALLOW
    )
    assert Case(grants=grants, arguments={"path": "/ws/x"}).evaluate().decision is ALLOW
    assert Case(grants=grants, arguments={"path": "/srv/x"}).evaluate().decision is DENY


@pytest.mark.parametrize(
    ("src", "dst", "expected"),
    [
        ("/ws/a", "/ws/b", ALLOW),
        ("/ws/a", "/etc/b", DENY),
        ("/etc/a", "/ws/b", DENY),
        ("/etc/a", "/etc/b", DENY),
    ],
)
def test_every_path_argument_must_be_contained(src, dst, expected):
    grants = (ToolGrant(tool="copy", allowed_path_prefixes=(WS,)),)
    decision = Case(
        tool="copy", grants=grants, arguments={"src": src, "dst": dst}
    ).evaluate()
    assert decision.decision is expected


def test_prefixes_on_a_non_path_grant_are_not_path_permission():
    # A constructed grant with prefixes on a non-path tool: nothing to check,
    # and the prefixes do not make the tool a path tool.
    grants = (ToolGrant(tool="search", allowed_path_prefixes=("/",)),)
    case = Case(tool="search", grants=grants, arguments={"query": "/etc/passwd"})
    assert outcome(case.evaluate()) == (ALLOW, ALLOWED)


def test_missing_path_argument_is_refused_not_decided():
    # The gateway guarantees path arguments; their absence means the inputs do
    # not belong together (I-10).
    case = Case(tool="read_file", arguments={"other": "/ws/a"})
    with pytest.raises(ValueError):
        case.evaluate()


def test_path_policy_uses_the_c04_containment_function(monkeypatch):
    calls = []
    real = policy_module.is_contained

    def spy(path, prefixes):
        calls.append((path, tuple(prefixes)))
        return real(path, prefixes)

    monkeypatch.setattr(policy_module, "is_contained", spy)
    Case(
        tool="copy", grants=(ToolGrant(tool="copy", allowed_path_prefixes=(WS,)),)
    ).evaluate()
    assert calls == [("/ws/a.txt", (WS,)), ("/ws/b.txt", (WS,))]


# ======================================================= destructive (D-06)


def test_destructive_tool_requires_approval_by_default():
    assert SecurityPolicy(version="v").require_approval_for_destructive is True
    decision = Case(tool="delete_file").evaluate()
    assert outcome(decision) == (APPROVE, DESTRUCTIVE_TOOL)


def test_non_destructive_tool_is_allowed():
    assert outcome(Case().evaluate()) == (ALLOW, ALLOWED)


def test_require_approval_is_never_allow():
    decision = Case(tool="delete_file").evaluate()
    assert decision.decision is not ALLOW
    assert decision.decision.value == "require_approval"


def test_approval_is_not_reached_when_a_deny_row_matches():
    for case, findings in [
        ({"tool": "delete_file", "authorized": False}, ()),
        ({"tool": "delete_file", "grants": ()}, ()),
        ({"tool": "delete_file", "arguments": {"path": "/etc"}}, ()),
        ({"tool": "delete_file"}, (finding("X", Severity.CRITICAL),)),
    ]:
        assert Case(**case).evaluate(findings).decision is DENY


# ============================================================== findings


def test_empty_findings_still_apply_every_other_row():
    assert Case(authorized=False).evaluate(()).decision is DENY
    assert Case(tool="search").evaluate([]).decision is DENY
    assert Case(arguments={"path": "/etc"}).evaluate(iter(())).decision is DENY
    assert Case(tool="delete_file").evaluate(()).decision is APPROVE


@pytest.mark.parametrize("severity", [Severity.LOW, Severity.MEDIUM])
def test_low_and_medium_findings_do_not_deny(severity):
    assert Case().evaluate((finding("F", severity),)).decision is ALLOW


@pytest.mark.parametrize("severity", [Severity.HIGH, Severity.CRITICAL])
def test_high_and_critical_findings_deny_by_default(severity):
    decision = Case().evaluate((finding("CODE", severity),))
    assert outcome(decision) == (DENY, "CODE")


def test_highest_severity_wins_over_smaller_code():
    findings = (
        finding("A_HIGH", Severity.HIGH),
        finding("Z_CRITICAL", Severity.CRITICAL),
    )
    assert Case().evaluate(findings).reason == "Z_CRITICAL"


def test_finding_order_never_changes_the_decision():
    findings = [
        finding("B", Severity.HIGH),
        finding("A", Severity.HIGH),
        finding("C", Severity.CRITICAL),
        finding("D", Severity.LOW),
        finding("A", Severity.MEDIUM),
    ]
    results = {
        (d.decision, d.reason, d.finding_codes)
        for d in (Case().evaluate(p) for p in itertools.permutations(findings))
    }
    assert results == {(DENY, "C", ("C", "A", "B", "A", "D"))}


def test_finding_codes_are_recorded_on_every_decision():
    findings = (finding("LOW1", Severity.LOW),)
    assert Case(authorized=False).evaluate(findings).finding_codes == ("LOW1",)
    assert Case(tool="delete_file").evaluate(findings).finding_codes == ("LOW1",)


def test_findings_are_not_modified():
    findings = [finding("B", Severity.HIGH), finding("A", Severity.LOW)]
    before = copy.deepcopy(findings)
    Case().evaluate(findings)
    assert findings == before


@pytest.mark.parametrize(
    "bad", ["PROMPT_INJECTION", None, [{"code": "X", "severity": 3}], [object()]]
)
def test_malformed_findings_are_refused(bad):
    with pytest.raises(TypeError):
        Case().evaluate(bad)


# ================================================ binding and consistency


def test_decision_embeds_the_exact_action():
    case = Case()
    decision = case.evaluate()
    assert isinstance(decision, SecurityDecision)
    assert decision.action is case.action
    assert decision.request_id == case.action.request_id == "req-1"
    assert decision.action.digest == case.action.digest
    assert decision.policy_version == "test-1"


@pytest.mark.parametrize(
    "decision_case", [{}, {"authorized": False}, {"tool": "delete_file"}]
)
def test_every_decision_binds_the_action(decision_case):
    case = Case(**decision_case)
    assert case.evaluate().action is case.action


def test_tool_spec_for_another_tool_is_refused():
    case = Case()
    with pytest.raises(ValueError):
        case.evaluate(tool_spec=SPECS["delete_file"])
    # Same name, different metadata cannot be detected by name alone; the
    # pipeline passes the registry's spec (D-15), and the spec is what decides.


def test_action_for_another_request_is_refused():
    case = Case()
    for other in (
        Case(request_id="req-2").action,
        Case(agent_id="agent-2").action,
        Case(arguments={"path": "/ws/other.txt"}).action,
        Case(tool="delete_file").action,
    ):
        with pytest.raises(ValueError):
            case.evaluate(action=other)


def test_request_arguments_must_equal_the_action_arguments_exactly():
    case = Case(tool="search", grants=(ToolGrant(tool="search"),))
    action = AuthorizedAction(
        request_id="req-1", agent_id="agent-1", tool="search", arguments={"n": 1}
    )
    # {"n": True} and {"n": 1.0} compare equal to {"n": 1} in Python; the
    # digest comparison still tells them apart.
    assert {"n": True} == {"n": 1} == {"n": 1.0}
    for other in ({"n": True}, {"n": 1.0}, {"n": 2}, {"query": "q"}):
        request = case.request.model_copy(update={"arguments": other})
        with pytest.raises(ValueError):
            case.evaluate(request=request, action=action)
    same = case.request.model_copy(update={"arguments": {"n": 1}})
    assert case.evaluate(request=same, action=action).action is action


@pytest.mark.parametrize("field", ["request", "context", "tool_spec", "action"])
def test_wrong_input_types_are_refused(field):
    with pytest.raises(TypeError):
        Case().evaluate(**{field: object()})


def test_inconsistent_inputs_raise_instead_of_deciding():
    # I-10: never a DENY for an orchestration defect.
    case = Case()
    for overrides in (
        {"tool_spec": SPECS["search"]},
        {"context": SecurityContext(agent_id="other", authorized=False)},
        {"action": Case(request_id="x").action},
    ):
        with pytest.raises((TypeError, ValueError)):
            case.evaluate(**overrides)


# ============================================================ determinism


def test_one_thousand_evaluations_give_one_result():
    cases = [
        (Case(), ()),
        (Case(authorized=False), ()),
        (Case(tool="search"), ()),
        (Case(arguments={"path": "/etc"}), ()),
        (Case(), (HIGH_PI, finding("A", Severity.HIGH))),
        (Case(tool="delete_file"), ()),
    ]
    for case, findings in cases:
        results = {
            (d.decision, d.reason, d.finding_codes, d.policy_version, d.action.digest)
            for d in (case.evaluate(findings) for _ in range(1000))
        }
        assert len(results) == 1


def test_evaluation_needs_no_files_sockets_clock_or_environment(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("policy touched the outside world")

    case = Case(
        tool="copy", grants=(ToolGrant(tool="copy", allowed_path_prefixes=(WS,)),)
    )
    expected = case.evaluate()
    for target, name in [
        (builtins, "open"),
        (socket, "socket"),
        (time, "time"),
        (time, "monotonic"),
        (os, "stat"),
        (os, "lstat"),
        (os.path, "realpath"),
        (os, "getenv"),
    ]:
        monkeypatch.setattr(target, name, boom)
    monkeypatch.setattr(os, "environ", {})
    assert case.evaluate() == expected


def test_policy_does_not_read_the_registry_or_detect():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(policy_module))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {
        a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names
    }
    imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "sentinel.registry" not in imports
    assert "sentinel.identity" not in imports
    for forbidden in (
        "ToolRegistry",
        "lookup",
        "canonicalise",
        "reverify",
        "logging",
        "random",
    ):
        assert forbidden not in names


def test_inputs_are_not_mutated():
    case = Case()
    before = (
        case.request.model_dump(),
        case.context.model_dump(),
        case.action.arguments,
        case.action.digest,
    )
    case.evaluate((HIGH_PI,))
    after = (
        case.request.model_dump(),
        case.context.model_dump(),
        case.action.arguments,
        case.action.digest,
    )
    assert before == after


# ===================================================== security invariants


def test_decision_values_are_only_the_three_policy_values():
    seen = set()
    for kwargs, findings in [
        ({}, ()),
        ({"authorized": False}, ()),
        ({"tool": "delete_file"}, ()),
        ({}, (HIGH_PI,)),
    ]:
        seen.add(Case(**kwargs).evaluate(findings).decision.value)
    assert seen <= {"allow", "deny", "require_approval"}
    assert "error" not in {d.value for d in Decision}


def test_every_reason_is_an_approved_policy_reason():
    rule_reasons = {UNAUTHORIZED_AGENT, UNAUTHORIZED_TOOL, RESTRICTED_PATH}
    finding_codes = {"PROMPT_INJECTION", "A"}
    for kwargs, findings in [
        ({"authorized": False}, ()),
        ({"tool": "search"}, ()),
        ({"arguments": {"path": "/etc"}}, ()),
        ({}, (HIGH_PI,)),
        ({}, (finding("A", Severity.CRITICAL),)),
    ]:
        decision = Case(**kwargs).evaluate(findings)
        assert decision.decision is DENY
        assert decision.reason in rule_reasons | finding_codes
        assert decision.reason not in NON_POLICY_REASONS
    assert Case(tool="delete_file").evaluate().reason == DESTRUCTIVE_TOOL
    assert Case().evaluate().reason == ALLOWED


def test_unreachable_rows_are_not_produced():
    # Row 3's CAPABILITY_EXCEEDED and row 5's RATE_LIMIT_EXCEEDED have no
    # source in v1 (I-11; rate-limited grants are refused, I-3).
    source = open(policy_module.__file__).read()  # noqa: SIM115
    assert "CAPABILITY_EXCEEDED" not in source.split('"""', 2)[2]
    assert "RATE_LIMIT_EXCEEDED" not in source.split('"""', 2)[2]
    assert {CAPABILITY_EXCEEDED, RATE_LIMIT_EXCEEDED}  # constants still exist


# ================================================================ policy


@pytest.mark.parametrize(
    "fields",
    [
        {},
        {"version": ""},
        {"version": 1},
        {"version": "v", "deny_at_severity": 3},
        {"version": "v", "deny_at_severity": "HIGH"},
        {"version": "v", "require_approval_for_destructive": 1},
        {"version": "v", "require_credentials": True},  # identity's (I-6)
        {"version": "v", "rules": []},
    ],
)
def test_invalid_policy_is_a_configuration_error(fields):
    with pytest.raises(ConfigurationError) as info:
        SecurityPolicy(**fields)
    assert info.value.__context__ is None or info.value.__suppress_context__


def test_policy_defaults_and_immutability():
    policy = SecurityPolicy(version="v")
    assert policy.deny_at_severity is Severity.HIGH
    assert policy.require_approval_for_destructive is True
    with pytest.raises(ValidationError):
        policy.version = "other"


def test_engine_requires_a_security_policy():
    for bad in (None, {"version": "v"}, "v"):
        with pytest.raises(ConfigurationError):
            PolicyEngine(bad)
    assert PolicyEngine(SecurityPolicy(version="v")).policy.version == "v"


def test_policy_engine_is_internal():
    assert "PolicyEngine" not in sentinel.__all__
    assert not hasattr(sentinel, "PolicyEngine")
