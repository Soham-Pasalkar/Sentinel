from importlib.metadata import version

import sentinel


def test_package_imports_with_version():
    assert isinstance(sentinel.__version__, str)
    assert sentinel.__version__


def test_installed_metadata_matches_package_version():
    assert version("sentinel-ai") == sentinel.__version__


def test_public_api_is_intentionally_minimal():
    # C-12 (I-33): the client, the types its signatures need, and the
    # exceptions it raises. Nothing else.
    assert sorted(sentinel.__all__) == [
        "AuditEvent",
        "AuditUnavailableError",
        "ConfigurationError",
        "Decision",
        "Execution",
        "InvalidRequestError",
        "PipelineResult",
        "RegistrationError",
        "SecurityPolicy",
        "SentinelClient",
        "SentinelConfig",
        "SentinelError",
        "Severity",
        "ToolGrant",
        "__version__",
    ]
    for name in sentinel.__all__:
        assert hasattr(sentinel, name)
