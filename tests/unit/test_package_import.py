from importlib.metadata import version

import sentinel


def test_package_imports_with_version():
    assert isinstance(sentinel.__version__, str)
    assert sentinel.__version__


def test_installed_metadata_matches_package_version():
    assert version("sentinel-ai") == sentinel.__version__


def test_public_api_is_intentionally_minimal():
    assert sentinel.__all__ == ["__version__"]
