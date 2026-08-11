"""Public-API contract — guards what consumers can import."""

import pytest

import stromy_byok


@pytest.mark.contract
def test_all_is_a_list() -> None:
    assert isinstance(stromy_byok.__all__, list)


@pytest.mark.contract
def test_all_symbols_are_exported() -> None:
    for symbol in stromy_byok.__all__:
        assert hasattr(stromy_byok, symbol), f"__all__ lists {symbol!r} but it's not exported"


@pytest.mark.unit
def test_version_matches_installed_package_metadata() -> None:
    """__version__ is derived, not hand-maintained.

    A literal here desynced on the very first bump: the consumer pinned
    v0.2.0, uv resolved the right commit, and the package still reported
    0.1.0 — so the one signal an operator would check to confirm a rollout
    lied while everything underneath was correct.
    """
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text())["project"]["version"]

    assert stromy_byok.__version__ == declared
