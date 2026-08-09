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
