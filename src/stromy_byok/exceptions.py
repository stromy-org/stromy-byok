"""Exceptions raised by stromy_byok."""

from __future__ import annotations


class StromyByokError(Exception):
    """Base exception for stromy_byok."""


class DependencyError(StromyByokError):
    """An optional dependency is missing.

    Raised when an optional-extra feature is used but the required dependency
    isn't installed. The message should tell the caller exactly which extra to install.
    """

    def __init__(self, extra: str, package: str) -> None:
        super().__init__(
            f"Missing optional dependency '{package}'. Install with: "
            f"uv pip install 'stromy-byok[{extra}]'"
        )
        self.extra = extra
        self.package = package
