"""Expected, user-facing failures. The API maps each to one HTTP status."""

from __future__ import annotations


class PRRiskError(Exception):
    """Base class."""


class DiffParseError(PRRiskError):
    """The diff is malformed or truncated."""


class SourceError(PRRiskError):
    """A file or revision could not be read (bad ref, missing repo, GitHub error)."""


class InputTooLargeError(PRRiskError):
    """The diff exceeds the configured size limit."""
