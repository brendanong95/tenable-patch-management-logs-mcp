"""Typed errors whose messages are safe to hand back to an MCP client."""

from __future__ import annotations

from typing import Any


class TpmLogError(Exception):
    """Base error carrying a message and remediation text for tool results."""

    kind = "tpm_log_error"
    default_remediation = "Check the server logs (stderr) for details."

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.remediation = remediation or self.default_remediation

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error": self.kind,
            "message": self.message,
            "remediation": self.remediation,
        }


class InputError(TpmLogError):
    """A tool argument is malformed or points at nothing."""

    kind = "invalid_input"
    default_remediation = "Correct the argument and call the tool again."


class SourceError(TpmLogError):
    """A log source is missing, unreadable, or cannot be registered."""

    kind = "source_error"
    default_remediation = (
        "Register logs with add_log_source (a folder, UNC path, single log file, .zip or "
        ".tar.gz), or set TPM_LOG_SOURCES. Run check_log_sources to see what is configured."
    )


class NoSourcesError(SourceError):
    """Nothing is configured to analyse yet."""

    kind = "no_sources"
