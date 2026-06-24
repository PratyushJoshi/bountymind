"""
utils/exceptions.py
-------------------
Custom exception hierarchy for ReconFramework.
All framework-specific exceptions inherit from ReconFrameworkError so callers
can catch the whole family with a single except clause when needed.
"""


class ReconFrameworkError(Exception):
    """Base exception for all ReconFramework errors."""


class ConfigurationError(ReconFrameworkError):
    """Raised when the configuration is missing, malformed, or invalid."""


class ToolNotFoundError(ReconFrameworkError):
    """Raised when a required external tool binary cannot be located."""

    def __init__(self, tool_name: str, install_hint: str = "") -> None:
        self.tool_name = tool_name
        self.install_hint = install_hint
        msg = f"Tool '{tool_name}' not found on PATH or configured path."
        if install_hint:
            msg += f" Install hint: {install_hint}"
        super().__init__(msg)


class ToolExecutionError(ReconFrameworkError):
    """Raised when an external tool exits with a non-zero return code."""

    def __init__(
        self,
        tool_name: str,
        return_code: int,
        stderr: str = "",
        cmd: str = "",
    ) -> None:
        self.tool_name = tool_name
        self.return_code = return_code
        self.stderr = stderr
        self.cmd = cmd
        msg = (
            f"Tool '{tool_name}' exited with code {return_code}."
            + (f" CMD: {cmd}" if cmd else "")
            + (f" STDERR: {stderr[:200]}" if stderr else "")
        )
        super().__init__(msg)


class ToolTimeoutError(ReconFrameworkError):
    """Raised when an external tool execution exceeds its allowed timeout."""

    def __init__(self, tool_name: str, timeout: int) -> None:
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(
            f"Tool '{tool_name}' timed out after {timeout} seconds."
        )


class TargetValidationError(ReconFrameworkError):
    """Raised when a supplied target domain/URL fails validation."""


class ReportGenerationError(ReconFrameworkError):
    """Raised when report generation fails."""


class UpdaterError(ReconFrameworkError):
    """Raised by the ToolUpdater when an update operation fails."""


class APIKeyMissingWarning(UserWarning):
    """Warning (not exception) emitted when an optional API key is absent."""
