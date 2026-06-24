"""
utils/runner.py
---------------
CommandRunner: safe, structured wrapper for all subprocess invocations.

Design principles:
- Never print raw tool output to console.
- Always capture stdout/stderr.
- Enforce timeouts with graceful kill.
- Log every invocation at DEBUG level with full context.
- Return a structured ToolResult so callers can parse output without
  worrying about exception-vs-return-value inconsistency.
- Supports optional raw output persistence to disk.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Union

from utils.exceptions import ToolNotFoundError, ToolTimeoutError
from utils.logger import get_logger, log_tool_invocation
from utils.models import ToolResult

log = get_logger("runner")

# Bytes limit on captured stdout to avoid memory issues with large outputs
MAX_OUTPUT_BYTES = 50 * 1024 * 1024  # 50 MB


class CommandRunner:
    """
    Runs external tools as subprocesses with consistent error handling.

    Usage::
        runner = CommandRunner(raw_output_dir=Path("output/raw"))
        result = runner.run(
            tool_name="subfinder",
            cmd=["subfinder", "-d", "example.com", "-o", "/tmp/out.txt"],
            target="example.com",
            timeout=120,
        )
        if result.return_code == 0:
            data = result.stdout
    """

    def __init__(self, raw_output_dir: Optional[Path] = None) -> None:
        self._raw_dir = raw_output_dir or Path("output/raw")
        self._raw_dir.mkdir(parents=True, exist_ok=True)

    def _ensure_pipx_path(self) -> None:
        """Add pipx's binary directory to PATH if missing."""
        pipx_bin = os.path.expanduser("~/.local/bin")
        current_path = os.environ.get("PATH", "")
        if pipx_bin not in current_path:
            os.environ["PATH"] = current_path + os.pathsep + pipx_bin if current_path else pipx_bin

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(
        self,
        tool_name: str,
        cmd: Union[List[str], str],
        target: str = "",
        timeout: int = 300,
        env: Optional[dict] = None,
        cwd: Optional[str] = None,
        save_raw: bool = True,
        check_exists: bool = True,
    ) -> ToolResult:
        """
        Execute a command and return a ToolResult.

        Args:
            tool_name:    Human label for logging (e.g., "subfinder").
            cmd:          Command as list (preferred) or shell string.
            target:       Target identifier for logging context.
            timeout:      Seconds before SIGKILL. 0 = no timeout.
            env:          Extra environment variables to merge with os.environ.
            cwd:          Working directory for the subprocess.
            save_raw:     Whether to persist stdout to output/raw/.
            check_exists: Verify binary is on PATH before running.

        Returns:
            ToolResult with return code, stdout, stderr, and duration.
        """
        self._ensure_pipx_path()
        cmd_list = self._normalize_cmd(cmd)

        if check_exists:
            self._check_binary(cmd_list[0], tool_name)

        # Build environment
        run_env = {**os.environ, **(env or {})}

        # Cap timeout at configured value (0 means unlimited)
        effective_timeout = timeout if timeout > 0 else None

        cmd_str = " ".join(shlex.quote(c) for c in cmd_list)
        log.debug("EXEC | tool=%s | target=%s | cmd=%s", tool_name, target, cmd_str)

        start = time.monotonic()
        timed_out = False
        stdout_data = ""
        stderr_data = ""
        return_code = -1

        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=run_env,
                cwd=cwd,
            )
            stdout_data = proc.stdout or ""
            stderr_data = proc.stderr or ""
            return_code = proc.returncode

        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout_data = (exc.stdout or b"").decode("utf-8", errors="replace")
            stderr_data = (exc.stderr or b"").decode("utf-8", errors="replace")
            return_code = -1
            log.warning(
                "TIMEOUT | tool=%s | target=%s | timeout=%ds",
                tool_name, target, timeout,
            )

        except FileNotFoundError:
            return_code = 127
            stderr_data = f"Binary not found: {cmd_list[0]}"
            log.error(
                "BINARY_NOT_FOUND | tool=%s | binary=%s",
                tool_name, cmd_list[0],
            )

        except OSError as exc:
            return_code = -1
            stderr_data = str(exc)
            log.error("OS_ERROR | tool=%s | error=%s", tool_name, exc)

        duration = time.monotonic() - start

        # Truncate oversized output
        if len(stdout_data) > MAX_OUTPUT_BYTES:
            stdout_data = stdout_data[:MAX_OUTPUT_BYTES] + "\n[TRUNCATED]"

        # Persist raw output
        raw_path = ""
        if save_raw and stdout_data.strip():
            raw_path = self._save_raw(tool_name, target, stdout_data)

        log_tool_invocation(
            log, tool_name, target, cmd_str, duration, return_code,
            stderr_summary=stderr_data[:200],
        )

        return ToolResult(
            tool_name=tool_name,
            target=target,
            cmd=cmd_str,
            return_code=return_code,
            stdout=stdout_data,
            stderr=stderr_data,
            duration_seconds=round(duration, 2),
            timed_out=timed_out,
            raw_output_path=raw_path,
        )

    def check_binary_available(self, binary: str) -> bool:
        """Return True if binary is found on PATH."""
        self._ensure_pipx_path()
        return shutil.which(binary) is not None or (Path(binary).is_absolute() and Path(binary).exists())

    def get_version(self, binary: str, version_flag: str = "--version") -> str:
        """
        Attempt to retrieve the version string of a tool.
        Returns empty string on failure.
        """
        self._ensure_pipx_path()
        try:
            result = subprocess.run(
                [binary, version_flag],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout.strip() or result.stderr.strip()
            # Return first non-empty line
            for line in output.splitlines():
                if line.strip():
                    return line.strip()
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalize_cmd(self, cmd: Union[List[str], str]) -> List[str]:
        if isinstance(cmd, str):
            return shlex.split(cmd)
        return list(cmd)

    def _check_binary(self, binary: str, tool_name: str) -> None:
        """Raise ToolNotFoundError if binary is not on PATH."""
        if not self.check_binary_available(binary):
            # Try resolving as absolute path
            if not (Path(binary).is_absolute() and Path(binary).exists()):
                raise ToolNotFoundError(
                    tool_name,
                    install_hint=f"Install '{binary}' and ensure it is on your PATH.",
                )

    def _save_raw(self, tool_name: str, target: str, content: str) -> str:
        """Write raw tool output to output/raw/<tool>/<sanitized_target>.txt."""
        target_safe = (
            target.replace("://", "_")
            .replace("/", "_")
            .replace(":", "_")
            .strip("_")[:80]
        )
        tool_dir = self._raw_dir / tool_name
        tool_dir.mkdir(parents=True, exist_ok=True)
        out_path = tool_dir / f"{target_safe}.txt"

        # Append if file exists (multiple runs / phases for same target)
        with open(out_path, "a", encoding="utf-8") as fh:
            fh.write(content)
            if not content.endswith("\n"):
                fh.write("\n")

        log.debug("RAW_SAVED | tool=%s | path=%s", tool_name, out_path)
        return str(out_path)
