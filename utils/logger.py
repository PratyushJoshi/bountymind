"""
utils/logger.py
---------------
Configures the framework's logging infrastructure.

Design:
- File handler writes DEBUG+ records to logs/framework.log with full context.
- Console handler writes WARNING+ only (keeps terminal clean).
- Rich handler used for console if available, falls back to standard StreamHandler.
- get_logger() returns a named child logger for each module.
- setup_logging() called once from main.py at startup.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional


# Module-level sentinel so setup is idempotent
_LOGGING_CONFIGURED = False

# Root logger name for the framework
FRAMEWORK_LOGGER = "reconframework"


def setup_logging(
    log_file: str = "logs/framework.log",
    log_level: str = "INFO",
    console_level: str = "WARNING",
) -> None:
    """
    Configure the framework root logger.
    Call once from main.py at startup.

    Args:
        log_file:      Path for the detailed file log.
        log_level:     Minimum level written to file (DEBUG, INFO, WARNING, ERROR).
        console_level: Minimum level shown on console (default WARNING = mostly silent).
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger(FRAMEWORK_LOGGER)
    root.setLevel(logging.DEBUG)  # Capture everything; handlers filter level

    numeric_file_level = _parse_level(log_level)
    numeric_console_level = _parse_level(console_level)

    # ------------------------------------------------------------------
    # File handler — detailed with full context
    # ------------------------------------------------------------------
    file_formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-40s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.FileHandler(log_file, encoding="utf-8", mode="a")
    file_handler.setLevel(numeric_file_level)
    file_handler.setFormatter(file_formatter)
    root.addHandler(file_handler)

    # ------------------------------------------------------------------
    # Console handler — minimal, only warnings and errors by default
    # ------------------------------------------------------------------
    console_formatter = logging.Formatter(
        fmt="%(levelname)-8s %(message)s"
    )
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_console_level)
    console_handler.setFormatter(console_formatter)
    root.addHandler(console_handler)

    _LOGGING_CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the framework root.

    Usage::
        log = get_logger(__name__)
        log.info("Starting discovery for %s", target)
    """
    return logging.getLogger(f"{FRAMEWORK_LOGGER}.{name}")


def _parse_level(level: str) -> int:
    """Convert a string log level to its numeric equivalent."""
    numeric = getattr(logging, level.upper(), None)
    if not isinstance(numeric, int):
        return logging.INFO
    return numeric


def log_tool_invocation(
    logger: logging.Logger,
    tool_name: str,
    target: str,
    cmd: str,
    duration: float,
    return_code: int,
    stderr_summary: str = "",
) -> None:
    """
    Convenience function to log a standardized tool execution record.
    Always written at DEBUG level to keep the file log structured.
    """
    logger.debug(
        "TOOL_RUN | tool=%-15s | target=%-40s | rc=%d | duration=%.1fs | cmd=%s%s",
        tool_name,
        target,
        return_code,
        duration,
        cmd,
        f" | stderr_excerpt={stderr_summary[:120]}" if stderr_summary else "",
    )
