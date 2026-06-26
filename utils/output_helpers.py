"""
utils/output_helpers.py
-----------------------
File system helpers and output path management.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class OutputManager:
    """
    Manages the output directory structure and provides path helpers.

    To keep simultaneous scans isolated (e.g. several Kali workspaces or
    desktops each running BountyMind against a different website at the same
    time), every scan gets its own directory grouped by website::

        output/
          <website>/                         <- one folder per target website
            <timestamp>_<session_id>/        <- one folder per scan run
              raw/          <- raw tool output files (per-tool subdirectories)
              parsed/       <- normalized JSON/text artefacts
              reports/      <- final Markdown and HTML reports
              screenshots/  <- gowitness captures

    Because each run lives under a unique ``<timestamp>_<session_id>`` folder,
    parallel sessions never overwrite one another's files — even when two
    workspaces scan the *same* website concurrently.

    When ``label`` is omitted (e.g. maintenance commands like ``--bootstrap``)
    the manager falls back to the flat legacy layout directly under ``base_dir``.
    """

    def __init__(
        self,
        base_dir: Path,
        session_id: Optional[str] = None,
        label: Optional[str] = None,
    ) -> None:
        self.root = Path(base_dir)
        self.session_id = session_id

        if label:
            safe_label = self._sanitize(label)
            ts = time.strftime("%Y%m%d_%H%M%S")
            run_name = f"{ts}_{session_id}" if session_id else ts
            self.website_dir = self.root / safe_label
            self.base = self.website_dir / run_name
        else:
            self.website_dir = self.root
            self.base = self.root

        self.raw = self.base / "raw"
        self.parsed = self.base / "parsed"
        self.reports = self.base / "reports"
        self.screenshots = self.base / "screenshots"
        self._init_dirs()

    def _init_dirs(self) -> None:
        for d in (self.base, self.raw, self.parsed, self.reports, self.screenshots):
            d.mkdir(parents=True, exist_ok=True)

    def raw_path(self, tool: str, target: str, suffix: str = "txt") -> Path:
        """Return path for a raw tool output file."""
        safe = self._sanitize(target)
        d = self.raw / tool
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}.{suffix}"

    def parsed_path(self, module: str, target: str, suffix: str = "json") -> Path:
        """Return path for a parsed output file."""
        safe = self._sanitize(target)
        d = self.parsed / module
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{safe}.{suffix}"

    def report_path(self, session_id: str, fmt: str) -> Path:
        """Return the final report path for a given format (md/html)."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        ext = "md" if fmt == "markdown" else fmt
        return self.reports / f"report_{session_id}_{ts}.{ext}"

    def save_parsed(self, module: str, target: str, data: Any) -> Path:
        """Serialize data to JSON and write to the parsed directory."""
        path = self.parsed_path(module, target, "json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        return path

    @staticmethod
    def _sanitize(name: str) -> str:
        """Make a string safe for use as a filename."""
        safe = re.sub(r"[^\w\-.]", "_", name)
        return safe[:100]


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_line_delimited(text: str) -> List[str]:
    """Split text on newlines, strip whitespace, drop empty and comment lines."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def is_valid_domain(domain: str) -> bool:
    """Basic check that a string looks like a domain name."""
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain.strip()))


def is_valid_url(url: str) -> bool:
    """Basic check that a string looks like an HTTP/HTTPS URL."""
    return url.strip().startswith(("http://", "https://"))


def clean_domain_list(raw: List[str]) -> List[str]:
    """
    Sanitize a list of domain strings.
    Removes blanks, comments (#), duplicates, and malformed entries.
    """
    seen: set = set()
    result = []
    for item in raw:
        item = item.strip().lstrip("*.")  # strip wildcards
        if not item or item.startswith("#"):
            continue
        item_lower = item.lower()
        if item_lower in seen:
            continue
        if is_valid_domain(item_lower):
            seen.add(item_lower)
            result.append(item_lower)
    return result


def extract_domains_from_url(url: str) -> str:
    """Extract the bare hostname from an HTTP URL."""
    url = url.strip()
    for prefix in ("https://", "http://"):
        if url.startswith(prefix):
            url = url[len(prefix):]
    return url.split("/")[0].split(":")[0]


def severity_sort_key(severity: str) -> int:
    """Return a sort key for severity strings (higher = more severe)."""
    order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
    return order.get(severity.lower(), 0)


def load_targets_from_file(file_path: str) -> List[str]:
    """
    Load target domains from a file.
    Handles blank lines, comments, and leading/trailing whitespace.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {file_path}")

    raw = path.read_text(encoding="utf-8").splitlines()
    targets = []
    for line in raw:
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)

    return targets
