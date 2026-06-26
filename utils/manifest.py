"""
utils/manifest.py
-----------------
Per-run machine-readable manifest (``run.json``) and cross-run discovery.

Every BountyMind scan writes a ``run.json`` into its isolated output
directory. The manifest is created with ``status = "running"`` at startup and
finalized to ``"completed"`` / ``"failed"`` when the scan ends. This gives the
tool industry-grade observability:

* **Automation / CI** can parse a stable JSON contract instead of scraping
  console text or Markdown.
* **Parallel sessions** (multiple terminal windows / Kali workspaces) become
  observable — ``--list-runs`` reads every manifest to show which runs are
  active, completed, or failed, with their PID and host.
* **Resumability / auditing** — each run records its exact command, targets,
  timing, finding counts, report paths, and error/warning totals.

The manifest filename is intentionally fixed (``run.json``) so discovery is a
simple glob, while the *directory* it lives in is unique per run.
"""

from __future__ import annotations

import datetime
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

log = get_logger("manifest")

MANIFEST_NAME = "run.json"
SCHEMA_VERSION = 1


def _tool_version() -> str:
    """Best-effort BountyMind version (installed metadata → fallback)."""
    try:
        from importlib.metadata import version, PackageNotFoundError

        try:
            return version("bountymind")
        except PackageNotFoundError:
            pass
    except Exception:  # noqa: BLE001
        pass
    return "2.1.0"


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(dt: Optional[datetime.datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


class RunManifest:
    """
    Manages the lifecycle of a single run's ``run.json``.

    Usage::

        manifest = RunManifest(output.base, session_id, targets, command)
        manifest.start()                 # writes status=running
        ...
        manifest.finish(session, reports, status="completed")
    """

    def __init__(
        self,
        run_dir: Path,
        session_id: str,
        targets: List[str],
        label: str,
        command: str,
    ) -> None:
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / MANIFEST_NAME
        self.session_id = session_id
        self.targets = list(targets)
        self.label = label
        self.command = command
        self.started_at = _utcnow()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Write the initial manifest with ``status = running``."""
        data = self._base_payload()
        data.update(
            {
                "status": "running",
                "ended_at": None,
                "duration_seconds": None,
                "stats": {},
                "reports": [],
                "error_count": 0,
                "warning_count": 0,
            }
        )
        self._write(data)

    def finish(
        self,
        session: Any,
        reports: Optional[List[Path]] = None,
        status: str = "completed",
    ) -> None:
        """Finalize the manifest with stats, report paths, and final status."""
        ended = _utcnow()
        duration = (ended - self.started_at).total_seconds()

        data = self._base_payload()
        data.update(
            {
                "status": status,
                "ended_at": _iso(ended),
                "duration_seconds": round(duration, 1),
                "stats": self._collect_stats(session),
                "reports": [str(p) for p in (reports or [])],
                "error_count": len(getattr(session, "errors", []) or []),
                "warning_count": len(getattr(session, "warnings", []) or []),
            }
        )
        self._write(data)

    def mark_failed(self, error: str) -> None:
        """Mark the run as failed (e.g. on an unhandled exception)."""
        ended = _utcnow()
        existing = self.read(self.path) or self._base_payload()
        existing.update(
            {
                "status": "failed",
                "ended_at": _iso(ended),
                "duration_seconds": round((ended - self.started_at).total_seconds(), 1),
                "fatal_error": error,
            }
        )
        self._write(existing)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _base_payload(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "bountymind",
            "tool_version": _tool_version(),
            "session_id": self.session_id,
            "label": self.label,
            "targets": self.targets,
            "command": self.command,
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "output_dir": str(self.run_dir),
            "started_at": _iso(self.started_at),
        }

    @staticmethod
    def _collect_stats(session: Any) -> Dict[str, int]:
        def _count(attr: str) -> int:
            val = getattr(session, attr, None)
            try:
                return len(val) if val is not None else 0
            except TypeError:
                return 0

        live_hosts = getattr(session, "live_hosts", []) or []
        screenshots = sum(
            1 for h in live_hosts if getattr(h, "screenshot_path", None)
        )
        return {
            "subdomains": _count("subdomains"),
            "live_hosts": _count("live_hosts"),
            "open_ports": _count("port_services"),
            "directory_findings": _count("directory_findings"),
            "nuclei_findings": _count("nuclei_findings"),
            "waf_endpoints": _count("waf_detections"),
            "evasion_findings": _count("evasion_findings"),
            "harvested_urls": _count("harvested_urls"),
            "js_secrets": _count("secret_findings"),
            "cloud_buckets": _count("cloud_bucket_findings"),
            "screenshots": screenshots,
            "manual_flags": _count("manual_flags"),
            "sqli_findings": _count("sqli_findings"),
            "xss_findings": _count("xss_findings"),
            "dast_findings": _count("dast_findings"),
            "smuggling_findings": _count("smuggling_findings"),
            "prototype_pollution": _count("prototype_pollution"),
            "bypass_403_findings": _count("bypass_403_findings"),
            "hidden_params": _count("hidden_params"),
            "ssrf_findings": _count("ssrf_findings"),
            "open_redirects": _count("open_redirects"),
            "info_disclosures": _count("info_disclosures"),
        }

    def _write(self, data: Dict[str, Any]) -> None:
        try:
            self.run_dir.mkdir(parents=True, exist_ok=True)
            # Atomic-ish write: write to temp then replace to avoid a reader
            # ever seeing a half-written manifest during concurrent listing.
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            tmp.replace(self.path)
        except OSError as exc:
            log.warning("Failed to write run manifest %s: %s", self.path, exc)

    @staticmethod
    def read(path: Path) -> Optional[Dict[str, Any]]:
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None


# ---------------------------------------------------------------------------
# Cross-run discovery (used by --list-runs / pruning)
# ---------------------------------------------------------------------------


@dataclass
class RunSummary:
    path: Path
    data: Dict[str, Any]

    @property
    def started_at(self) -> str:
        return self.data.get("started_at") or ""

    @property
    def status(self) -> str:
        return self.data.get("status", "unknown")

    @property
    def label(self) -> str:
        return self.data.get("label", "-")

    @property
    def session_id(self) -> str:
        return self.data.get("session_id", "-")


def find_runs(output_root: Path) -> List[RunSummary]:
    """
    Discover all run manifests under ``output_root`` (recursively).

    Returns summaries sorted newest-first by start time. Reads are tolerant of
    missing/partial files so an in-progress run never breaks discovery.
    """
    root = Path(output_root)
    runs: List[RunSummary] = []
    if not root.exists():
        return runs

    for manifest_path in root.glob(f"*/*/{MANIFEST_NAME}"):
        data = RunManifest.read(manifest_path)
        if data:
            runs.append(RunSummary(path=manifest_path, data=data))

    runs.sort(key=lambda r: r.started_at, reverse=True)
    return runs


def runs_table_rows(runs: List[RunSummary]) -> List[List[str]]:
    """Build display rows for ``print_summary_table``."""
    rows: List[List[str]] = []
    for r in runs:
        stats = r.data.get("stats", {}) or {}
        nuclei = stats.get("nuclei_findings", 0)
        live = stats.get("live_hosts", 0)
        started = (r.started_at or "").replace("T", " ")[:19]
        dur = r.data.get("duration_seconds")
        dur_str = f"{dur:.0f}s" if isinstance(dur, (int, float)) else "-"
        rows.append(
            [
                r.label,
                r.status,
                started,
                dur_str,
                str(live),
                str(nuclei),
                r.session_id,
            ]
        )
    return rows


RUNS_TABLE_HEADERS = [
    "Website",
    "Status",
    "Started (UTC)",
    "Duration",
    "Live",
    "Nuclei",
    "Session",
]
