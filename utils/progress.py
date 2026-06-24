"""
utils/progress.py
-----------------
Terminal UI / progress display using Rich.

Design:
- ProgressManager wraps Rich's Live/Progress for a clean, non-scrolling UI.
- If Rich is not installed, falls back to a simple print-based display.
- Module code calls update_task() / advance() rather than printing directly.
- All detailed logging still goes to framework.log via the logging module.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator, Optional

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        Progress,
        SpinnerColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# Terminal palette — dark, minimal, Apple-clean with hacker green accents
_UI_THEME = Theme({
    "banner.title": "bold #30d158",
    "banner.sub": "dim #86868b",
    "banner.accent": "#64d2ff",
    "phase.title": "bold #e5e5ea",
    "phase.dim": "dim #636366",
    "info": "#64d2ff",
    "ok": "#30d158",
    "warn": "#ffd60a",
    "err": "#ff453a",
    "finding.critical": "bold #ff453a",
    "finding.high": "#ff9f0a",
    "finding.medium": "#ffd60a",
    "finding.low": "#64d2ff",
    "finding.info": "dim #86868b",
}) if RICH_AVAILABLE else None


# ---------------------------------------------------------------------------
# Public console instance (used across the project for structured output)
# ---------------------------------------------------------------------------

if RICH_AVAILABLE:
    console = Console(stderr=False, theme=_UI_THEME, highlight=False)
else:
    # Minimal shim
    class _FallbackConsole:  # type: ignore[no-untyped-def]
        def print(self, *args, **kwargs):
            print(*args)

        def rule(self, title="", **kwargs):
            print(f"\n{'=' * 60}  {title}  {'=' * 60}\n")

        def log(self, *args, **kwargs):
            print(*args)

    console = _FallbackConsole()  # type: ignore[assignment]


def render_banner() -> None:
    """Minimal startup banner — dark terminal x Apple typography."""
    if not RICH_AVAILABLE:
        print(
            "\n  BOUNTYMIND\n"
            "  automated recon · vuln assessment · waf evasion\n"
            "  authorized use only\n"
        )
        return

    art = Text.assemble(
        ("  BOUNTY", "banner.title"),
        ("MIND", "bold white"),
        ("\n", ""),
        ("  recon  ·  vuln  ·  evasion  ·  deep detection", "banner.sub"),
    )
    console.print(
        Panel(
            art,
            border_style="#30d158",
            box=box.ROUNDED,
            padding=(0, 2),
            subtitle="[banner.sub]authorized targets only · unauthenticated by default[/banner.sub]",
        )
    )


# ---------------------------------------------------------------------------
# ProgressManager
# ---------------------------------------------------------------------------


class PhaseTracker:
    """
    Tracks all scan phases and renders a live status table alongside progress bars.
    """

    PHASES = [
        ("bootstrap", "Tool Bootstrap"),
        ("discovery", "Subdomain Discovery"),
        ("probing", "HTTP Probing & Ports"),
        ("harvest", "URL Harvesting"),
        ("scanning", "Vulnerability Scanning"),
        ("secrets", "JS Secret Mining"),
        ("cloud", "Cloud Bucket Recon"),
        ("screenshots", "Visual Screenshots"),
        ("waf", "WAF Detection & Evasion"),
        ("deep-scans", "Deep Detection Scans"),
        ("reporting", "Report Generation"),
    ]

    def __init__(self) -> None:
        self._states: dict[str, dict[str, str]] = {
            name: {"label": label, "status": "pending", "detail": ""}
            for name, label in self.PHASES
        }

    def set(self, phase: str, status: str, detail: str = "") -> None:
        if phase in self._states:
            self._states[phase]["status"] = status
            if detail:
                self._states[phase]["detail"] = detail

    def render_table(self) -> "Table | str":
        if not RICH_AVAILABLE:
            lines = ["Scan Phases:"]
            for name, info in self._states.items():
                lines.append(f"  [{info['status']:10}] {info['label']} {info['detail']}")
            return "\n".join(lines)

        status_style = {
            "pending": "phase.dim",
            "running": "bold #ffd60a",
            "done": "bold #30d158",
            "skipped": "dim italic #636366",
            "error": "bold #ff453a",
        }
        table = Table(
            title="[phase.title]SCAN PIPELINE[/phase.title]",
            show_header=True,
            header_style="bold #64d2ff",
            box=box.SIMPLE_HEAD,
            border_style="#2c2c2e",
            padding=(0, 1),
        )
        table.add_column("Phase", style="white", width=28, no_wrap=True)
        table.add_column("Status", width=12, no_wrap=True)
        table.add_column("Detail", style="phase.dim", overflow="ellipsis", max_width=52)
        for info in self._states.values():
            style = status_style.get(info["status"], "white")
            icon = {
                "pending": ".",
                "running": ">",
                "done": "+",
                "skipped": "-",
                "error": "!",
            }.get(info["status"], "·")
            table.add_row(
                info["label"],
                Text(f" {icon}  {info['status']}", style=style),
                info["detail"][:60],
            )
        return table


class ProgressManager:
    """
    Manages a Rich progress bar display with phase/module/target/tool columns.

    Usage::
        pm = ProgressManager()
        with pm.session("Scanning example.com"):
            task_id = pm.add_task("Discovery", total=5)
            for item in items:
                do_work(item)
                pm.advance(task_id)
    """

    def __init__(self) -> None:
        self._progress: Optional[object] = None
        self._live: Optional[object] = None
        self._current_phase: str = ""
        self._current_tool: str = ""
        self._start_time: float = time.monotonic()
        self.phases = PhaseTracker()

        if RICH_AVAILABLE:
            self._progress = Progress(
                SpinnerColumn(spinner_name="dots", style="#30d158"),
                TextColumn("[bold #e5e5ea]{task.description}"),
                BarColumn(
                    bar_width=36,
                    complete_style="#30d158",
                    finished_style="#30d158",
                    pulse_style="#1c4228",
                ),
                MofNCompleteColumn(),
                TextColumn("[phase.dim]{task.fields[status]}"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
                refresh_per_second=5,
            )

    @contextmanager
    def session(self, title: str = "ReconFramework") -> Generator[None, None, None]:
        """Context manager that renders the progress panel for the scan session."""
        if RICH_AVAILABLE and self._progress:
            with self._progress:
                console.print(
                    Panel(
                        Text(title, style="bold #e5e5ea"),
                        border_style="#30d158",
                        box=box.ROUNDED,
                        padding=(0, 2),
                    )
                )
                yield
            console.print(
                Panel(
                    "[ok]+[/ok]  [bold #e5e5ea]scan complete[/bold #e5e5ea]",
                    border_style="#2c2c2e",
                    box=box.ROUNDED,
                    padding=(0, 2),
                )
            )
        else:
            print(f"\n{'=' * 70}")
            print(f"  {title}")
            print(f"{'=' * 70}\n")
            yield
            print(f"\n{'=' * 70}  Complete  {'=' * 70}\n")

    def add_task(self, description: str, total: int = 100, **fields) -> object:
        """Add a progress task. Returns task ID."""
        if RICH_AVAILABLE and self._progress:
            default_fields = {"status": ""}
            default_fields.update(fields)
            return self._progress.add_task(  # type: ignore[union-attr]
                description, total=total, **default_fields
            )
        # Fallback: just print
        print(f"  [{description}] starting...")
        return None

    def advance(self, task_id: object, amount: int = 1, status: str = "") -> None:
        """Advance a task by amount steps."""
        if RICH_AVAILABLE and self._progress and task_id is not None:
            update_kwargs = {"advance": amount}
            if status:
                update_kwargs["status"] = status  # type: ignore[assignment]
            self._progress.update(task_id, **update_kwargs)  # type: ignore[union-attr]

    def update_status(self, task_id: object, status: str) -> None:
        """Update the status text for a task without advancing."""
        if RICH_AVAILABLE and self._progress and task_id is not None:
            self._progress.update(task_id, status=status)  # type: ignore[union-attr]

    def complete_task(self, task_id: object, status: str = "Done") -> None:
        """Mark a task as complete."""
        if RICH_AVAILABLE and self._progress and task_id is not None:
            self._progress.update(task_id, status=status, completed=True)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Convenience print methods (go through rich console)
    # ------------------------------------------------------------------

    @staticmethod
    def print_info(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(f"[info]  *[/info]  {msg}")
        else:
            print(f"  INFO: {msg}")

    @staticmethod
    def print_success(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(f"[ok]  +[/ok]  {msg}")
        else:
            print(f"  OK: {msg}")

    @staticmethod
    def print_warning(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(f"[warn]  ![/warn]  {msg}")
        else:
            print(f"  WARN: {msg}")

    @staticmethod
    def print_error(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(f"[err]  x[/err]  {msg}")
        else:
            print(f"  ERROR: {msg}")

    @staticmethod
    def print_phase(phase: str) -> None:
        if RICH_AVAILABLE:
            console.rule(f"[bold #30d158]{phase.upper()}", style="#2c2c2e")
        else:
            print(f"\n--- Phase: {phase} ---\n")

    def set_phase_status(self, phase: str, status: str, detail: str = "") -> None:
        """Update a named phase and refresh the live dashboard."""
        self.phases.set(phase, status, detail)
        self.refresh_dashboard()

    def refresh_dashboard(self) -> None:
        """Print the simultaneous phase progress table."""
        table = self.phases.render_table()
        if RICH_AVAILABLE:
            console.print(Panel(table, border_style="#2c2c2e", box=box.ROUNDED, padding=(0, 1)))
        else:
            print(table)

    def print_usage(self) -> None:
        """Show quick CLI usage reference."""
        if not RICH_AVAILABLE:
            print(
                "BountyMind CLI: bountymind -d DOMAIN | bountymind -l FILE | "
                "bountymind --help"
            )
            return

        usage = Table(show_header=False, box=box.SIMPLE, border_style="#2c2c2e", padding=(0, 1))
        usage.add_column("cmd", style="bold #30d158", no_wrap=True)
        usage.add_column("desc", style="phase.dim")
        commands = [
            ("bountymind -d example.com", "scan a single domain"),
            ("bountymind -l targets.txt", "scan from list file"),
            ("bountymind --update", "self-update from GitHub"),
            ("bountymind --bootstrap", "install missing tools"),
            ("bountymind --check-env", "verify environment"),
            ("bountymind --help", "full option list"),
        ]
        for cmd, desc in commands:
            usage.add_row(cmd, desc)
        console.print(
            Panel(
                usage,
                title="[phase.title]quick reference[/phase.title]",
                border_style="#2c2c2e",
                box=box.ROUNDED,
                subtitle="[phase.dim]reports → output/reports/  ·  logs → logs/framework.log[/phase.dim]",
                padding=(0, 1),
            )
        )

    @staticmethod
    def print_finding(severity: str, target: str, msg: str) -> None:
        """Print a finding to console with severity-based coloring."""
        colors = {
            "critical": "finding.critical",
            "high": "finding.high",
            "medium": "finding.medium",
            "low": "finding.low",
            "info": "finding.info",
        }
        color = colors.get(severity.lower(), "white")
        if RICH_AVAILABLE:
            console.print(f"[{color}]  {severity.upper():8}[/{color}]  [white]{target}[/white]  [phase.dim]{msg}[/phase.dim]")
        else:
            print(f"  [{severity.upper():8}] {target}: {msg}")

    @staticmethod
    def print_summary_table(rows: list, headers: list, title: str = "") -> None:
        """Print a simple summary table."""
        if not RICH_AVAILABLE:
            if title:
                print(f"\n{title}")
            col_width = max(len(h) for h in headers) + 2
            print("  " + "  ".join(h.ljust(col_width) for h in headers))
            for row in rows:
                print("  " + "  ".join(str(c).ljust(col_width) for c in row))
            return

        table = Table(
            title=f"[phase.title]{title}[/phase.title]" if title else None,
            show_header=True,
            header_style="bold #64d2ff",
            box=box.SIMPLE_HEAD,
            border_style="#2c2c2e",
            padding=(0, 1),
        )
        for h in headers:
            table.add_column(h)
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
