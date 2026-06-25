"""
utils/progress.py
-----------------
BountyMind terminal UI — a live, in-place scan dashboard built on Rich.

Design goals (v2.1 UI):
- A single persistent ``Live`` surface renders the whole scan pipeline in place
  instead of spamming the scrollback with a new panel on every status change.
- The pipeline shows every phase with an animated state marker, a result detail
  column and a per-phase elapsed timer, plus an embedded progress region for the
  currently-running task(s).
- Log-style messages (info/success/warning/error/findings) print cleanly *above*
  the live dashboard so history is preserved while the dashboard stays pinned.
- Everything degrades gracefully to plain ``print`` when Rich is unavailable.

Public surface (kept stable for the rest of the codebase):
    render_banner()
    console                      (module-level Rich console / shim)
    ProgressManager:
        session(title)           context manager wrapping a scan
        add_task / advance / update_status / complete_task
        set_phase_status / refresh_dashboard
        print_info / print_success / print_warning / print_error
        print_phase / print_usage / print_finding / print_summary_table
        phases                   (PhaseTracker instance)
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Dict, Generator, List, Optional, Tuple

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console, Group, RenderableType
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
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without Rich installed
    RICH_AVAILABLE = False


APP_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Palette — dark terminal, hacker-green primary with electric-cyan accents.
# ---------------------------------------------------------------------------
C_GREEN = "#30d158"
C_CYAN = "#64d2ff"
C_AMBER = "#ffd60a"
C_ORANGE = "#ff9f0a"
C_RED = "#ff453a"
C_TEXT = "#e5e5ea"
C_MUTED = "#86868b"
C_DIM = "#636366"
C_LINE = "#2c2c2e"

_UI_THEME = (
    {
        "banner.title": f"bold {C_GREEN}",
        "banner.sub": f"dim {C_MUTED}",
        "banner.accent": C_CYAN,
        "phase.title": f"bold {C_TEXT}",
        "phase.dim": f"dim {C_DIM}",
        "info": C_CYAN,
        "ok": C_GREEN,
        "warn": C_AMBER,
        "err": C_RED,
        "finding.critical": f"bold {C_RED}",
        "finding.high": C_ORANGE,
        "finding.medium": C_AMBER,
        "finding.low": C_CYAN,
        "finding.info": f"dim {C_MUTED}",
    }
)

if RICH_AVAILABLE:
    from rich.theme import Theme

    console: object = Console(theme=Theme(_UI_THEME), highlight=False)
else:

    class _FallbackConsole:  # type: ignore[no-redef]
        """Minimal stand-in so the rest of the code can call console.print()."""

        def print(self, *args, **kwargs):
            text = " ".join(str(a) for a in args)
            print(text)

        def rule(self, title="", **kwargs):
            print(f"\n{'=' * 24} {title} {'=' * 24}\n")

        def log(self, *args, **kwargs):
            print(*args)

    console = _FallbackConsole()


_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _gradient(
    text: str,
    start: Tuple[int, int, int] = (48, 209, 88),
    end: Tuple[int, int, int] = (100, 210, 255),
    style: str = "bold",
) -> "Text":
    """Return a Rich Text with a per-character colour gradient (start → end)."""
    out = Text()
    n = max(len(text) - 1, 1)
    for i, ch in enumerate(text):
        r = int(start[0] + (end[0] - start[0]) * i / n)
        g = int(start[1] + (end[1] - start[1]) * i / n)
        b = int(start[2] + (end[2] - start[2]) * i / n)
        out.append(ch, style=f"{style} #{r:02x}{g:02x}{b:02x}")
    return out


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER_ART = r"""
 ██████   ██████  ██    ██ ███    ██ ████████ ██    ██
 ██   ██ ██    ██ ██    ██ ████   ██    ██     ██  ██ 
 ██████  ██    ██ ██    ██ ██ ██  ██    ██      ████  
 ██   ██ ██    ██ ██    ██ ██  ██ ██    ██       ██   
 ██████   ██████   ██████  ██   ████    ██       ██   
            ███    ███ ██ ███    ██ ██████
            ████  ████ ██ ████   ██ ██   ██
            ██ ████ ██ ██ ██ ██  ██ ██   ██
            ██  ██  ██ ██ ██  ██ ██ ██   ██
            ██      ██ ██ ██   ████ ██████
""".strip("\n")


def render_banner() -> None:
    """Startup banner — gradient wordmark, tagline and safety chips."""
    if not RICH_AVAILABLE:
        print(
            "\n  BOUNTYMIND  v" + APP_VERSION + "\n"
            "  recon · vuln assessment · waf evasion · deep detection\n"
            "  authorized targets only · unauthenticated by default\n"
        )
        return

    art = Text()
    lines = _BANNER_ART.splitlines()
    for idx, line in enumerate(lines):
        # Vertical gradient: green at the top fading to cyan at the bottom.
        t = idx / max(len(lines) - 1, 1)
        r = int(48 + (100 - 48) * t)
        g = int(209 + (210 - 209) * t)
        b = int(88 + (255 - 88) * t)
        art.append(line + "\n", style=f"bold #{r:02x}{g:02x}{b:02x}")

    tagline = Text(
        "recon › vulns › secrets › waf evasion › deep detection",
        style=f"italic {C_MUTED}",
    )
    chips = Text()
    chips.append("  ◆ authorized targets only  ", style=f"{C_GREEN}")
    chips.append("  ◆ unauthenticated · safe-mode  ", style=f"{C_CYAN}")

    meta = Text()
    meta.append("v", style=C_DIM)
    meta.append(APP_VERSION, style=f"bold {C_CYAN}")
    meta.append("  ·  ", style=C_DIM)
    meta.append("automated bug-hunting framework", style=C_MUTED)

    body = Group(
        Align.center(art),
        Align.center(tagline),
        Text(""),
        Align.center(meta),
        Align.center(chips),
    )
    console.print(
        Panel(
            body,
            border_style=C_GREEN,
            box=box.ROUNDED,
            padding=(1, 4),
        )
    )


# ---------------------------------------------------------------------------
# Phase tracking
# ---------------------------------------------------------------------------


class PhaseTracker:
    """Tracks the status, detail text and timing of every scan phase."""

    PHASES: List[Tuple[str, str]] = [
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
        self._states: Dict[str, Dict[str, object]] = {
            name: {
                "label": label,
                "status": "pending",
                "detail": "",
                "started": None,
                "ended": None,
            }
            for name, label in self.PHASES
        }

    def set(self, phase: str, status: str, detail: str = "") -> None:
        st = self._states.get(phase)
        if st is None:
            return
        now = time.monotonic()
        prev = st["status"]
        if status == "running" and prev != "running":
            st["started"] = now
            st["ended"] = None
        elif status in ("done", "error", "skipped"):
            if st["started"] is None and status != "skipped":
                st["started"] = now
            st["ended"] = now
        st["status"] = status
        if detail:
            st["detail"] = detail

    def _elapsed(self, st: Dict[str, object]) -> str:
        start = st["started"]
        if start is None:
            return ""
        end = st["ended"] if st["ended"] is not None else time.monotonic()
        secs = max(0, int(end - start))  # type: ignore[operator]
        if secs >= 3600:
            return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"
        if secs >= 60:
            return f"{secs // 60}m{secs % 60:02d}s"
        return f"{secs}s"

    def counts(self) -> Tuple[int, int, int]:
        """Return (done, total_active, errors) for the summary line."""
        done = sum(1 for s in self._states.values() if s["status"] == "done")
        errors = sum(1 for s in self._states.values() if s["status"] == "error")
        active = sum(1 for s in self._states.values() if s["status"] != "skipped")
        return done, active, errors

    # -- rendering ----------------------------------------------------------

    def render_plain(self) -> str:
        lines = ["Scan Phases:"]
        for st in self._states.values():
            lines.append(
                f"  [{str(st['status']):8}] {st['label']} {st['detail']}".rstrip()
            )
        return "\n".join(lines)

    def render_table(self, spinner_frame: str = "") -> "Table":
        status_style = {
            "pending": C_DIM,
            "running": f"bold {C_AMBER}",
            "done": f"bold {C_GREEN}",
            "skipped": f"dim italic {C_DIM}",
            "error": f"bold {C_RED}",
        }
        marker = {
            "pending": "○",
            "running": spinner_frame or "◇",
            "done": "●",
            "skipped": "⊘",
            "error": "✗",
        }
        table = Table(
            show_header=True,
            header_style=f"bold {C_CYAN}",
            box=box.SIMPLE_HEAD,
            border_style=C_LINE,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("", width=2, no_wrap=True)
        table.add_column("Phase", style=C_TEXT, no_wrap=True, ratio=3)
        table.add_column("Status", width=10, no_wrap=True)
        table.add_column("Detail", style=C_DIM, overflow="ellipsis", ratio=4)
        table.add_column("Time", justify="right", style=C_DIM, width=7, no_wrap=True)

        for st in self._states.values():
            status = str(st["status"])
            style = status_style.get(status, "white")
            table.add_row(
                Text(marker.get(status, "·"), style=style),
                str(st["label"]),
                Text(status, style=style),
                str(st["detail"])[:80],
                self._elapsed(st),
            )
        return table


# ---------------------------------------------------------------------------
# Live dashboard renderable
# ---------------------------------------------------------------------------


if RICH_AVAILABLE:

    class _Dashboard:
        """A self-refreshing renderable: pipeline table + active progress bars.

        Because this object exposes ``__rich_console__``, the parent ``Live``
        re-renders it on every refresh tick, which animates the spinner and
        ticks the per-phase timers without any manual repainting.
        """

        def __init__(self, manager: "ProgressManager") -> None:
            self._m = manager

        def __rich_console__(self, console, options):  # noqa: D401,ANN001
            frame = _SPINNER_FRAMES[int(time.monotonic() * 12) % len(_SPINNER_FRAMES)]
            done, active, errors = self._m.phases.counts()

            elapsed = ""
            if self._m._session_start is not None:
                secs = int(time.monotonic() - self._m._session_start)
                elapsed = (
                    f"{secs // 60}m{secs % 60:02d}s" if secs >= 60 else f"{secs}s"
                )

            subtitle = Text()
            subtitle.append(f" {done}", style=f"bold {C_GREEN}")
            subtitle.append("/", style=C_DIM)
            subtitle.append(f"{active} phases", style=C_MUTED)
            if errors:
                subtitle.append(f"  ·  {errors} error(s)", style=f"bold {C_RED}")
            if elapsed:
                subtitle.append(f"  ·  {elapsed} elapsed ", style=C_MUTED)

            renderables: List[RenderableType] = [self._m.phases.render_table(frame)]

            # Only show progress bars for work that is still in flight so the
            # pinned region stays compact during long scans.
            live_tasks = [t for t in self._m._progress.tasks if not t.finished]
            if live_tasks:
                renderables.append(Rule(style=C_LINE))
                renderables.append(self._m._progress)

            yield Panel(
                Group(*renderables),
                title=f"[bold {C_GREEN}]BOUNTYMIND[/]  [dim {C_MUTED}]scan pipeline[/]",
                title_align="left",
                subtitle=subtitle,
                subtitle_align="right",
                border_style=C_LINE,
                box=box.ROUNDED,
                padding=(0, 1),
            )


# ---------------------------------------------------------------------------
# ProgressManager
# ---------------------------------------------------------------------------


class ProgressManager:
    """Owns the live scan dashboard and all console output helpers."""

    def __init__(self) -> None:
        self.phases = PhaseTracker()
        self._live: Optional[object] = None
        self._session_start: Optional[float] = None
        self._progress: Optional[object] = None

        if RICH_AVAILABLE:
            self._progress = Progress(
                SpinnerColumn(spinner_name="dots", style=C_GREEN),
                TextColumn(f"[{C_TEXT}]{{task.description}}"),
                BarColumn(
                    bar_width=30,
                    complete_style=C_GREEN,
                    finished_style=C_GREEN,
                    pulse_style="#1c4228",
                ),
                MofNCompleteColumn(),
                TextColumn(f"[dim {C_DIM}]{{task.fields[status]}}"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            )

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    @contextmanager
    def session(self, title: str = "BountyMind") -> Generator[None, None, None]:
        """Render the live scan dashboard for the duration of the scan."""
        if RICH_AVAILABLE and self._progress is not None:
            self._session_start = time.monotonic()
            header = Text()
            header.append("◢◤ ", style=f"bold {C_GREEN}")
            header.append("target  ", style=C_DIM)
            header.append(title, style=f"bold {C_TEXT}")
            console.print(
                Panel(
                    header,
                    border_style=C_GREEN,
                    box=box.HEAVY_EDGE,
                    padding=(0, 2),
                )
            )
            self._live = Live(
                _Dashboard(self),
                console=console,
                refresh_per_second=12,
                transient=False,
                vertical_overflow="visible",
            )
            self._live.start()
            try:
                yield
            finally:
                # Final repaint so completed timings/states are accurate.
                try:
                    self._live.refresh()
                finally:
                    self._live.stop()
                    self._live = None

            secs = int(time.monotonic() - (self._session_start or time.monotonic()))
            dur = f"{secs // 60}m{secs % 60:02d}s" if secs >= 60 else f"{secs}s"
            done, active, errors = self.phases.counts()
            tail = Text()
            tail.append("●  ", style=f"bold {C_GREEN}")
            tail.append("scan complete", style=f"bold {C_TEXT}")
            tail.append(f"   {done}/{active} phases", style=C_MUTED)
            if errors:
                tail.append(f" · {errors} error(s)", style=f"bold {C_RED}")
            tail.append(f" · {dur}", style=C_MUTED)
            console.print(
                Panel(tail, border_style=C_LINE, box=box.ROUNDED, padding=(0, 2))
            )
        else:
            print(f"\n{'=' * 70}\n  {title}\n{'=' * 70}\n")
            yield
            print(f"\n{'=' * 28}  scan complete  {'=' * 28}\n")

    # ------------------------------------------------------------------
    # Progress tasks
    # ------------------------------------------------------------------

    def add_task(self, description: str, total: int = 100, **fields) -> object:
        """Add a progress task and return its id (or None in fallback mode)."""
        if RICH_AVAILABLE and self._progress is not None:
            default_fields = {"status": ""}
            default_fields.update(fields)
            return self._progress.add_task(  # type: ignore[union-attr]
                description, total=total, **default_fields
            )
        print(f"  → {description} …")
        return None

    def advance(self, task_id: object, amount: int = 1, status: str = "") -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            kwargs: Dict[str, object] = {"advance": amount}
            if status:
                kwargs["status"] = status
            self._progress.update(task_id, **kwargs)  # type: ignore[union-attr]

    def update_status(self, task_id: object, status: str) -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            self._progress.update(task_id, status=status)  # type: ignore[union-attr]

    def complete_task(self, task_id: object, status: str = "Done") -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            # Mark fully complete; the dashboard hides finished tasks to stay tidy.
            self._progress.update(  # type: ignore[union-attr]
                task_id, status=status, completed=True
            )

    # ------------------------------------------------------------------
    # Dashboard / phase state
    # ------------------------------------------------------------------

    def set_phase_status(self, phase: str, status: str, detail: str = "") -> None:
        """Update a phase's state; the live dashboard reflects it automatically."""
        self.phases.set(phase, status, detail)
        self.refresh_dashboard()

    def refresh_dashboard(self) -> None:
        """Repaint the live dashboard if active; quiet no-op otherwise."""
        if RICH_AVAILABLE and self._live is not None:
            try:
                self._live.refresh()  # type: ignore[union-attr]
            except Exception:  # pragma: no cover - defensive
                pass
        elif not RICH_AVAILABLE:
            # Without Rich there is no pinned surface; stay quiet to avoid spam.
            return

    # ------------------------------------------------------------------
    # Console output helpers (print above the live dashboard)
    # ------------------------------------------------------------------

    @staticmethod
    def print_info(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(Text.assemble(("  › ", C_CYAN), (msg, C_TEXT)))
        else:
            print(f"  INFO: {msg}")

    @staticmethod
    def print_success(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(Text.assemble(("  ✔ ", C_GREEN), (msg, C_TEXT)))
        else:
            print(f"  OK: {msg}")

    @staticmethod
    def print_warning(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(Text.assemble(("  ▲ ", C_AMBER), (msg, C_TEXT)))
        else:
            print(f"  WARN: {msg}")

    @staticmethod
    def print_error(msg: str) -> None:
        if RICH_AVAILABLE:
            console.print(Text.assemble(("  ✖ ", C_RED), (msg, f"bold {C_TEXT}")))
        else:
            print(f"  ERROR: {msg}")

    @staticmethod
    def print_phase(phase: str) -> None:
        if RICH_AVAILABLE:
            console.print(
                Rule(
                    Text(f" {phase} ", style=f"bold {C_GREEN}"),
                    style=C_LINE,
                    align="left",
                )
            )
        else:
            print(f"\n--- Phase: {phase} ---\n")

    def print_usage(self) -> None:
        """Show a compact CLI quick-reference card."""
        if not RICH_AVAILABLE:
            print(
                "BountyMind: bountymind -d DOMAIN | -l FILE | "
                "--bootstrap | --check-env | --help"
            )
            return

        usage = Table(
            show_header=False, box=box.SIMPLE, border_style=C_LINE, padding=(0, 2)
        )
        usage.add_column("cmd", style=f"bold {C_GREEN}", no_wrap=True)
        usage.add_column("desc", style=C_MUTED)
        for cmd, desc in [
            ("bountymind -d example.com", "scan a single domain"),
            ("bountymind -l targets.txt", "scan targets from a file"),
            ("bountymind --bootstrap", "install / update all tools"),
            ("bountymind --update", "self-update from GitHub"),
            ("bountymind --check-env", "verify the environment"),
            ("bountymind --help", "full option reference"),
        ]:
            usage.add_row(cmd, desc)
        console.print(
            Panel(
                usage,
                title=f"[bold {C_TEXT}]quick reference[/]",
                title_align="left",
                subtitle=f"[dim {C_DIM}]reports → output/reports/  ·  logs → logs/framework.log[/]",
                subtitle_align="right",
                border_style=C_LINE,
                box=box.ROUNDED,
                padding=(0, 1),
            )
        )

    @staticmethod
    def print_finding(severity: str, target: str, msg: str) -> None:
        """Print a single finding with severity-based colouring."""
        sev = severity.lower()
        colors = {
            "critical": C_RED,
            "high": C_ORANGE,
            "medium": C_AMBER,
            "low": C_CYAN,
            "info": C_MUTED,
        }
        color = colors.get(sev, C_TEXT)
        if RICH_AVAILABLE:
            line = Text()
            line.append("  ", style="")
            line.append(f" {severity.upper():8} ", style=f"bold {color} reverse")
            line.append("  ", style="")
            line.append(target, style=C_TEXT)
            line.append("  ", style="")
            line.append(msg, style=f"dim {C_MUTED}")
            console.print(line)
        else:
            print(f"  [{severity.upper():8}] {target}: {msg}")

    @staticmethod
    def print_summary_table(rows: list, headers: list, title: str = "") -> None:
        """Render a summary table."""
        if not RICH_AVAILABLE:
            if title:
                print(f"\n{title}")
            col_width = max((len(h) for h in headers), default=4) + 2
            print("  " + "  ".join(h.ljust(col_width) for h in headers))
            for row in rows:
                print("  " + "  ".join(str(c).ljust(col_width) for c in row))
            return

        table = Table(
            title=f"[bold {C_TEXT}]{title}[/]" if title else None,
            title_justify="left",
            show_header=True,
            header_style=f"bold {C_CYAN}",
            box=box.SIMPLE_HEAD,
            border_style=C_LINE,
            padding=(0, 1),
        )
        for h in headers:
            table.add_column(str(h))
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
