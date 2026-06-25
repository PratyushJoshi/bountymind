"""
utils/progress.py
-----------------
BountyMind terminal UI — professional hacker-grade dashboard.

Renders cleanly on every shell:
  · bash / zsh  (Kali, Ubuntu, macOS)       — full 24-bit color + Unicode
  · Windows Terminal / modern PowerShell     — full ANSI + Unicode
  · Legacy CMD / old PowerShell (no ANSI)   — ASCII-only, auto-detected
  · Rich not installed                       — plain timestamped text

Log-line convention (same as Metasploit / Impacket):
  [HH:MM:SS] [*]  informational
  [HH:MM:SS] [+]  success / result
  [HH:MM:SS] [!]  warning / non-fatal
  [HH:MM:SS] [-]  error / fatal

Public API (stable — all other modules depend on this interface):
    render_banner()
    console                       (module-level Rich Console or plain shim)
    ProgressManager:
        session(title)            context manager wrapping one scan session
        add_task(desc, total)     → opaque task id
        advance(tid, amount, status)
        update_status(tid, status)
        complete_task(tid, status)
        set_phase_status(phase, status, detail)
        refresh_dashboard()
        print_info / print_success / print_warning / print_error
        print_phase / print_usage / print_finding / print_summary_table
        phases                    → PhaseTracker instance
"""

from __future__ import annotations

import datetime
import os
import re
import time
from contextlib import contextmanager
from typing import Dict, Generator, List, Optional, Tuple

try:
    from rich import box
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
except ImportError:  # pragma: no cover
    RICH_AVAILABLE = False


APP_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Colour palette  (one place to tune everything)
# ---------------------------------------------------------------------------
C_GREEN  = "#30d158"   # primary accent  — hacker green
C_CYAN   = "#64d2ff"   # secondary accent — electric cyan
C_AMBER  = "#ffd60a"   # warning / in-progress
C_ORANGE = "#ff9f0a"   # high severity
C_RED    = "#ff453a"   # critical / error
C_TEXT   = "#e5e5ea"   # main foreground
C_MUTED  = "#8e8e93"   # secondary text
C_DIM    = "#636366"   # dim / placeholders
C_LINE   = "#3a3a3c"   # panel borders / rule lines

# Braille spinner animation — synced to wall clock, no state needed
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# ---------------------------------------------------------------------------
# Console — auto-detects terminal capabilities at import time
# ---------------------------------------------------------------------------

if RICH_AVAILABLE:
    from rich.theme import Theme

    _THEME = Theme({
        "info":             C_CYAN,
        "ok":               C_GREEN,
        "warn":             C_AMBER,
        "err":              C_RED,
        "finding.critical": f"bold {C_RED}",
        "finding.high":     C_ORANGE,
        "finding.medium":   C_AMBER,
        "finding.low":      C_CYAN,
        "finding.info":     f"dim {C_MUTED}",
    })

    console = Console(theme=_THEME, highlight=False)

    # Pick box style: Unicode rounded corners on color-capable terminals;
    # pure-ASCII fallback on legacy CMD / redirected / dumb terminals.
    _HAS_COLOR = getattr(console, "color_system", None) is not None
    _BOX       = box.ROUNDED if _HAS_COLOR else box.ASCII
    _BOX_TABLE = box.SIMPLE_HEAD

else:
    class _FallbackConsole:  # type: ignore[no-redef]
        """Minimal shim so the rest of the code can always call console.print()."""
        def print(self, *args, **kwargs) -> None:
            print(" ".join(str(a) for a in args))
        def rule(self, title: str = "", **kwargs) -> None:
            print(f"\n{'─' * 20}  {title}  {'─' * 20}\n")
        def log(self, *args, **kwargs) -> None:
            print(*args)

    console    = _FallbackConsole()  # type: ignore[assignment]
    _HAS_COLOR = False
    _BOX       = None
    _BOX_TABLE = None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    """Wall-clock timestamp for log prefixes, e.g. ``[15:23:41]``."""
    return datetime.datetime.now().strftime("[%H:%M:%S]")


def _fmt_secs(secs: int) -> str:
    """Human-readable elapsed duration."""
    if secs >= 3600:
        return f"{secs // 3600}h{(secs % 3600) // 60:02d}m"
    if secs >= 60:
        return f"{secs // 60}m{secs % 60:02d}s"
    return f"{secs}s"


def _strip_markup(s: str) -> str:
    """Remove Rich markup tags (e.g. ``[cyan]``) from a string."""
    return re.sub(r"\[/?[^\]]*\]", "", s)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def render_banner() -> None:
    """
    Compact operational header.  Works on every shell without degrading.

    Rich terminal:
        ╭── BOUNTYMIND v2.1.0 ────────────────────────────────────────────╮
        │  Automated Reconnaissance · Vulnerability Assessment · Evasion  │
        │  ▸ authorized targets only    ▸ unauthenticated · safe-mode     │
        ╰─────────────────────────────────────────────────────────────────╯

    Plain terminal:
        ──────────────────────────────────────────────
        BOUNTYMIND  v2.1.0
        Automated Reconnaissance & Vulnerability Assessment
        Use only against authorized targets
        ──────────────────────────────────────────────
    """
    if not RICH_AVAILABLE:
        sep = "─" * 56
        print(f"\n  {sep}")
        print(f"  BOUNTYMIND  v{APP_VERSION}")
        print("  Automated Reconnaissance & Vulnerability Assessment")
        print("  Use only against authorized targets")
        print(f"  {sep}\n")
        return

    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M")

    wordmark = Text()
    wordmark.append("BOUNTY", style=f"bold {C_GREEN}")
    wordmark.append("MIND",   style=f"bold {C_CYAN}")
    wordmark.append(f"  v{APP_VERSION}", style=f"dim {C_DIM}")
    wordmark.append(f"   ─   {now}",    style=f"dim {C_DIM}")

    tagline = Text(
        "Automated Reconnaissance · Vulnerability Assessment · WAF Evasion",
        style=C_MUTED,
    )

    chips = Text()
    chips.append("▸ ", style=C_GREEN)
    chips.append("authorized targets only     ", style=C_DIM)
    chips.append("▸ ", style=C_CYAN)
    chips.append("unauthenticated  ·  safe-mode", style=C_DIM)

    console.print(
        Panel(
            Group(wordmark, tagline, Text(""), chips),
            border_style=C_GREEN,
            box=_BOX,
            padding=(0, 3),
        )
    )


# ---------------------------------------------------------------------------
# Phase tracking
# ---------------------------------------------------------------------------

class PhaseTracker:
    """
    Tracks state, detail text, and wall-clock timing for every scan phase.

    Phase states: pending → running → done | error | skipped
    """

    PHASES: List[Tuple[str, str]] = [
        ("bootstrap",   "Tool Bootstrap"),
        ("discovery",   "Subdomain Discovery"),
        ("probing",     "HTTP Probing & Ports"),
        ("harvest",     "URL Harvesting"),
        ("scanning",    "Vulnerability Scanning"),
        ("secrets",     "JS Secret Mining"),
        ("cloud",       "Cloud Bucket Recon"),
        ("screenshots", "Visual Screenshots"),
        ("waf",         "WAF Detection & Evasion"),
        ("deep-scans",  "Deep Detection Scans"),
        ("reporting",   "Report Generation"),
    ]

    # (marker-char, colour) keyed by status
    # Markers are chosen to be legible in every terminal font.
    _MARKER: Dict[str, Tuple[str, str]] = {
        "pending": ("·",  C_DIM),
        "running": ("◆",  C_AMBER),  # overridden with spinner frame when live
        "done":    ("✓",  C_GREEN),
        "skipped": ("─",  C_DIM),
        "error":   ("✗",  C_RED),
    }

    def __init__(self) -> None:
        self._states: Dict[str, Dict] = {
            name: {
                "label":   label,
                "status":  "pending",
                "detail":  "",
                "started": None,
                "ended":   None,
            }
            for name, label in self.PHASES
        }

    def set(self, phase: str, status: str, detail: str = "") -> None:
        st = self._states.get(phase)
        if st is None:
            return
        now  = time.monotonic()
        prev = st["status"]
        if status == "running" and prev != "running":
            st["started"] = now
            st["ended"]   = None
        elif status in ("done", "error", "skipped"):
            if st["started"] is None and status != "skipped":
                st["started"] = now
            st["ended"] = now
        st["status"] = status
        if detail:
            st["detail"] = detail

    def _elapsed(self, st: Dict) -> str:
        start = st["started"]
        if start is None:
            return ""
        end = st["ended"] if st["ended"] is not None else time.monotonic()
        return _fmt_secs(max(0, int(end - start)))  # type: ignore[operator]

    def counts(self) -> Tuple[int, int, int]:
        """(done, active_phases, errors) — used in the dashboard subtitle."""
        done   = sum(1 for s in self._states.values() if s["status"] == "done")
        errors = sum(1 for s in self._states.values() if s["status"] == "error")
        active = sum(1 for s in self._states.values() if s["status"] != "skipped")
        return done, active, errors

    # -- plain-text render (no Rich) ----------------------------------------

    def render_plain(self) -> str:
        lines = []
        for st in self._states.values():
            marker, _ = self._MARKER.get(str(st["status"]), ("?", ""))
            detail = f"  {st['detail']}" if st["detail"] else ""
            dur    = f"  {self._elapsed(st)}" if self._elapsed(st) else ""
            lines.append(
                f"  {marker}  {str(st['label']):<28} {str(st['status']):<9}{detail}{dur}"
            )
        return "\n".join(lines)

    # -- Rich table render (embedded inside the live panel) -----------------

    def render_table(self, spinner_frame: str = "") -> "Table":
        """
        Tight ops table — no outer border, just a flat list of phase rows.

        Layout:
          marker  Phase Name               result detail           time
          ──────────────────────────────────────────────────────────────
          ✓       Tool Bootstrap           12 tools verified       0:04
          ⠸       Vulnerability Scanning   CVE-2024-xxxx           3:09
          ·       JS Secret Mining
        """
        status_style: Dict[str, str] = {
            "pending": C_DIM,
            "running": f"bold {C_AMBER}",
            "done":    f"{C_GREEN}",
            "skipped": f"dim {C_DIM}",
            "error":   f"bold {C_RED}",
        }

        table = Table(
            show_header=False,
            box=None,           # no outer border — panel provides that
            padding=(0, 1),
            expand=True,
        )
        table.add_column("m",      width=2,   no_wrap=True)
        table.add_column("label",             no_wrap=True, ratio=3)
        table.add_column("detail",            overflow="ellipsis", ratio=5)
        table.add_column("time",   width=7,   no_wrap=True, justify="right")

        for st in self._states.values():
            status = str(st["status"])
            style  = status_style.get(status, "white")
            marker, mcol = self._MARKER.get(status, ("·", C_DIM))
            if status == "running":
                marker = spinner_frame or "◆"

            # Dim everything that hasn't started yet so running/done stand out
            label_style = style if status in ("running", "done", "error") else C_DIM

            table.add_row(
                Text(marker, style=mcol),
                Text(str(st["label"]), style=label_style),
                Text(str(st["detail"])[:72], style=C_DIM if status != "running" else C_MUTED),
                Text(self._elapsed(st), style=C_DIM),
            )

        return table


# ---------------------------------------------------------------------------
# Live dashboard renderable
# ---------------------------------------------------------------------------

if RICH_AVAILABLE:

    class _Dashboard:
        """
        Self-refreshing renderable composed from:
          · Panel title/subtitle  — session target, phase count, elapsed
          · Phase ops-table       — all 11 phases with state + detail + time
          · Separator + progress  — only rendered when a task is in flight

        Rich calls ``__rich_console__`` on every Live refresh tick (~10 Hz),
        so spinner frames and elapsed times update without manual repainting.
        """

        def __init__(self, manager: "ProgressManager") -> None:
            self._m = manager

        def __rich_console__(self, console, options):  # noqa: ANN001
            m     = self._m
            frame = _SPINNER[int(time.monotonic() * 10) % len(_SPINNER)]

            done, active, errors = m.phases.counts()

            # ── subtitle (right side of panel border) ────────────────────
            subtitle = Text()
            subtitle.append(f"{done}", style=f"bold {C_GREEN}")
            subtitle.append(f"/{active} phases", style=C_MUTED)
            if errors:
                subtitle.append(f"   {errors} err", style=f"bold {C_RED}")
            if m._session_start is not None:
                secs = int(time.monotonic() - m._session_start)
                subtitle.append(f"   {_fmt_secs(secs)} ", style=C_DIM)

            # ── panel title (left side) ───────────────────────────────────
            if m._target:
                title_text = (
                    f"[bold {C_GREEN}]◆ BOUNTYMIND[/]"
                    f"  [dim {C_DIM}]▸[/]"
                    f"  [{C_TEXT}]{m._target}[/]"
                )
            else:
                title_text = f"[bold {C_GREEN}]◆ BOUNTYMIND[/]"

            # ── hide completed tasks; collect in-flight ones ─────────────
            # This is the critical fix: without hiding finished tasks,
            # the Progress widget accumulates one bar per phase and grows
            # taller than the terminal, causing Rich to re-emit the whole
            # frame each tick — producing the duplicated scrolling bars.
            live_tasks = []
            for t in m._progress.tasks:  # type: ignore[union-attr]
                if t.finished:
                    if t.visible:
                        m._progress.update(t.id, visible=False)  # type: ignore[union-attr]
                elif t.visible:
                    live_tasks.append(t)

            # ── compose renderables ──────────────────────────────────────
            parts: List[RenderableType] = [m.phases.render_table(frame)]
            if live_tasks:
                parts.append(Rule(style=C_LINE))
                parts.append(m._progress)  # type: ignore[arg-type]

            yield Panel(
                Group(*parts),
                title=title_text,
                title_align="left",
                subtitle=subtitle,
                subtitle_align="right",
                border_style=C_LINE,
                box=_BOX,
                padding=(0, 1),
            )


# ---------------------------------------------------------------------------
# ProgressManager — the single object every module imports and calls
# ---------------------------------------------------------------------------

class ProgressManager:
    """
    Owns the live scan dashboard, phase tracker, and all console helpers.

    All ``print_*`` methods emit timestamped lines *above* the live panel
    so the operator log scrolls naturally while the dashboard stays pinned.
    """

    def __init__(self) -> None:
        self.phases          = PhaseTracker()
        self._live:          Optional[object] = None
        self._session_start: Optional[float]  = None
        self._target:        str              = ""
        self._progress:      Optional[object] = None

        if RICH_AVAILABLE:
            self._progress = Progress(
                SpinnerColumn(spinner_name="dots", style=C_GREEN),
                # Strip any Rich markup modules embed in descriptions
                # (e.g. "[cyan]Discovery") so the bar shows plain text.
                TextColumn(f"[{C_TEXT}]{{task.description}}"),
                BarColumn(
                    bar_width=26,
                    complete_style=C_GREEN,
                    finished_style=C_GREEN,
                    pulse_style="#1c4228",
                ),
                MofNCompleteColumn(),
                TextColumn(f"[dim {C_DIM}]{{task.fields[status]}}"),
                TimeElapsedColumn(),
                console=console,
                transient=False,
                # The session Live owns all repainting; disable the Progress
                # widget's own refresh to prevent re-entrant render calls.
                auto_refresh=False,
            )

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    @contextmanager
    def session(self, title: str = "BountyMind") -> Generator[None, None, None]:
        """
        Context manager that starts the live dashboard for one scan.

        Usage::

            with pm.session("BountyMind — example.com"):
                # run phases here
        """
        self._target        = title.replace("BountyMind — ", "").strip()
        self._session_start = time.monotonic()

        if RICH_AVAILABLE and self._progress is not None:
            self._live = Live(
                _Dashboard(self),
                console=console,
                refresh_per_second=10,
                transient=False,
                # Clip to viewport: a safety net for small terminals.
                # The dashboard is bounded (fixed phase table + at most
                # one task bar) so this never loses meaningful output.
                vertical_overflow="crop",
            )
            self._live.start()  # type: ignore[union-attr]
            try:
                yield
            finally:
                try:
                    self._live.refresh()  # type: ignore[union-attr]
                finally:
                    self._live.stop()  # type: ignore[union-attr]
                    self._live = None

            # ── completion footer ─────────────────────────────────────
            secs           = int(time.monotonic() - (self._session_start or 0))
            dur            = _fmt_secs(secs)
            done, active, errors = self.phases.counts()
            foot           = Text()
            foot.append(" SCAN COMPLETE ", style=f"bold reverse {C_GREEN}")
            foot.append(f"   {self._target}   ", style=f"bold {C_TEXT}")
            foot.append(f"{done}/{active} phases", style=C_MUTED)
            if errors:
                foot.append(f"   {errors} error(s)", style=f"bold {C_RED}")
            foot.append(f"   {dur}", style=C_MUTED)
            console.print(
                Panel(foot, border_style=C_GREEN, box=_BOX, padding=(0, 2))
            )

        else:
            # ── plain-text fallback ───────────────────────────────────
            sep    = "═" * 60
            target = title.replace("BountyMind — ", "").strip()
            start  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n  {sep}")
            print(f"  TARGET  : {target}")
            print(f"  STARTED : {start}")
            print(f"  {sep}\n")
            yield
            secs = int(time.monotonic() - (self._session_start or 0))
            print(f"\n  {sep}")
            print(f"  SCAN COMPLETE  ·  {_fmt_secs(secs)}")
            print(f"  {sep}\n")

    # ------------------------------------------------------------------
    # Progress tasks
    # ------------------------------------------------------------------

    def add_task(self, description: str, total: int = 100, **fields) -> object:
        """Add a progress task and return an opaque task id."""
        if RICH_AVAILABLE and self._progress is not None:
            kw = {"status": ""}
            kw.update(fields)
            return self._progress.add_task(  # type: ignore[union-attr]
                description, total=total, **kw
            )
        plain = _strip_markup(description)
        print(f"  {_ts()} [*] {plain} …")
        return None

    def advance(self, task_id: object, amount: int = 1, status: str = "") -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            kw: Dict[str, object] = {"advance": amount}
            if status:
                kw["status"] = status
            self._progress.update(task_id, **kw)  # type: ignore[union-attr]

    def update_status(self, task_id: object, status: str) -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            self._progress.update(task_id, status=status)  # type: ignore[union-attr]

    def complete_task(self, task_id: object, status: str = "Done") -> None:
        if RICH_AVAILABLE and self._progress is not None and task_id is not None:
            # Snap bar to 100 % then immediately hide it so the dashboard
            # stays compact — only in-flight tasks should be visible.
            task = next(
                (t for t in self._progress.tasks  # type: ignore[union-attr]
                 if t.id == task_id), None
            )
            if task is not None and task.total is not None:
                self._progress.update(task_id, completed=task.total)  # type: ignore[union-attr]
            self._progress.update(task_id, status=status, visible=False)  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Phase state / dashboard
    # ------------------------------------------------------------------

    def set_phase_status(self, phase: str, status: str, detail: str = "") -> None:
        """Update a phase; the live dashboard reflects it automatically."""
        self.phases.set(phase, status, detail)
        self.refresh_dashboard()

    def refresh_dashboard(self) -> None:
        """Repaint the live panel; quiet no-op when no session is active."""
        if RICH_AVAILABLE and self._live is not None:
            try:
                self._live.refresh()  # type: ignore[union-attr]
            except Exception:  # pragma: no cover
                pass

    # ------------------------------------------------------------------
    # Console output helpers
    # All print_* methods include a wall-clock timestamp and a
    # Metasploit-style prefix so the operator log is always readable.
    # Lines are emitted *above* the live panel — they scroll, the panel
    # stays pinned.
    # ------------------------------------------------------------------

    @staticmethod
    def print_info(msg: str) -> None:
        ts = _ts()
        if RICH_AVAILABLE:
            line = Text()
            line.append(f"  {ts} ", style=f"dim {C_DIM}")
            line.append("[*]", style=f"bold {C_CYAN}")
            line.append(f" {msg}", style=C_TEXT)
            console.print(line)
        else:
            print(f"  {ts} [*] {msg}")

    @staticmethod
    def print_success(msg: str) -> None:
        ts = _ts()
        if RICH_AVAILABLE:
            line = Text()
            line.append(f"  {ts} ", style=f"dim {C_DIM}")
            line.append("[+]", style=f"bold {C_GREEN}")
            line.append(f" {msg}", style=C_TEXT)
            console.print(line)
        else:
            print(f"  {ts} [+] {msg}")

    @staticmethod
    def print_warning(msg: str) -> None:
        ts = _ts()
        if RICH_AVAILABLE:
            line = Text()
            line.append(f"  {ts} ", style=f"dim {C_DIM}")
            line.append("[!]", style=f"bold {C_AMBER}")
            line.append(f" {msg}", style=C_TEXT)
            console.print(line)
        else:
            print(f"  {ts} [!] {msg}")

    @staticmethod
    def print_error(msg: str) -> None:
        ts = _ts()
        if RICH_AVAILABLE:
            line = Text()
            line.append(f"  {ts} ", style=f"dim {C_DIM}")
            line.append("[-]", style=f"bold {C_RED}")
            line.append(f" {msg}", style=f"bold {C_TEXT}")
            console.print(line)
        else:
            print(f"  {ts} [-] {msg}")

    @staticmethod
    def print_phase(phase: str) -> None:
        """Section divider — emitted before each major phase begins."""
        if RICH_AVAILABLE:
            console.print(
                Rule(
                    Text(f" {phase.upper()} ", style=f"bold {C_GREEN}"),
                    style=C_LINE,
                    align="left",
                )
            )
        else:
            sep = "─" * 60
            print(f"\n  {sep}\n  {phase.upper()}\n  {sep}\n")

    def print_usage(self) -> None:
        """Quick-reference card printed immediately after the banner."""
        if not RICH_AVAILABLE:
            print(
                "  Usage: bountymind -d DOMAIN | -l FILE | "
                "--bootstrap | --check-env | --help"
            )
            return

        cmds = [
            ("bountymind -d example.com",   "scan a single domain"),
            ("bountymind -l targets.txt",   "scan targets from a file"),
            ("bountymind --bootstrap",      "install / update all tools"),
            ("bountymind --update",         "self-update from GitHub"),
            ("bountymind --check-env",      "verify tool environment"),
            ("bountymind --help",           "full option reference"),
        ]

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("cmd",  style=f"bold {C_GREEN}", no_wrap=True)
        table.add_column("sep",  style=C_DIM, width=1, no_wrap=True)
        table.add_column("desc", style=C_MUTED)
        for cmd, desc in cmds:
            table.add_row(cmd, "─", desc)

        console.print(
            Panel(
                table,
                title=f"[bold {C_TEXT}]quick reference[/]",
                title_align="left",
                subtitle=(
                    f"[dim {C_DIM}]reports → output/reports/"
                    f"   logs → logs/framework.log[/]"
                ),
                subtitle_align="right",
                border_style=C_LINE,
                box=_BOX,
                padding=(0, 2),
            )
        )

    @staticmethod
    def print_finding(severity: str, target: str, msg: str) -> None:
        """
        Emit a single finding.

        Rich output:
          [15:27:09] [CRITICAL]  admin.example.com  SQL Injection — /api/users
          [15:27:11] [HIGH    ]  api.example.com    Hardcoded JWT secret in app.js
        """
        sev = severity.lower()
        color_map: Dict[str, str] = {
            "critical": C_RED,
            "high":     C_ORANGE,
            "medium":   C_AMBER,
            "low":      C_CYAN,
            "info":     C_MUTED,
        }
        color = color_map.get(sev, C_TEXT)
        ts    = _ts()
        badge = f"[{severity.upper():<8}]"

        if RICH_AVAILABLE:
            line = Text()
            line.append(f"  {ts} ", style=f"dim {C_DIM}")
            line.append(badge,   style=f"bold {color}")
            line.append("  ",    style="")
            line.append(f"{target}", style=f"bold {C_TEXT}")
            line.append("  ",    style="")
            line.append(msg,     style=C_MUTED)
            console.print(line)
        else:
            print(f"  {ts}  {badge}  {target}  {msg}")

    @staticmethod
    def print_summary_table(rows: list, headers: list, title: str = "") -> None:
        """
        Render an aligned tabular summary (tool status, scan totals, etc.).
        """
        if not RICH_AVAILABLE:
            if title:
                print(f"\n  {title}")
                print(f"  {'─' * max(40, len(title) + 4)}")
            w = max((len(h) for h in headers), default=4) + 2
            print("  " + "  ".join(h.ljust(w) for h in headers))
            for row in rows:
                print("  " + "  ".join(str(c).ljust(w) for c in row))
            return

        table = Table(
            title=f"[bold {C_TEXT}]{title}[/]" if title else None,
            title_justify="left",
            show_header=True,
            header_style=f"bold {C_CYAN}",
            box=_BOX_TABLE,
            border_style=C_LINE,
            padding=(0, 2),
        )
        for h in headers:
            table.add_column(str(h))
        for row in rows:
            table.add_row(*[str(c) for c in row])
        console.print(table)
