"""
modules/screenshots.py
-----------------------
ScreenshotModule: captures visual screenshots of live web interfaces
using gowitness for analyst triage and report inclusion.

Tool selection rationale:

- gowitness (go): Headless Chrome-based web screenshot utility.
  Designed for bulk screenshot capture of large URL lists.
  Source: https://github.com/sensepost/gowitness
  Classification: Open / Free

  Why gowitness:
  - Handles large URL lists efficiently.
  - Saves screenshots with URL-derived filenames for easy mapping.
  - Non-intrusive: only performs standard HTTP GET requests.
  - No JavaScript execution side-effects that would modify application state.

  Safety notes:
  - Screenshots are a passive visual observation only.
  - gowitness does NOT click buttons, submit forms, or interact with the app.
  - Results are saved locally and included in the HTML report.
  - max_hosts cap prevents unbounded screenshot sessions.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import LiveHost
from utils.output_helpers import OutputManager
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("screenshots")


class ScreenshotModule:
    """
    Captures screenshots of live web services using gowitness.
    Updates LiveHost.screenshot_path for each host that was captured.
    """

    def __init__(
        self,
        config: ConfigManager,
        output: OutputManager,
        runner: CommandRunner,
        progress: ProgressManager,
    ) -> None:
        self._cfg = config
        self._out = output
        self._runner = runner
        self._progress = progress

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self, live_hosts: List[LiveHost]) -> List[LiveHost]:
        """
        Capture screenshots of all live hosts.
        Returns the same list with screenshot_path populated where captured.
        """
        if not self._cfg.screenshots_enabled:
            log.info("Screenshots disabled in config; skipping")
            return live_hosts

        if not live_hosts:
            log.info("No live hosts to screenshot; skipping")
            return live_hosts

        binary = self._cfg.get_tool_binary("gowitness")
        if not self._runner.check_binary_available(binary):
            log.warning(
                "gowitness not found; skipping screenshots. "
                "Install: go install github.com/sensepost/gowitness@latest"
            )
            self._progress.print_warning(
                "gowitness not found — skipping visual reconnaissance. "
                "Install: go install github.com/sensepost/gowitness@latest"
            )
            return live_hosts

        self._progress.print_phase("Phase 2.5c — Visual Reconnaissance (Screenshots)")

        # Apply max_hosts cap
        max_hosts = self._cfg.screenshots_max_hosts
        hosts_to_capture = live_hosts[:max_hosts]
        if len(live_hosts) > max_hosts:
            log.warning(
                "Host count (%d) exceeds screenshots.max_hosts=%d; truncating",
                len(live_hosts), max_hosts,
            )

        # Write URL list
        url_list_path = self._out.base / "tmp_screenshot_urls.txt"
        url_list_path.write_text(
            "\n".join(h.url for h in hosts_to_capture if h.url),
            encoding="utf-8",
        )

        # Screenshot output directory
        screenshot_dir = self._out.base / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        task = self._progress.add_task(
            "[cyan]Screenshots", total=len(hosts_to_capture), status="capturing"
        )

        log.info(
            "Capturing screenshots for %d hosts → %s",
            len(hosts_to_capture), screenshot_dir,
        )

        result = self._runner.run(
            tool_name="gowitness",
            cmd=[
                binary, "scan", "file",
                "-f", str(url_list_path),
                "--screenshot-path", str(screenshot_dir),
                "--no-http",           # don't start the gowitness HTTP server
                "--threads", "3",      # conservative threading
            ],
            target="batch",
            timeout=self._cfg.screenshots_timeout,
            save_raw=False,
        )

        url_list_path.unlink(missing_ok=True)

        if result.return_code not in (0, 1):
            log.warning(
                "gowitness exited %d. Stderr: %s",
                result.return_code, result.stderr[:200],
            )

        # Map screenshots back to LiveHost records
        live_hosts = self._map_screenshots(live_hosts, screenshot_dir)
        captured = sum(1 for h in live_hosts if h.screenshot_path)

        self._progress.advance(task, amount=len(hosts_to_capture), status="done")
        self._progress.print_success(
            f"Screenshots captured: {captured}/{len(hosts_to_capture)} hosts"
        )
        log.info("Screenshot capture complete: %d captured", captured)
        return live_hosts

    # ------------------------------------------------------------------
    # Screenshot mapping
    # ------------------------------------------------------------------

    def _map_screenshots(
        self, live_hosts: List[LiveHost], screenshot_dir: Path
    ) -> List[LiveHost]:
        """
        Map generated screenshot files back to their corresponding LiveHost.
        gowitness names files using a URL-derived slug.
        """
        # Build a map of available screenshot filenames
        if not screenshot_dir.exists():
            return live_hosts

        png_files = {f.stem.lower(): f for f in screenshot_dir.glob("*.png")}

        for host in live_hosts:
            if not host.url:
                continue
            # gowitness uses a sanitized form of the URL as the filename
            slug = self._url_to_slug(host.url)
            # Try exact match, then prefix match
            matched_path = None
            if slug in png_files:
                matched_path = png_files[slug]
            else:
                for stem, path in png_files.items():
                    if slug[:30] in stem or stem[:30] in slug:
                        matched_path = path
                        break

            if matched_path:
                host.screenshot_path = str(matched_path)

        return live_hosts

    @staticmethod
    def _url_to_slug(url: str) -> str:
        """
        Convert a URL to a slug matching gowitness's file naming convention.
        gowitness replaces special chars with underscores or dashes.
        """
        import re
        slug = url.lower()
        for prefix in ("https://", "http://"):
            if slug.startswith(prefix):
                slug = slug[len(prefix):]
        slug = re.sub(r"[^a-z0-9]", "_", slug).strip("_")
        return slug[:100]
