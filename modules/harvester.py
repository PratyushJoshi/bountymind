"""
modules/harvester.py
--------------------
URLHarvester: collects URLs from passive sources and active crawling
to build a rich endpoint surface for JS secret mining and scanning.

Tool selection rationale:

- gau (go): GetAllURLs — queries AlienVault OTX, Wayback Machine,
  CommonCrawl, and URLScan.io passively. No API key needed for basic use.
  Source: https://github.com/lc/gau
  Classification: Open / Free

- waybackurls (go): Fetches URLs archived in the Wayback Machine.
  Source: https://github.com/tomnomnom/waybackurls
  Classification: Open / Free

- katana (go): ProjectDiscovery's modern web crawler. Supports JS rendering,
  passive endpoint extraction, and configurable depth. Used at shallow depth
  (default 3) to stay non-intrusive.
  Source: https://github.com/projectdiscovery/katana
  Classification: Open / Free

Safety notes:
- gau and waybackurls are purely passive (no direct requests to target).
- katana performs active crawling but stays within configured depth.
- Collected URLs feed into JS secret scanning only — not submitted anywhere.
"""

from __future__ import annotations

import os
import re
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Set

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import HarvestedURL
from utils.output_helpers import OutputManager, parse_line_delimited
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("harvester")

# Patterns that flag a URL as interesting (worth including in JS scan / reporting)
INTERESTING_URL_PATTERNS = re.compile(
    r"(api|v\d+|graphql|swagger|openapi|auth|login|oauth|token|secret|"
    r"config|admin|upload|download|export|import|webhook|callback|"
    r"redirect|reset|verify|confirm|invite|payment|checkout|\.env|"
    r"\.git|backup|dump|debug|internal|private|preview)",
    re.IGNORECASE,
)


class URLHarvester:
    """
    Harvests URLs from passive and active sources, deduplicates them,
    and flags JS files and interesting endpoints for downstream scanning.
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

    def run(self, targets: List[str], live_urls: List[str]) -> List[HarvestedURL]:
        """
        Harvest URLs for all targets.

        Args:
            targets:   Root domain list (for passive sources).
            live_urls: Confirmed live URLs (for katana crawling).

        Returns:
            Deduplicated list of HarvestedURL records.
        """
        if not self._cfg.harvesting_enabled:
            log.info("URL harvesting disabled in config; skipping")
            return []

        self._progress.print_phase("Phase 1.5 — URL Harvesting & Surface Mapping")
        all_urls: Set[str] = set()
        source_map: dict = {}  # url → source

        task = self._progress.add_task(
            "[cyan]URL Harvesting", total=len(targets) + 1, status="starting"
        )

        # Passive sources per target domain
        for domain in targets:
            self._progress.update_status(task, f"passive={domain}")

            if self._cfg.is_tool_enabled("gau"):
                gau_urls = self._run_gau(domain)
                for u in gau_urls:
                    all_urls.add(u)
                    source_map[u] = "gau"
                log.debug("gau: %d URLs for %s", len(gau_urls), domain)

            if self._cfg.is_tool_enabled("waybackurls"):
                wb_urls = self._run_waybackurls(domain)
                for u in wb_urls:
                    all_urls.add(u)
                    if u not in source_map:
                        source_map[u] = "waybackurls"
                log.debug("waybackurls: %d URLs for %s", len(wb_urls), domain)

            self._progress.advance(task, status=f"{len(all_urls)} urls")

        # Active crawling on live hosts
        if self._cfg.is_tool_enabled("katana") and live_urls:
            self._progress.update_status(task, "crawling live hosts")
            katana_urls = self._run_katana(live_urls)
            for u in katana_urls:
                all_urls.add(u)
                if u not in source_map:
                    source_map[u] = "katana"
            log.debug("katana: %d URLs discovered", len(katana_urls))

        self._progress.advance(task, status="processing")

        # Apply safety cap
        max_urls = self._cfg.harvesting_max_urls
        url_list = list(all_urls)
        if len(url_list) > max_urls:
            log.warning(
                "Harvested URL count (%d) exceeds max_urls_per_target=%d; truncating",
                len(url_list), max_urls,
            )
            url_list = url_list[:max_urls]

        # Build HarvestedURL records
        records = self._build_records(url_list, source_map)
        js_count = sum(1 for r in records if r.is_js)
        interesting_count = sum(1 for r in records if r.is_interesting)

        self._save_results(records)
        self._progress.print_success(
            f"URL harvesting complete — {len(records)} URLs "
            f"({js_count} JS files, {interesting_count} interesting endpoints)"
        )
        log.info(
            "URL harvesting complete: total=%d js=%d interesting=%d",
            len(records), js_count, interesting_count,
        )
        return records

    def get_js_urls(self, harvested: List[HarvestedURL]) -> List[str]:
        """Return deduplicated list of JS file URLs from harvested results."""
        return list({r.url for r in harvested if r.is_js})

    def collect_js_urls(self, target) -> List[str]:
        """Collect JS URLs from a scan session (alias used by PrototypePollutionScanner)."""
        urls = self.get_js_urls(getattr(target, "harvested_urls", []) or [])
        for host in getattr(target, "live_hosts", []) or []:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            if url and url.lower().endswith(".js"):
                urls.append(url)
        return list(dict.fromkeys(urls))

    # ------------------------------------------------------------------
    # Tool runners
    # ------------------------------------------------------------------

    def _run_gau(self, domain: str) -> List[str]:
        """
        Run gau for passive URL collection.
        Queries Wayback Machine, AlienVault OTX, CommonCrawl, URLScan.
        """
        binary = self._cfg.get_tool_binary("gau")
        out_file = self._out.raw_path("gau", domain, "txt")

        result = self._runner.run(
            tool_name="gau",
            cmd=[binary, "--o", str(out_file), "--threads", "5", domain],
            target=domain,
            timeout=120,
            save_raw=False,
        )

        if out_file.exists():
            return parse_line_delimited(out_file.read_text(encoding="utf-8"))
        return parse_line_delimited(result.stdout)

    def _run_waybackurls(self, domain: str) -> List[str]:
        """
        Run waybackurls for Wayback Machine URL collection.
        Simple stdin-driven tool — pipe domain to binary.
        """
        binary = self._cfg.get_tool_binary("waybackurls")

        import subprocess
        try:
            self._runner._ensure_pipx_path()
            proc = subprocess.run(
                [binary, domain],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return parse_line_delimited(proc.stdout)
        except Exception as exc:
            log.debug("waybackurls failed for %s: %s", domain, exc)
            return []

    def _run_katana(self, live_urls: List[str]) -> List[str]:
        """
        Run katana web crawler on live hosts.

        Why katana: Modern crawler with JS rendering, scope control,
        and structured output. Replaces older spider tools.

        Safety: Depth limited to config.katana_depth (default 3).
        No form submission, no authentication, no POST requests.
        """
        binary = self._cfg.get_tool_binary("katana")
        depth = self._cfg.katana_depth
        js_crawl = self._cfg.katana_js_crawl

        # Write URL list to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".txt", encoding="utf-8"
        ) as f:
            f.write("\n".join(live_urls))
            url_file = f.name

        out_file = self._out.raw_path("katana", "batch", "txt")

        cmd = [
            binary,
            "-list", url_file,
            "-depth", str(depth),
            "-silent",
            "-o", str(out_file),
            "-no-color",
            "-field", "url",
        ]
        if js_crawl:
            cmd += ["-jc", "-jsl"]

        result = self._runner.run(
            tool_name="katana",
            cmd=cmd,
            target="batch",
            timeout=self._cfg.tool_timeout,
            save_raw=False,
        )

        try:
            os.unlink(url_file)
        except OSError:
            pass

        if out_file.exists():
            return parse_line_delimited(out_file.read_text(encoding="utf-8"))
        return parse_line_delimited(result.stdout)

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def _build_records(
        self, urls: List[str], source_map: dict
    ) -> List[HarvestedURL]:
        records = []
        for url in urls:
            url = url.strip()
            if not url:
                continue
            is_js = url.lower().endswith(".js") or ".js?" in url.lower()
            is_interesting = bool(INTERESTING_URL_PATTERNS.search(url))
            records.append(HarvestedURL(
                url=url,
                source=source_map.get(url, "unknown"),
                is_js=is_js,
                is_interesting=is_interesting,
            ))
        return records

    def _save_results(self, records: List[HarvestedURL]) -> None:
        self._out.save_parsed("harvester", "harvested_urls", [
            {
                "url": r.url,
                "source": r.source,
                "is_js": r.is_js,
                "is_interesting": r.is_interesting,
            }
            for r in records
        ])
