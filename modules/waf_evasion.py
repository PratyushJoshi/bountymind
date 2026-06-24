"""
modules/waf_evasion.py
----------------------
WAFEvasion: Web Application Firewall detection and non-intrusive evasion probing.

Tools:
- wafw00f  — passive WAF fingerprinting on live URLs
- nuclei   — waf-bypass profile (detection-only templates)
- ffuf     — directory discovery with evasion headers/delays
- arjun    — passive HTTP parameter discovery
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import EvasionFinding, LiveHost, ScanSession
from utils.output_helpers import OutputManager
from utils.progress import ProgressManager
from utils.runner import CommandRunner
from utils.wordlists import get_wordlist

log = get_logger("waf_evasion")

# Bundled wordlist for WAF evasion directory fuzzing
COMMON_DIRS = Path(get_wordlist("directories", "config/common_dirs.txt"))


class WAFEvasion:
    """Detect WAFs on live endpoints and run evasion-oriented discovery scans."""

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

    def run(self, session: ScanSession, targets: List[str]) -> None:
        """Run WAF detection then evasion scans against the session."""
        primary_domain = targets[0] if targets else "target"
        self.detect_waf(session, primary_domain)
        self.run_evasion_scans(session, primary_domain)

    def detect_waf(self, session: ScanSession, domain: str) -> None:
        """Run wafw00f on live URLs and store WAF names."""
        self._progress.print_phase("WAF Detection")
        log.info("Detecting Web Application Firewalls...")

        if not shutil.which("wafw00f"):
            msg = "wafw00f not installed. Skipping WAF detection."
            log.warning(msg)
            self._progress.print_warning(msg)
            return

        urls = [h.url for h in session.live_hosts if h.url]
        if not urls:
            log.info("No live URLs for WAF detection")
            return

        task = self._progress.add_task("WAF detection (wafw00f)", total=len(urls))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_list = f.name

        try:
            result = self._runner.run(
                tool_name="wafw00f",
                cmd=["wafw00f", "-i", url_list, "-v", "-o", "-"],
                target=domain,
                timeout=120,
                save_raw=True,
                check_exists=False,
            )
            out = result.stdout or result.stderr
            if out:
                self._parse_wafw00f_output(out, session)
        finally:
            os.unlink(url_list)

        self._progress.complete_task(task, f"{len(session.waf_detections)} WAF(s)")
        self._progress.print_success(
            f"WAF detection complete. {len(session.waf_detections)} protected endpoint(s) found."
        )
        log.info(
            "WAF detection complete. %d protected endpoints found.",
            len(session.waf_detections),
        )

    def _parse_wafw00f_output(self, out: str, session: ScanSession) -> None:
        current_url: Optional[str] = None
        for line in out.splitlines():
            if line.startswith("Checking"):
                parts = line.split()
                if len(parts) > 1:
                    current_url = parts[1].strip()
            elif "is behind" in line and current_url:
                waf_name = line.split("is behind")[1].strip().split(".")[0]
                session.waf_detections[current_url] = waf_name
                # Enrich live host records
                for host in session.live_hosts:
                    if host.url == current_url:
                        host.waf = waf_name

    def run_evasion_scans(self, session: ScanSession, domain: str) -> None:
        """Run additional scans with WAF bypass techniques on protected endpoints."""
        if not session.waf_detections:
            self._progress.print_info("No WAF targets to evade. Skipping evasion scans.")
            return

        waf_urls = list(session.waf_detections.keys())
        self._progress.print_phase("WAF Evasion Scans")
        self._progress.print_info(
            f"Launching evasion scans on {len(waf_urls)} protected endpoint(s)..."
        )
        log.info("Launching evasion scans on %d protected endpoints...", len(waf_urls))

        waf_list = self._out.parsed / f"waf_urls_{domain}.txt"
        waf_list.parent.mkdir(parents=True, exist_ok=True)
        waf_list.write_text("\n".join(waf_urls), encoding="utf-8")

        task = self._progress.add_task("WAF evasion scans", total=3)
        self._run_nuclei_wafbypass(session, waf_list, domain)
        self._progress.advance(task, status="nuclei done")
        self._run_ffuf_evasion(session, waf_urls, domain)
        self._progress.advance(task, status="ffuf done")
        self._run_arjun(session, waf_urls, domain)
        self._progress.complete_task(task, f"{len(session.evasion_findings)} finding(s)")

        self._progress.print_success(
            f"Evasion scans completed. Extra findings: {len(session.evasion_findings)}"
        )
        log.info(
            "Evasion scans completed. Extra findings: %d",
            len(session.evasion_findings),
        )

    def _run_nuclei_wafbypass(
        self, session: ScanSession, waf_list: Path, domain: str
    ) -> None:
        if not shutil.which("nuclei"):
            return

        evasion_raw = self._out.raw / "nuclei" / f"wafbypass_{domain}.jsonl"
        evasion_raw.parent.mkdir(parents=True, exist_ok=True)

        self._runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(waf_list),
                "-jsonl", "-o", str(evasion_raw),
                "-silent",
                # WAF bypass posture: randomize Host header casing + spoof common
                # forwarding headers so detection templates still fire behind a WAF.
                "-H", "X-Forwarded-For: 127.0.0.1",
                "-H", "X-Real-IP: 127.0.0.1",
                "-exclude-tags", "dos,brute,ddos,intrusive,destructive,fuzz",
            ],
            target=domain,
            timeout=1200,
            check_exists=False,
        )

        if evasion_raw.exists():
            for line in evasion_raw.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line.strip())
                    info = data.get("info", {})
                    session.evasion_findings.append(EvasionFinding(
                        template_id=str(data.get("template-id", data.get("templateID", "waf-bypass"))),
                        matched_at=str(data.get("matched-at", data.get("host", ""))),
                        name=str(info.get("name", "")),
                        severity=str(info.get("severity", "info")).lower(),
                        technique="nuclei-waf-bypass",
                        source_tool="nuclei",
                        raw=line.strip(),
                    ))
                except (json.JSONDecodeError, KeyError):
                    continue

    def _run_ffuf_evasion(
        self, session: ScanSession, waf_urls: List[str], domain: str
    ) -> None:
        if not shutil.which("ffuf"):
            return

        wordlist = self._resolve_wordlist()
        if not wordlist:
            log.debug("No wordlist for WAF evasion ffuf scans")
            return

        for url in waf_urls[:10]:
            raw_ffuf = self._out.raw / "ffuf" / f"evade_{domain}_{os.getpid()}.json"
            raw_ffuf.parent.mkdir(parents=True, exist_ok=True)

            self._runner.run(
                tool_name="ffuf",
                cmd=[
                    "ffuf",
                    "-w", str(wordlist),
                    "-u", f"{url}/FUZZ",
                    "-H", "X-Forwarded-For: 127.0.0.1",
                    "-H", "X-Originating-IP: 127.0.0.1",
                    "-H", "X-Real-IP: 127.0.0.1",
                    "-H", "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    "-p", "0.5",
                    "-sa", "-se", "-sf",
                    "-json", "-o", str(raw_ffuf),
                    "-t", "5",
                ],
                target=url,
                timeout=180,
                check_exists=False,
            )

            if raw_ffuf.exists():
                try:
                    data = json.loads(raw_ffuf.read_text(encoding="utf-8"))
                    for res in data.get("results", []):
                        status = res.get("status")
                        if status in (200, 403):
                            fuzz = res.get("input", {}).get("FUZZ", "")
                            session.evasion_findings.append(EvasionFinding(
                                template_id="waf-bypass-directory",
                                matched_at=url,
                                name=f"Hidden path via WAF evasion: {fuzz}",
                                severity="info",
                                technique="header-spoof",
                                source_tool="ffuf",
                            ))
                except (json.JSONDecodeError, KeyError):
                    pass

    def _run_arjun(
        self, session: ScanSession, waf_urls: List[str], domain: str
    ) -> None:
        if not shutil.which("arjun"):
            return

        for url in waf_urls[:5]:
            out_path = self._out.raw / "arjun" / f"{domain}.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)

            self._runner.run(
                tool_name="arjun",
                cmd=[
                    "arjun", "-u", url,
                    "--passive", "--stable",
                    "-oJ", str(out_path),
                ],
                target=url,
                timeout=120,
                check_exists=False,
            )
            self._progress.print_info(f"Arjun parameter discovery launched for {url}")
            log.info("Arjun parameter discovery launched for %s", url)

    def _resolve_wordlist(self) -> Optional[Path]:
        if COMMON_DIRS.exists():
            return COMMON_DIRS
        cfg_wordlist = self._cfg.get("probing", "dir_wordlist", default="")
        if cfg_wordlist and Path(cfg_wordlist).exists():
            return Path(cfg_wordlist)
        fallback = self._cfg.get("probing", "dir_wordlist_fallback", default="")
        if fallback and Path(fallback).exists():
            return Path(fallback)
        return None
