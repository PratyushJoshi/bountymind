"""
modules/secret_scanner.py
--------------------------
JSSecretScanner: mines JavaScript files for hardcoded secrets,
API keys, tokens, and credentials using SecretFinder.

Tool selection rationale:

- SecretFinder (github): Python script that applies JSFuck-resistant
  regex patterns to extract secrets from JS files.
  Source: https://github.com/m4ll0k/SecretFinder
  Classification: Open / Free (GitHub clone)

  Detects: AWS keys, Google API keys, Slack tokens, Stripe keys,
  JWT tokens, generic API key patterns, private keys, passwords,
  and many other sensitive credential formats.

  Safety notes:
  - SecretFinder only fetches the JS file URL and parses its content.
  - It does NOT submit credentials, test them, or make any secondary
    requests beyond fetching the JS file itself.
  - Results are logged and reported but never acted upon automatically.
  - max_js_files cap prevents unbounded scanning sessions.

Alternative/complementary approach:
  If SecretFinder is unavailable, a built-in regex fallback scans
  the same JS URLs using common secret patterns — no external tool needed.
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import SecretFinding
from utils.output_helpers import OutputManager
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("secret_scanner")

# ---------------------------------------------------------------------------
# Built-in regex patterns for fallback scanning (when SecretFinder absent)
# These are conservative detection patterns — expected to have false positives.
# All findings require analyst review before treating as confirmed secrets.
# ---------------------------------------------------------------------------
BUILTIN_SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "AWS Secret Access Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"(?i)stripe[^'\"\n]{0,20}sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key"),
    (r"xox[baprs]-[0-9a-zA-Z]{10,48}", "Slack Token"),
    (r"(?i)github[^'\"\n]{0,20}[0-9a-f]{40}", "GitHub Token"),
    (r"(?i)api[_\-\s]?key['\"\s:=]+[0-9a-zA-Z\-_]{20,60}", "Generic API Key"),
    (r"eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}", "JWT Token"),
    (r"(?i)password['\"\s:=]+[^\s'\"]{8,}", "Potential Password"),
    (r"(?i)secret['\"\s:=]+[^\s'\"]{8,}", "Potential Secret"),
    (r"(?i)private[_\s]key['\"\s:=]+[^\s'\"]{20,}", "Private Key"),
    (r"sq0atp-[0-9A-Za-z\-_]{22}", "Square Access Token"),
    (r"AC[a-z0-9]{32}", "Twilio Account SID"),
    (r"SK[a-z0-9]{32}", "Twilio Auth Token"),
    (r"(?i)bearer\s+[a-zA-Z0-9\-_.]{20,}", "Bearer Token"),
]
BUILTIN_PATTERNS_COMPILED = [(re.compile(p), label) for p, label in BUILTIN_SECRET_PATTERNS]

# Limit extracted value display to avoid leaking full secrets in reports
MAX_SECRET_VALUE_LEN = 60


class JSSecretScanner:
    """
    Scans JavaScript files for exposed secrets and credentials.

    Uses SecretFinder when available, falls back to built-in regex patterns.
    Processes files in parallel with a configurable concurrency limit.
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

    def run(self, js_urls: List[str]) -> List[SecretFinding]:
        """
        Scan a list of JS URLs for secrets. Returns findings.

        Args:
            js_urls: List of absolute JS file URLs to scan.
        """
        if not self._cfg.secret_scanning_enabled:
            log.info("Secret scanning disabled in config; skipping")
            return []

        if not js_urls:
            log.info("No JS URLs to scan; skipping secret scan")
            return []

        # Apply safety cap
        max_files = self._cfg.secret_scan_max_js_files
        if len(js_urls) > max_files:
            log.warning(
                "JS URL count (%d) exceeds max_js_files=%d; truncating",
                len(js_urls), max_files,
            )
            js_urls = js_urls[:max_files]

        self._progress.print_phase("Phase 2.5a — JavaScript Secret Mining")
        log.info("Scanning %d JS files for secrets", len(js_urls))

        # Determine scan method
        secretfinder_script = self._cfg.secretfinder_path
        use_secretfinder = Path(secretfinder_script).exists()

        if not use_secretfinder:
            log.info(
                "SecretFinder not found at %s; using built-in regex patterns",
                secretfinder_script,
            )
            self._progress.print_warning(
                "SecretFinder not found — using built-in regex fallback. "
                "Run --update-tools to install SecretFinder."
            )

        task = self._progress.add_task(
            "[yellow]JS Secret Scan", total=len(js_urls), status="scanning"
        )
        all_findings: List[SecretFinding] = []

        # Parallel scanning
        max_workers = min(self._cfg.max_concurrency, 5)
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            if use_secretfinder:
                futures = {
                    pool.submit(self._scan_with_secretfinder, url, secretfinder_script): url
                    for url in js_urls
                }
            else:
                futures = {
                    pool.submit(self._scan_with_builtin_regex, url): url
                    for url in js_urls
                }

            for future in as_completed(futures):
                url = futures[future]
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                        log.debug("%d secrets found in %s", len(findings), url)
                except Exception as exc:
                    log.debug("Secret scan failed for %s: %s", url, exc)
                finally:
                    self._progress.advance(
                        task, status=f"{len(all_findings)} secrets found"
                    )

        self._save_results(all_findings)
        self._progress.print_success(
            f"JS secret scan complete — {len(all_findings)} potential secrets found"
        )

        # Console alert for high-value patterns
        for f in all_findings:
            if any(kw in f.secret_type.lower() for kw in ["aws", "stripe", "private key", "jwt"]):
                self._progress.print_finding(
                    "high", f.url, f"{f.secret_type} detected"
                )

        return all_findings

    # ------------------------------------------------------------------
    # SecretFinder scanner
    # ------------------------------------------------------------------

    def _scan_with_secretfinder(
        self, url: str, script_path: str
    ) -> List[SecretFinding]:
        """
        Run SecretFinder.py on a single JS URL.
        SecretFinder fetches the URL and outputs matched secrets to stdout.
        """
        result = self._runner.run(
            tool_name="secretfinder",
            cmd=["python3", script_path, "-i", url, "-o", "cli"],
            target=url,
            timeout=30,
            save_raw=True,
            check_exists=False,  # python3 is always present
        )

        findings = []
        for line in result.stdout.splitlines():
            line = line.strip()
            # SecretFinder CLI output format: "SecretType: value"
            if ":" in line and not line.startswith("[") and not line.startswith("http"):
                colon_idx = line.index(":")
                secret_type = line[:colon_idx].strip()
                secret_value = line[colon_idx + 1:].strip()

                if secret_type and secret_value and len(secret_type) < 80:
                    findings.append(SecretFinding(
                        url=url,
                        secret_type=secret_type,
                        secret_value=self._redact(secret_value),
                        source_tool="secretfinder",
                    ))
        return findings

    # ------------------------------------------------------------------
    # Built-in regex fallback
    # ------------------------------------------------------------------

    def _scan_with_builtin_regex(self, url: str) -> List[SecretFinding]:
        """
        Fetch a JS URL and apply built-in regex patterns.
        Pure Python — no external tool dependency.
        """
        content = self._fetch_url(url)
        if not content:
            return []

        findings = []
        for pattern, label in BUILTIN_PATTERNS_COMPILED:
            for match in pattern.finditer(content):
                value = match.group(0)
                findings.append(SecretFinding(
                    url=url,
                    secret_type=label,
                    secret_value=self._redact(value),
                    source_tool="builtin-regex",
                ))
        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fetch_url(self, url: str) -> str:
        """Fetch a URL and return its text content."""
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconFramework/1.0 (authorized security testing)"},
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.read(1024 * 1024).decode("utf-8", errors="replace")  # 1 MB cap
        except urllib.error.URLError as exc:
            log.debug("Fetch failed for %s: %s", url, exc)
        except Exception as exc:
            log.debug("Unexpected fetch error for %s: %s", url, exc)
        return ""

    @staticmethod
    def _redact(value: str) -> str:
        """
        Partially redact a secret value for safe display in reports.
        Shows first 6 chars + redacted suffix to allow pattern identification
        without fully exposing the credential.
        """
        if len(value) <= 8:
            return "***REDACTED***"
        visible = value[:6]
        return f"{visible}{'*' * min(len(value) - 6, 20)}[{len(value)} chars]"

    def _save_results(self, findings: List[SecretFinding]) -> None:
        self._out.save_parsed("secret_scanner", "js_secrets", [
            {
                "url": f.url,
                "secret_type": f.secret_type,
                "secret_value": f.secret_value,
                "source_tool": f.source_tool,
            }
            for f in findings
        ])
