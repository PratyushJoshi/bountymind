"""
modules/cloud_recon.py
-----------------------
CloudReconModule: enumerates public/misconfigured cloud storage buckets
across AWS S3, GCP Cloud Storage, Azure Blob Storage, and DigitalOcean Spaces.

Tool selection rationale:

- cloud_enum (pip): Python tool that generates permutations of the target
  domain/keywords and checks for open/existing buckets across major providers.
  Source: https://github.com/initstring/cloud_enum
  Classification: Open / Free (pip install cloud_enum)

  Safety notes:
  - cloud_enum ONLY checks whether buckets exist and are publicly accessible.
  - It does NOT download, modify, or upload any bucket content.
  - It sends HTTP HEAD/GET requests to well-known bucket URL patterns.
  - No credentials or privileged access is used or required.
  - All findings are informational — analyst must manually verify.

Fallback:
  If cloud_enum is unavailable, the module performs direct HTTP checks
  against common bucket URL patterns derived from the target domain —
  pure Python, no external tool required.
"""

from __future__ import annotations

import re
import urllib.request
import urllib.error
from typing import List

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import CloudBucketFinding
from utils.output_helpers import OutputManager, parse_line_delimited
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("cloud_recon")

# ---------------------------------------------------------------------------
# URL pattern templates for fallback HTTP checks
# ---------------------------------------------------------------------------
# Generates candidate bucket URLs from a keyword
BUCKET_URL_TEMPLATES = [
    # AWS S3
    ("aws",    "https://{kw}.s3.amazonaws.com/"),
    ("aws",    "https://s3.amazonaws.com/{kw}/"),
    ("aws",    "https://{kw}.s3-website.us-east-1.amazonaws.com/"),
    # GCP
    ("gcp",    "https://storage.googleapis.com/{kw}/"),
    ("gcp",    "https://{kw}.storage.googleapis.com/"),
    # Azure
    ("azure",  "https://{kw}.blob.core.windows.net/"),
    # DigitalOcean Spaces
    ("do",     "https://{kw}.nyc3.digitaloceanspaces.com/"),
    ("do",     "https://{kw}.sfo2.digitaloceanspaces.com/"),
]

# Indicators of open/misconfigured bucket in response body
OPEN_BUCKET_INDICATORS = [
    "ListBucketResult",  # AWS S3 listing
    "NoSuchBucket",      # bucket name exists but may be claimable
    "<?xml",             # any XML response from cloud storage
    "AccessDenied",      # bucket exists but access restricted (still interesting)
    "AllAccessDisabled",
    "Contents",
]


class CloudReconModule:
    """
    Enumerates cloud storage buckets using cloud_enum (with built-in fallback).
    All checks are read-only HTTP requests — no modifications.
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

    def run(
        self, targets: List[str], subdomains: List[str]
    ) -> List[CloudBucketFinding]:
        """
        Run cloud bucket enumeration.

        Args:
            targets:    Root domain list.
            subdomains: Discovered subdomains (for keyword generation).
        """
        if not self._cfg.cloud_recon_enabled:
            log.info("Cloud bucket recon disabled in config; skipping")
            return []

        self._progress.print_phase("Phase 2.5b — Cloud Bucket Enumeration")

        # Build keyword set from domains and subdomains
        keywords = self._build_keywords(targets, subdomains)
        log.info("Cloud recon: %d keywords to enumerate", len(keywords))

        findings: List[CloudBucketFinding] = []

        # Try cloud_enum first
        if self._cfg.is_tool_enabled("cloud_enum") and \
                self._runner.check_binary_available(
                    self._cfg.get_tool_binary("cloud_enum")
                ):
            findings = self._run_cloud_enum(keywords)
        else:
            log.info(
                "cloud_enum not available; using built-in HTTP fallback"
            )
            self._progress.print_warning(
                "cloud_enum not found — using built-in HTTP checks. "
                "Install: pip3 install cloud_enum"
            )
            findings = self._run_builtin_check(keywords)

        self._save_results(findings)
        self._progress.print_success(
            f"Cloud recon complete — {len(findings)} open/interesting buckets found"
        )
        log.info("Cloud recon complete: %d findings", len(findings))
        return findings

    # ------------------------------------------------------------------
    # cloud_enum runner
    # ------------------------------------------------------------------

    def _run_cloud_enum(self, keywords: List[str]) -> List[CloudBucketFinding]:
        """Run cloud_enum with keyword list."""
        binary = self._cfg.get_tool_binary("cloud_enum")
        threads = self._cfg.cloud_enum_threads
        timeout = self._cfg.cloud_enum_timeout

        # Write keyword file
        kw_file = self._out.base / "tmp_cloud_keywords.txt"
        kw_file.write_text("\n".join(keywords), encoding="utf-8")

        task = self._progress.add_task(
            "[cyan]Cloud Bucket Enum", total=1, status="running"
        )

        result = self._runner.run(
            tool_name="cloud_enum",
            cmd=[
                binary,
                "-kf", str(kw_file),
                "-t", str(threads),
                "--timeout", "30",
            ],
            target="cloud-enum",
            timeout=timeout,
            save_raw=True,
        )
        kw_file.unlink(missing_ok=True)
        self._progress.advance(task, status="parsing")

        return self._parse_cloud_enum_output(result.stdout)

    def _parse_cloud_enum_output(self, stdout: str) -> List[CloudBucketFinding]:
        """
        Parse cloud_enum stdout for confirmed open/accessible buckets.
        cloud_enum uses '[+]' prefix for positive findings.
        """
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if "[+]" not in line and "OPEN" not in line.upper():
                continue

            # Determine provider from URL patterns in the line
            provider = "unknown"
            for marker, prov in [
                ("amazonaws.com", "aws"), ("s3.", "aws"),
                ("googleapis.com", "gcp"), ("storage.google", "gcp"),
                ("blob.core.windows.net", "azure"),
                ("digitaloceanspaces.com", "digitalocean"),
            ]:
                if marker in line.lower():
                    provider = prov
                    break

            # Extract URL from line
            url_match = re.search(r"https?://[^\s\"']+", line)
            url = url_match.group(0) if url_match else ""
            bucket_name = self._extract_bucket_name(url) if url else line[:80]

            findings.append(CloudBucketFinding(
                provider=provider,
                bucket_name=bucket_name,
                url=url,
                is_public=True,
                finding_detail=line,
                source_tool="cloud_enum",
            ))
        return findings

    # ------------------------------------------------------------------
    # Built-in HTTP fallback
    # ------------------------------------------------------------------

    def _run_builtin_check(self, keywords: List[str]) -> List[CloudBucketFinding]:
        """
        Direct HTTP checks against common bucket URL patterns.
        Sends HEAD/GET requests and checks for open bucket indicators.
        """
        findings = []
        # Limit to prevent excessive requests in fallback mode
        limited_keywords = keywords[:20]

        task = self._progress.add_task(
            "[cyan]Cloud HTTP Check", total=len(limited_keywords) * len(BUCKET_URL_TEMPLATES)
        )

        for kw in limited_keywords:
            for provider, template in BUCKET_URL_TEMPLATES:
                url = template.format(kw=kw)
                self._progress.advance(task, status=f"checking {kw}")
                finding = self._check_bucket_url(url, provider, kw)
                if finding:
                    findings.append(finding)
                    self._progress.print_finding(
                        "medium", url, f"Cloud bucket accessible: {finding.bucket_name}"
                    )

        return findings

    def _check_bucket_url(
        self, url: str, provider: str, kw: str
    ) -> CloudBucketFinding | None:
        """Send a single HEAD/GET request to a candidate bucket URL."""
        try:
            req = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "ReconFramework/1.0 (authorized security testing)"
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                body = resp.read(4096).decode("utf-8", errors="replace")

            # Any 2xx or XML response from a cloud storage URL is interesting
            if status == 200 or any(ind in body for ind in OPEN_BUCKET_INDICATORS):
                return CloudBucketFinding(
                    provider=provider,
                    bucket_name=kw,
                    url=url,
                    is_public=(status == 200),
                    finding_detail=f"HTTP {status} — {body[:200]}",
                    source_tool="builtin-http",
                )
        except urllib.error.HTTPError as exc:
            # 403 = bucket exists but access denied (still interesting)
            if exc.code == 403:
                return CloudBucketFinding(
                    provider=provider,
                    bucket_name=kw,
                    url=url,
                    is_public=False,
                    finding_detail=f"HTTP 403 — bucket exists but access denied",
                    source_tool="builtin-http",
                )
        except (urllib.error.URLError, OSError):
            pass
        except Exception as exc:
            log.debug("Bucket check error for %s: %s", url, exc)
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_keywords(
        self, targets: List[str], subdomains: List[str]
    ) -> List[str]:
        """
        Generate keyword permutations from domain and subdomain names.
        Keywords are used by cloud_enum to form bucket name candidates.
        """
        keywords: set = set()
        for domain in targets:
            # Add domain without TLD and with
            parts = domain.split(".")
            keywords.add(parts[0])          # "example"
            keywords.add(domain)             # "example.com"
            keywords.add(domain.replace(".", "-"))  # "example-com"

        for sub in subdomains[:50]:  # cap at 50 to avoid excessive permutations
            parts = sub.split(".")
            if parts:
                keywords.add(parts[0])  # subdomain label only
                keywords.add(sub)

        # Remove generic values unlikely to match real buckets
        boring = {"www", "mail", "ftp", "api", "dev", "test", "staging"}
        return [k for k in keywords if k.lower() not in boring and len(k) > 2]

    @staticmethod
    def _extract_bucket_name(url: str) -> str:
        """Extract the bucket name from a cloud storage URL."""
        m = re.search(
            r"(?:https?://)([^.]+)\.(?:s3|storage\.googleapis|blob\.core\.windows"
            r"|digitaloceanspaces)(?:\.[^/]+)?/?",
            url,
        )
        if m:
            return m.group(1)
        return url.split("/")[-2] if url.endswith("/") else url.split("/")[-1]

    def _save_results(self, findings: List[CloudBucketFinding]) -> None:
        self._out.save_parsed("cloud_recon", "cloud_buckets", [
            {
                "provider": f.provider,
                "bucket_name": f.bucket_name,
                "url": f.url,
                "is_public": f.is_public,
                "finding_detail": f.finding_detail,
                "source_tool": f.source_tool,
            }
            for f in findings
        ])
