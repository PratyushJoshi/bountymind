"""
modules/scanner.py
------------------
ScannerModule: orchestrates unauthenticated, non-destructive vulnerability scanning.

Tool selection rationale:

- nuclei (go): ProjectDiscovery's template-based vulnerability scanner.
  The de-facto standard for automated CVE/exposure/misconfiguration scanning.
  Uses community-maintained templates covering thousands of known issues.
  Source: https://github.com/projectdiscovery/nuclei
  Templates: https://github.com/projectdiscovery/nuclei-templates
  Classification: Open / Free (templates are MIT licensed)

  Safety enforcement:
  - Excluded tags: dos, fuzz, brute-force, bruteforce, intrusive, destructive,
    exploit, rce, sqli (hardcoded + config-overridable exclusions)
  - Only unauthenticated, detection-mode templates run by default
  - No exploit execution, no payload delivery, no shell spawning
  - Rate-limited to 50 req/s by default (configurable downward)

  Template categories included:
  - cve: Known CVE detection (passive/detection only)
  - exposure: Exposed sensitive files, endpoints, configs
  - misconfig: Server/application misconfiguration detection
  - technology: Technology fingerprinting
  - default-login: Default credential page detection (NOT actual brute force)
  - takeover: Subdomain takeover detection
  - config: Configuration exposure
  - info: Informational findings
  - panel: Admin/login panel detection
  - token: Exposed API tokens or credentials in responses

Why nuclei only for automated scanning:
  A second scanner (nikto) is intentionally not included in the automated
  pipeline. Nikto's default scan profiles include intrusive checks, and
  its false positive rate makes it less suitable for automated batch scanning.
  Analysts are guided to run nikto manually in the authenticated follow-up
  section if needed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from utils.config_manager import ConfigManager
from utils.exceptions import ToolNotFoundError
from utils.logger import get_logger
from utils.models import NucleiFinding, Severity
from utils.output_helpers import OutputManager
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("scanner")

# These tags are ALWAYS excluded regardless of config, for safety
HARDCODED_EXCLUDED_TAGS = frozenset([
    "dos",
    "fuzz",
    "brute-force",
    "bruteforce",
    "intrusive",
    "destructive",
    "exploit",
])


class ScannerModule:
    """
    Runs nuclei against live hosts from the probing phase.

    Safety invariants:
    - Hardcoded tag exclusions cannot be overridden by config.
    - No authenticated scanning in this module.
    - No exploit template execution.
    - All findings are detection-only (no payloads executed).
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

    def run(self, live_urls: List[str], live_hosts: Optional[List] = None) -> List[NucleiFinding]:
        """
        Scan all live URLs with nuclei and return findings.

        When ``live_hosts`` is provided, a second technology-targeted nuclei pass
        runs templates tagged for detected stacks (PHP, Java, Node, WordPress, …).
        """
        self._progress.print_phase("Phase 2 — Vulnerability Scanning")

        if not live_urls:
            log.info("No live URLs to scan; skipping vulnerability scanning")
            self._progress.print_warning("No live hosts to scan")
            return []

        if not self._cfg.is_tool_enabled("nuclei"):
            log.info("nuclei disabled in config; skipping vulnerability scanning")
            self._progress.print_warning("nuclei disabled — skipping vulnerability scanning")
            return []

        # Verify nuclei binary
        binary = self._cfg.get_tool_binary("nuclei")
        if not self._runner.check_binary_available(binary):
            log.warning("nuclei binary not found: %s", binary)
            self._progress.print_warning(
                "nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            )
            return []

        # Update templates first (safe, read-only network operation)
        self._update_templates(binary)

        findings = self._run_nuclei(live_urls, binary)

        # Technology-targeted pass: run stack-specific templates for detected frameworks.
        if live_hosts and self._cfg.get("scanning", "tech_targeted_scan", default=True):
            from utils.finding_filter import collect_tech_tags
            tech_tags = collect_tech_tags(live_hosts)
            if tech_tags:
                log.info("Running tech-targeted nuclei pass: tags=%s", tech_tags)
                self._progress.print_info(
                    f"Tech-targeted nuclei scan: {', '.join(tech_tags[:8])}"
                    + ("…" if len(tech_tags) > 8 else "")
                )
                extra = self._run_nuclei(live_urls, binary, include_tags=tech_tags)
                # Merge; dedupe happens later in finding_filter.
                seen = {(f.template_id, f.matched_at) for f in findings}
                for f in extra:
                    key = (f.template_id, f.matched_at)
                    if key not in seen:
                        findings.append(f)
                        seen.add(key)

        self._save_results(findings)
        self._print_findings_summary(findings)

        return findings

    # ------------------------------------------------------------------
    # Template management
    # ------------------------------------------------------------------

    def _update_templates(self, binary: str) -> None:
        """
        Run 'nuclei -update-templates' to refresh the community template set.
        This is a safe, read-only operation (downloads files, no scanning).
        """
        log.info("Updating nuclei templates...")
        result = self._runner.run(
            tool_name="nuclei",
            cmd=[binary, "-update-templates"],
            target="template-update",
            timeout=120,
            save_raw=False,
        )
        if result.return_code == 0:
            log.info("Nuclei templates updated successfully")
        else:
            log.warning(
                "Nuclei template update failed (rc=%d). Proceeding with existing templates.",
                result.return_code,
            )

    # ------------------------------------------------------------------
    # Nuclei execution
    # ------------------------------------------------------------------

    def _run_nuclei(
        self,
        urls: List[str],
        binary: str,
        include_tags: Optional[List[str]] = None,
    ) -> List[NucleiFinding]:
        """
        Run nuclei with safety-enforced tag exclusions and JSON output.
        """
        # Write URL list
        url_list_path = self._out.base / "tmp_nuclei_targets.txt"
        url_list_path.write_text("\n".join(urls), encoding="utf-8")

        # Build tag filters
        excluded = self._build_excluded_tags()
        included = self._cfg.nuclei_included_tags
        severities = self._cfg.nuclei_severity_levels

        # Output file
        out_file = self._out.raw_path("nuclei", "batch_scan", "jsonl")

        cmd = [
            binary,
            "-l", str(url_list_path),
            "-jsonl",
            "-o", str(out_file),
            "-silent",
            "-severity", ",".join(severities),
            "-rate-limit", str(self._cfg.nuclei_rate_limit),
            "-bulk-size", str(self._cfg.nuclei_bulk_size),
            "-concurrency", str(self._cfg.nuclei_concurrency),
            "-timeout", str(self._cfg.nuclei_timeout),
            "-no-color",
            "-stats",
        ]

        # Excluded tags (safety enforcement)
        if excluded:
            cmd += ["-etags", ",".join(excluded)]

        # Included tags (scope narrowing) — tech-targeted pass overrides config.
        if include_tags:
            cmd += ["-tags", ",".join(include_tags)]
        elif included:
            cmd += ["-tags", ",".join(included)]

        # Custom templates path
        templates_path = self._cfg.nuclei_templates_path
        if templates_path and Path(templates_path).exists():
            cmd += ["-t", templates_path]

        log.info(
            "Running nuclei: %d URLs, severity=%s, excluded_tags=%s",
            len(urls), severities, list(excluded),
        )

        task = self._progress.add_task(
            "[red]Vulnerability Scanning", total=len(urls), status="running nuclei"
        )

        result = self._runner.run(
            tool_name="nuclei",
            cmd=cmd,
            target="batch",
            timeout=self._cfg.tool_timeout * len(urls),  # scale timeout with target count
            save_raw=False,  # we use -o directly
        )

        url_list_path.unlink(missing_ok=True)
        self._progress.advance(task, amount=len(urls), status="parsing results")

        if result.return_code not in (0, 1):  # nuclei exits 1 when findings are present
            log.warning(
                "nuclei exited with unexpected code %d. Stderr: %s",
                result.return_code, result.stderr[:300],
            )

        return self._parse_nuclei_jsonl(out_file)

    def _parse_nuclei_jsonl(self, jsonl_path: Path) -> List[NucleiFinding]:
        """
        Parse nuclei JSONL output into NucleiFinding records.
        Nuclei outputs one JSON object per line.
        """
        findings: List[NucleiFinding] = []

        if not jsonl_path.exists():
            log.debug("Nuclei output file not found: %s", jsonl_path)
            return findings

        content = jsonl_path.read_text(encoding="utf-8", errors="replace")

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                finding = self._parse_nuclei_entry(data)
                if finding:
                    findings.append(finding)
            except json.JSONDecodeError:
                log.debug("nuclei: could not parse JSONL line: %s", line[:100])

        log.info("Nuclei returned %d findings", len(findings))
        return findings

    def _parse_nuclei_entry(self, data: dict) -> Optional[NucleiFinding]:
        """Convert a single nuclei JSON entry to a NucleiFinding."""
        try:
            info = data.get("info", {})
            severity_str = info.get("severity", "unknown")
            severity = Severity.from_string(severity_str)

            # Safety: skip any finding tagged with hardcoded exclusion tags
            tags = info.get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            if any(t.lower() in HARDCODED_EXCLUDED_TAGS for t in tags):
                log.debug(
                    "Skipping finding %s — excluded tag found",
                    data.get("template-id", ""),
                )
                return None

            # Extract CVE IDs from template ID and classification
            cve_ids: List[str] = []
            template_id = data.get("template-id", "")
            cve_matches = re.findall(r"CVE-\d{4}-\d+", template_id, re.IGNORECASE)
            cve_ids.extend([c.upper() for c in cve_matches])

            classification = info.get("classification", {})
            if isinstance(classification, dict):
                cve_list = classification.get("cve-id", [])
                if isinstance(cve_list, str):
                    cve_list = [cve_list]
                cve_ids.extend([c.upper() for c in cve_list if c])

            cvss_score: Optional[float] = None
            if isinstance(classification, dict):
                raw_cvss = classification.get("cvss-score", "")
                try:
                    cvss_score = float(raw_cvss) if raw_cvss else None
                except (ValueError, TypeError):
                    pass

            references = info.get("reference", [])
            if isinstance(references, str):
                references = [references]

            extracted = data.get("extracted-results", [])
            if isinstance(extracted, str):
                extracted = [extracted]

            return NucleiFinding(
                template_id=template_id,
                name=info.get("name", template_id),
                severity=severity,
                host=data.get("host", ""),
                matched_at=data.get("matched-at", ""),
                description=info.get("description", ""),
                tags=tags,
                reference=references or [],
                extracted_results=extracted or [],
                cvss_score=cvss_score,
                cve_ids=list(set(cve_ids)),
                raw=json.dumps(data),
            )

        except (KeyError, TypeError, ValueError) as exc:
            log.debug("nuclei entry parse error: %s — data: %s", exc, str(data)[:200])
            return None

    # ------------------------------------------------------------------
    # Tag management
    # ------------------------------------------------------------------

    def _build_excluded_tags(self) -> frozenset:
        """Merge hardcoded exclusions with config-defined exclusions."""
        config_exclusions = frozenset(
            t.lower() for t in self._cfg.nuclei_excluded_tags
        )
        return HARDCODED_EXCLUDED_TAGS | config_exclusions

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _save_results(self, findings: List[NucleiFinding]) -> None:
        """Persist parsed nuclei findings to output/parsed/."""
        self._out.save_parsed("scanner", "nuclei_findings", [
            {
                "template_id": f.template_id,
                "name": f.name,
                "severity": f.severity.value,
                "host": f.host,
                "matched_at": f.matched_at,
                "description": f.description,
                "tags": f.tags,
                "cve_ids": f.cve_ids,
                "cvss_score": f.cvss_score,
                "references": f.reference,
            }
            for f in findings
        ])

    def _print_findings_summary(self, findings: List[NucleiFinding]) -> None:
        """Print a severity-grouped summary to the progress console."""
        severity_counts: dict = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        rows = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                rows.append([sev.upper(), str(count)])

        if rows:
            self._progress.print_summary_table(
                rows, ["Severity", "Count"], "Nuclei Findings"
            )

        # Highlight critical/high findings immediately
        for f in findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                self._progress.print_finding(
                    f.severity.value, f.host, f"{f.name} — {f.matched_at}"
                )
