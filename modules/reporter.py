"""
modules/reporter.py
-------------------
ReportGenerator: parses raw findings, normalizes data, and produces
professional Markdown and HTML reports with explicit analyst guidance.

Report sections:
1. Executive Summary
2. Scan Scope & Metadata
3. Target Overview
4. Discovered Subdomains & Assets
5. Live Web Services
6. Port & Service Observations
7. Directory & File Discovery
8. Vulnerability Findings (grouped by severity)
9. Tool Execution Summary
10. Warnings & Errors
11. Data Source & Provider Summary
12. Authenticated Validation Follow-Up (analyst-only)
13. *** Potential Manual Verification & Exploitation Gateways ***
"""
from __future__ import annotations

import datetime
import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import (
    CloudBucketFinding,
    DirectoryFinding,
    EvasionFinding,
    HarvestedURL,
    LiveHost,
    ManualFlag,
    NucleiFinding,
    PortService,
    ScanSession,
    SecretFinding,
    Severity,
    SubdomainRecord,
    ToolResult,
)
from utils.output_helpers import OutputManager, severity_sort_key
from utils.progress import ProgressManager

log = get_logger("reporter")

# Patterns that indicate admin/sensitive paths requiring manual review
ADMIN_PATH_KEYWORDS = [
    "admin", "administrator", "dashboard", "portal", "console", "panel",
    "login", "signin", "auth", "sso", "oauth", "oidc", "saml",
    "management", "manager", "manage", "phpmyadmin", "cpanel", "plesk",
    "wp-admin", "wp-login", "xmlrpc",
]

API_PATH_KEYWORDS = [
    "api", "v1", "v2", "v3", "graphql", "swagger", "openapi", "rest",
    "endpoint", "webhook", "callback",
]

BACKUP_FILE_KEYWORDS = [
    ".bak", ".sql", ".zip", ".tar", ".gz", ".env", ".config",
    ".log", "backup", "dump", "export",
]

DEBUG_PATH_KEYWORDS = [
    "debug", "phpinfo", "server-status", "server-info", "actuator",
    "health", "metrics", "trace", "heapdump", "env", "info", "beans",
]


class ManualFlagGenerator:
    """Analyzes scan results and generates ManualFlag records for the report."""

    def generate(self, session: ScanSession) -> List[ManualFlag]:
        flags: List[ManualFlag] = []
        flags.extend(self._check_subdomain_takeovers(session.subdomains))
        flags.extend(self._check_interesting_dirs(session.directory_findings))
        flags.extend(self._check_nuclei_auth_findings(session.nuclei_findings))
        flags.extend(self._check_exposed_services(session.port_services))
        flags.extend(self._check_technology_indicators(session.live_hosts))
        flags.extend(self._check_js_secrets(session.secret_findings))
        flags.extend(self._check_cloud_buckets(session.cloud_bucket_findings))
        return flags

    def _check_subdomain_takeovers(self, subdomains: List[SubdomainRecord]) -> List[ManualFlag]:
        flags = []
        for sub in subdomains:
            if sub.dangling_cname:
                flags.append(ManualFlag(
                    flag_type="subdomain_takeover",
                    target=sub.domain,
                    observation=f"Dangling CNAME detected: {sub.domain} → {sub.cname}",
                    significance=(
                        "Dangling CNAMEs pointing to cloud providers with no active "
                        "resource may be claimable by an attacker, allowing them to "
                        "serve content from this subdomain."
                    ),
                    evidence=f"CNAME: {sub.cname}, IPs resolved: {sub.ip_addresses}",
                    raw_data_path="output/raw/crtsh/ or output/raw/subfinder/",
                    analyst_steps=[
                        f"Attempt to claim the resource at the CNAME target: {sub.cname}",
                        "Check if the target cloud service account is still active",
                        "Use https://github.com/EdOverflow/can-i-take-over-xyz for provider specifics",
                        "If claimable, document and report as confirmed subdomain takeover",
                    ],
                    auth_required=True,
                    severity_hint=Severity.HIGH,
                ))
        return flags

    def _check_interesting_dirs(self, dirs: List[DirectoryFinding]) -> List[ManualFlag]:
        flags = []
        for d in dirs:
            url_lower = d.url.lower()
            if any(kw in url_lower for kw in ADMIN_PATH_KEYWORDS):
                flags.append(ManualFlag(
                    flag_type="exposed_admin_panel",
                    target=d.url,
                    observation=f"Admin/login panel discovered: {d.url} (HTTP {d.status_code})",
                    significance=(
                        "Admin panels and login pages are high-value targets. "
                        "Default credentials, authentication bypass, or weak lockout "
                        "policies may be exploitable."
                    ),
                    evidence=f"Status: {d.status_code}, Content-Length: {d.content_length}",
                    raw_data_path=f"output/raw/ffuf/ or output/raw/dirsearch/",
                    analyst_steps=[
                        "Navigate to the URL manually and observe the interface",
                        "Test for default credentials (admin:admin, admin:password, etc.)",
                        "Check for authentication bypass (direct URL access without login)",
                        "Review for version leakage in page source or headers",
                        "Test for username enumeration in login responses",
                        "Run nikto manually: nikto -h " + d.url,
                    ],
                    auth_required=True,
                    severity_hint=Severity.MEDIUM,
                ))
            elif any(kw in url_lower for kw in API_PATH_KEYWORDS):
                flags.append(ManualFlag(
                    flag_type="api_endpoint",
                    target=d.url,
                    observation=f"API endpoint discovered: {d.url} (HTTP {d.status_code})",
                    significance=(
                        "API endpoints may expose unauthenticated data, support IDOR, "
                        "lack proper authorization controls, or expose internal functionality."
                    ),
                    evidence=f"Status: {d.status_code}, Content-Length: {d.content_length}",
                    raw_data_path="output/raw/ffuf/ or output/raw/dirsearch/",
                    analyst_steps=[
                        "Enumerate API endpoints manually (check /api/v1/, /api/docs/)",
                        "Look for Swagger/OpenAPI documentation (swagger.json, openapi.yaml)",
                        "Test unauthenticated access: does the endpoint return data without auth?",
                        "With credentials: test IDOR by manipulating object IDs",
                        "Check HTTP methods: OPTIONS, HEAD, PUT, DELETE",
                        "Review response headers for internal metadata",
                    ],
                    auth_required=False,
                    severity_hint=Severity.MEDIUM,
                ))
            elif any(kw in url_lower for kw in BACKUP_FILE_KEYWORDS):
                flags.append(ManualFlag(
                    flag_type="backup_file_exposure",
                    target=d.url,
                    observation=f"Potential backup/config file: {d.url} (HTTP {d.status_code})",
                    significance=(
                        "Backup and configuration files can expose credentials, "
                        "database connection strings, API keys, or source code."
                    ),
                    evidence=f"Status: {d.status_code}, Content-Length: {d.content_length}",
                    raw_data_path="output/raw/ffuf/ or output/raw/dirsearch/",
                    analyst_steps=[
                        "Download and inspect the file content manually",
                        "Search for hardcoded credentials, API keys, or connection strings",
                        "Check for database schemas or sensitive business logic",
                        "Verify if the file should be publicly accessible",
                    ],
                    auth_required=False,
                    severity_hint=Severity.HIGH,
                ))
            elif any(kw in url_lower for kw in DEBUG_PATH_KEYWORDS):
                flags.append(ManualFlag(
                    flag_type="debug_endpoint",
                    target=d.url,
                    observation=f"Debug/diagnostic endpoint: {d.url} (HTTP {d.status_code})",
                    significance=(
                        "Debug endpoints (phpinfo, actuator, server-status) can expose "
                        "environment variables, stack traces, system information, and "
                        "internal configuration that aids further attacks."
                    ),
                    evidence=f"Status: {d.status_code}",
                    raw_data_path="output/raw/ffuf/ or output/raw/dirsearch/",
                    analyst_steps=[
                        "Access the endpoint and document what information is exposed",
                        "Check /actuator/env for Spring environment variables (potential credential exposure)",
                        "Check /actuator/heapdump for Java heap dumps (credential extraction possible)",
                        "phpinfo() output: check for sensitive config and loaded modules",
                        "Verify if these endpoints should be accessible from the internet",
                    ],
                    auth_required=False,
                    severity_hint=Severity.HIGH,
                ))
        return flags

    def _check_nuclei_auth_findings(self, findings: List[NucleiFinding]) -> List[ManualFlag]:
        flags = []
        for f in findings:
            tags_lower = [t.lower() for t in f.tags]
            if "default-login" in tags_lower or "panel" in tags_lower:
                flags.append(ManualFlag(
                    flag_type="default_credentials_panel",
                    target=f.matched_at,
                    observation=f"Nuclei detected login panel or default-login template match: {f.name}",
                    significance=(
                        "Default credentials panels indicate the service may not have been "
                        "hardened. Manual credential testing is required to confirm exploitability."
                    ),
                    evidence=f"Template: {f.template_id}, Severity: {f.severity.value}",
                    raw_data_path="output/raw/nuclei/batch_scan.jsonl",
                    analyst_steps=[
                        f"Navigate to: {f.matched_at}",
                        "Attempt default credentials for the identified service",
                        "Check vendor documentation for default usernames/passwords",
                        "Test for authentication bypass or direct object access",
                        "If login succeeds, document and escalate immediately",
                    ],
                    auth_required=True,
                    severity_hint=Severity.HIGH,
                ))
            if "takeover" in tags_lower:
                flags.append(ManualFlag(
                    flag_type="nuclei_takeover_signal",
                    target=f.matched_at,
                    observation=f"Nuclei subdomain takeover template match: {f.name}",
                    significance="Nuclei detected indicators consistent with subdomain takeover vulnerability.",
                    evidence=f"Template: {f.template_id}, Host: {f.host}",
                    raw_data_path="output/raw/nuclei/batch_scan.jsonl",
                    analyst_steps=[
                        "Verify the CNAME/DNS record for this host",
                        "Attempt to claim the resource at the pointed provider",
                        "Reference: https://github.com/EdOverflow/can-i-take-over-xyz",
                        "If successful, report as confirmed subdomain takeover",
                    ],
                    auth_required=True,
                    severity_hint=Severity.HIGH,
                ))
        return flags

    def _check_exposed_services(self, services: List[PortService]) -> List[ManualFlag]:
        flags = []
        sensitive_ports = {
            21: ("FTP", "FTP exposes file transfer operations, often unencrypted."),
            22: ("SSH", "SSH exposed: check for weak keys, outdated version, or password auth."),
            23: ("Telnet", "Telnet is unencrypted and should never be internet-exposed."),
            25: ("SMTP", "SMTP exposure may allow open relay testing or user enumeration."),
            445: ("SMB", "SMB exposure is extremely high risk; test for EternalBlue/PrintNightmare."),
            1433: ("MSSQL", "MSSQL database directly exposed to internet."),
            3306: ("MySQL", "MySQL database directly exposed to internet."),
            3389: ("RDP", "RDP exposed: test for BlueKeep, credential attack surface."),
            5432: ("PostgreSQL", "PostgreSQL database directly exposed to internet."),
            5900: ("VNC", "VNC exposed: check for authentication and version vulnerabilities."),
            6379: ("Redis", "Redis commonly misconfigured with no auth; critical exposure."),
            27017: ("MongoDB", "MongoDB may be accessible without authentication."),
            9200: ("Elasticsearch", "Elasticsearch often requires no auth by default."),
            8500: ("Consul", "Consul API may expose internal service mesh configuration."),
            2375: ("Docker", "Docker daemon API exposed without TLS is a critical vulnerability."),
        }
        for svc in services:
            if svc.port in sensitive_ports:
                svc_name, significance = sensitive_ports[svc.port]
                flags.append(ManualFlag(
                    flag_type="sensitive_port_exposure",
                    target=f"{svc.host}:{svc.port}",
                    observation=f"Sensitive service exposed: {svc_name} on port {svc.port}/{svc.protocol}",
                    significance=significance,
                    evidence=f"Host: {svc.host}, Port: {svc.port}, Service: {svc.service}, Version: {svc.version}",
                    raw_data_path=f"output/raw/nmap/{svc.host}.gnmap",
                    analyst_steps=[
                        f"Connect to {svc.host}:{svc.port} and observe the banner",
                        f"Check {svc_name} version against known CVEs",
                        "Attempt default/blank credentials if applicable",
                        "Verify if this service requires internet exposure",
                        "For databases: test unauthenticated access and data exposure",
                    ],
                    auth_required=svc.port in (22, 3389, 5900),
                    severity_hint=Severity.HIGH,
                ))
        return flags

    def _check_technology_indicators(self, hosts: List[LiveHost]) -> List[ManualFlag]:
        flags = []
        for h in hosts:
            for tech in h.technologies:
                tech_lower = tech.lower()
                if any(kw in tech_lower for kw in ["wordpress", "joomla", "drupal", "magento"]):
                    flags.append(ManualFlag(
                        flag_type="cms_detected",
                        target=h.url,
                        observation=f"CMS detected: {tech} on {h.url}",
                        significance=(
                            f"{tech} installations are frequent targets due to plugin/theme "
                            "vulnerabilities, outdated core versions, and common misconfigurations."
                        ),
                        evidence=f"Detected by technology fingerprinting on {h.url}",
                        raw_data_path="output/raw/httpx/batch.txt or output/raw/whatweb/",
                        analyst_steps=[
                            f"Run WPScan (for WordPress): wpscan --url {h.url} --enumerate vp,vt,u",
                            "Identify installed plugins/themes and check for known CVEs",
                            "Check /wp-content/uploads/ for unrestricted file upload",
                            "Test xmlrpc.php for brute-force enablement (WordPress)",
                            "Check for exposed configuration files: wp-config.php.bak",
                        ],
                        auth_required=False,
                        severity_hint=Severity.MEDIUM,
                    ))
        return flags

    def _check_js_secrets(self, findings) -> List[ManualFlag]:
        """Generate manual flags for high-value JS secret findings."""
        from utils.models import SecretFinding
        flags = []
        high_value_types = ["aws", "stripe", "private key", "jwt", "github",
                             "slack", "twilio", "square", "google api"]
        for f in findings:
            stype_lower = f.secret_type.lower()
            severity = Severity.HIGH if any(h in stype_lower for h in high_value_types) else Severity.MEDIUM
            flags.append(ManualFlag(
                flag_type="js_secret_exposure",
                target=f.url,
                observation=f"Potential {f.secret_type} found in JavaScript file",
                significance=(
                    f"Hardcoded secrets in JavaScript files are accessible to anyone "
                    f"who can view the file. A {f.secret_type} may allow unauthorized "
                    "access to third-party services, cloud infrastructure, or APIs."
                ),
                evidence=f"Type: {f.secret_type}, Redacted value: {f.secret_value}, "
                         f"Tool: {f.source_tool}",
                raw_data_path="output/parsed/secret_scanner/js_secrets.json",
                analyst_steps=[
                    f"Fetch the JS file manually: {f.url}",
                    "Search for the secret pattern in the file source",
                    "Verify whether the secret is valid (check against the provider's API)",
                    "If valid: report immediately and initiate credential rotation",
                    "Check git history if source is accessible — secret may predate this version",
                    "Review all environments (dev/staging/prod) for the same exposure",
                ],
                auth_required=False,
                severity_hint=severity,
            ))
        return flags

    def _check_cloud_buckets(self, findings) -> List[ManualFlag]:
        """Generate manual flags for open/misconfigured cloud buckets."""
        from utils.models import CloudBucketFinding
        flags = []
        for b in findings:
            flags.append(ManualFlag(
                flag_type="cloud_bucket_exposure",
                target=b.url,
                observation=f"{b.provider.upper()} bucket accessible: {b.bucket_name}",
                significance=(
                    "Open cloud storage buckets may expose sensitive files including "
                    "backups, source code, credentials, customer data, or configuration. "
                    "Writable buckets can be abused for data injection or malware hosting."
                ),
                evidence=f"Provider: {b.provider}, Bucket: {b.bucket_name}, "
                         f"Public: {b.is_public}, Detail: {b.finding_detail[:200]}",
                raw_data_path="output/parsed/cloud_recon/cloud_buckets.json",
                analyst_steps=[
                    f"Navigate to the bucket URL: {b.url}",
                    "List bucket contents (if public listing is enabled)",
                    "Identify any sensitive files (*.sql, *.bak, *.env, *.key, *.pem)",
                    "Test write access: attempt to upload a benign test file",
                    "If sensitive data is exposed: document and report immediately",
                    "Do NOT download, copy, or access any data beyond initial listing",
                    "Verify authorization scope before any further interaction",
                ],
                auth_required=False,
                severity_hint=Severity.HIGH if b.is_public else Severity.MEDIUM,
            ))
        return flags


class ReportGenerator:
    """
    Aggregates scan session data and renders Markdown and/or HTML reports.
    """

    def __init__(
        self,
        config: ConfigManager,
        output: OutputManager,
        progress: ProgressManager,
    ) -> None:
        self._cfg = config
        self._out = output
        self._progress = progress
        self._flag_generator = ManualFlagGenerator()

    def run(self, session: ScanSession) -> List[Path]:
        """Generate all configured report formats. Returns list of output paths."""
        self._progress.print_phase("Phase 3 — Report Generation")
        session.end_time = datetime.datetime.utcnow()

        # Generate manual flags
        session.manual_flags = self._flag_generator.generate(session)
        log.info("Generated %d manual validation flags", len(session.manual_flags))

        output_paths: List[Path] = []
        for fmt in self._cfg.report_formats:
            if fmt == "markdown":
                path = self._render_markdown(session)
                output_paths.append(path)
                self._progress.print_success(f"Markdown report: {path}")
            elif fmt == "html":
                path = self._render_html(session)
                output_paths.append(path)
                self._progress.print_success(f"HTML report: {path}")
            else:
                log.warning("Unknown report format: %s", fmt)

        return output_paths

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _render_markdown(self, session: ScanSession) -> Path:
        """Build and write the Markdown report."""
        lines: List[str] = []
        self._md_header(lines, session)
        self._md_executive_summary(lines, session)
        self._md_scope(lines, session)
        self._md_subdomains(lines, session)
        self._md_live_hosts(lines, session)
        self._md_ports(lines, session)
        self._md_directories(lines, session)
        self._md_vulnerabilities(lines, session)
        self._md_js_secrets(lines, session)
        self._md_cloud_buckets(lines, session)
        self._md_harvested_urls(lines, session)
        self._md_screenshots(lines, session)
        self._md_waf_detection(lines, session)
        self._md_waf_evasion(lines, session)
        self._md_tool_summary(lines, session)
        self._md_warnings(lines, session)
        self._md_data_sources(lines, session)
        self._md_authenticated_followup(lines, session)
        self._md_manual_gateways(lines, session)

        content = "\n".join(lines)
        path = self._out.report_path(session.session_id, "markdown")
        path.write_text(content, encoding="utf-8")
        log.info("Markdown report written to %s", path)
        return path

    def _md_header(self, lines: List[str], s: ScanSession) -> None:
        lines += [
            f"# {self._cfg.report_title}",
            f"",
            f"**Organization:** {self._cfg.organization}  ",
            f"**Session ID:** `{s.session_id}`  ",
            f"**Started:** {s.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Completed:** {s.end_time.strftime('%Y-%m-%d %H:%M:%S UTC') if s.end_time else 'N/A'}  ",
            f"**Duration:** {str(s.duration).split('.')[0] if s.duration else 'N/A'}  ",
            f"**Targets:** {', '.join(s.targets)}  ",
            f"",
            f"> ⚠️ **AUTHORIZED USE ONLY** — This report was generated by automated",
            f"> reconnaissance tooling and is intended exclusively for security",
            f"> personnel with written authorization to assess the listed targets.",
            f"> Do not distribute without appropriate access controls.",
            f"",
            "---",
            "",
        ]

    def _md_executive_summary(self, lines: List[str], s: ScanSession) -> None:
        crit = sum(1 for f in s.nuclei_findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in s.nuclei_findings if f.severity == Severity.HIGH)
        med = sum(1 for f in s.nuclei_findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in s.nuclei_findings if f.severity == Severity.LOW)
        info = sum(1 for f in s.nuclei_findings if f.severity == Severity.INFO)
        lines += [
            "## Executive Summary",
            "",
            f"Automated reconnaissance and vulnerability assessment was performed against "
            f"**{len(s.targets)} target(s)**. The unauthenticated, non-intrusive scan "
            f"identified **{len(s.subdomains)} subdomains**, **{len(s.live_hosts)} live "
            f"web services**, **{len(s.port_services)} open ports**, and "
            f"**{len(s.nuclei_findings)} potential vulnerability findings**.",
            "",
            "### Finding Counts by Severity",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {crit} |",
            f"| 🟠 High | {high} |",
            f"| 🟡 Medium | {med} |",
            f"| 🔵 Low | {low} |",
            f"| ℹ️ Info | {info} |",
            f"| **Total** | **{len(s.nuclei_findings)}** |",
            "",
            "### Extended Capability Results",
            "",
            "| Module | Findings |",
            "|--------|---------|",
            f"| URL Harvesting | {len(s.harvested_urls)} URLs ({sum(1 for u in s.harvested_urls if u.is_js)} JS files) |",
            f"| JS Secret Mining | {len(s.secret_findings)} potential secrets |",
            f"| Cloud Bucket Recon | {len(s.cloud_bucket_findings)} open/interesting buckets |",
            f"| Visual Screenshots | {sum(1 for h in s.live_hosts if h.screenshot_path)} captured |",
            f"| WAF Endpoints | {len(s.waf_detections)} protected endpoints |",
            f"| WAF Evasion Findings | {len(s.evasion_findings)} bypass discoveries |",
            "",
            f"**{len(s.manual_flags)} items** were flagged for manual analyst validation "
            f"(see _Potential Manual Verification & Exploitation Gateways_ section).",
            "",
            "---",
            "",
        ]

    def _md_scope(self, lines: List[str], s: ScanSession) -> None:
        lines += [
            "## Scan Scope & Configuration",
            "",
            f"- **Targets:** {', '.join(s.targets)}",
            f"- **Mode:** Unauthenticated, non-intrusive automated reconnaissance",
            f"- **Phases:** Subdomain enumeration → HTTP probing → Port scanning "
            f"→ Directory discovery → Nuclei scanning → Report",
            f"- **Safe mode:** Enabled (destructive/intrusive checks excluded)",
            "",
            "---",
            "",
        ]

    def _md_subdomains(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Discovered Subdomains & Assets", ""]
        if not s.subdomains:
            lines += ["_No subdomains discovered._", "", "---", ""]
            return
        lines += [f"**Total:** {len(s.subdomains)}", ""]
        takeovers = [sub for sub in s.subdomains if sub.dangling_cname]
        if takeovers:
            lines += [
                f"> ⚠️ **{len(takeovers)} potential subdomain takeover indicator(s)** detected "
                f"(dangling CNAMEs). See _Manual Gateways_ section.",
                "",
            ]
        lines += [
            "| Subdomain | IP(s) | CNAME | Source | Takeover Risk |",
            "|-----------|-------|-------|--------|---------------|",
        ]
        for sub in sorted(s.subdomains, key=lambda x: x.domain):
            ips = ", ".join(sub.ip_addresses[:3]) or "unresolved"
            cname = sub.cname or ""
            risk = "⚠️ YES" if sub.dangling_cname else "No"
            lines.append(f"| `{sub.domain}` | {ips} | {cname} | {sub.source} | {risk} |")
        lines += ["", "---", ""]

    def _md_live_hosts(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Live Web Services", ""]
        if not s.live_hosts:
            lines += ["_No live hosts found._", "", "---", ""]
            return
        lines += [f"**Total:** {len(s.live_hosts)}", "",
                  "| URL | Status | Title | Technologies | WAF |",
                  "|-----|--------|-------|--------------|-----|"]
        for h in s.live_hosts:
            techs = ", ".join(h.technologies[:5]) or "—"
            waf = h.waf or "—"
            title = (h.title[:60] + "…") if len(h.title) > 60 else h.title or "—"
            lines.append(f"| {h.url} | {h.status_code} | {title} | {techs} | {waf} |")
        lines += ["", "---", ""]

    def _md_ports(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Port & Service Observations", ""]
        if not s.port_services:
            lines += ["_No open ports identified._", "", "---", ""]
            return
        lines += [f"**Total open ports:** {len(s.port_services)}", "",
                  "| Host | Port | Protocol | Service | Version |",
                  "|------|------|----------|---------|---------|"]
        for p in sorted(s.port_services, key=lambda x: (x.host, x.port)):
            lines.append(
                f"| {p.host} | {p.port} | {p.protocol} | {p.service or '—'} | {p.version or '—'} |"
            )
        lines += ["", "---", ""]

    def _md_directories(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Directory & File Discovery", ""]
        if not s.directory_findings:
            lines += ["_No directory findings._", "", "---", ""]
            return
        interesting = [d for d in s.directory_findings if d.is_interesting]
        lines += [
            f"**Total paths found:** {len(s.directory_findings)}  ",
            f"**Interesting paths flagged:** {len(interesting)}",
            "",
            "| URL | Status | Length | Tool | Interesting |",
            "|-----|--------|--------|------|-------------|",
        ]
        for d in sorted(s.directory_findings, key=lambda x: -x.status_code):
            flag = "⚠️" if d.is_interesting else ""
            lines.append(
                f"| {d.url} | {d.status_code} | {d.content_length} | {d.source_tool} | {flag} |"
            )
        lines += ["", "---", ""]

    def _md_vulnerabilities(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Vulnerability Findings (Nuclei)", ""]
        if not s.nuclei_findings:
            lines += ["_No vulnerability findings from automated scanning._", "", "---", ""]
            return
        lines += [f"**Total findings:** {len(s.nuclei_findings)}", ""]
        # Group by severity
        grouped: Dict[str, List[NucleiFinding]] = defaultdict(list)
        for f in s.nuclei_findings:
            grouped[f.severity.value].append(f)
        severity_order = ["critical", "high", "medium", "low", "info", "unknown"]
        for sev in severity_order:
            group = grouped.get(sev, [])
            if not group:
                continue
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                     "low": "🔵", "info": "ℹ️"}.get(sev, "⚪")
            lines += [f"### {emoji} {sev.capitalize()} ({len(group)})", ""]
            for f in group:
                cve_str = ", ".join(f.cve_ids) if f.cve_ids else "—"
                lines += [
                    f"#### {f.name}",
                    f"- **Template:** `{f.template_id}`",
                    f"- **Host:** `{f.host}`",
                    f"- **Matched at:** `{f.matched_at}`",
                    f"- **CVE(s):** {cve_str}",
                    f"- **CVSS:** {f.cvss_score or '—'}",
                    f"- **Tags:** {', '.join(f.tags)}",
                ]
                if f.description:
                    lines += [f"- **Description:** {f.description}"]
                if f.extracted_results:
                    lines += [f"- **Extracted:** `{'`, `'.join(f.extracted_results[:5])}`"]
                if self._cfg.include_raw_references:
                    lines += [f"- **Raw data:** `output/raw/nuclei/batch_scan.jsonl`"]
                lines.append("")
        lines += ["---", ""]

    def _md_js_secrets(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## JavaScript Secrets & Credential Exposure", ""]
        if not s.secret_findings:
            lines += ["_No secrets extracted from JavaScript files._", "", "---", ""]
            return
        lines += [
            f"**Total findings:** {len(s.secret_findings)}",
            "",
            "> ⚠️ All values below are **partially redacted** for safe display.",
            "> Raw artifacts stored in `output/raw/secretfinder/` and `output/parsed/secret_scanner/`.",
            "> **Analyst action required** — verify each finding manually before treating as confirmed.",
            "",
            "| Source JS File | Secret Type | Redacted Value | Tool |",
            "|----------------|-------------|----------------|------|",
        ]
        for f in s.secret_findings:
            url_short = (f.url[:70] + "…") if len(f.url) > 70 else f.url
            lines.append(
                f"| `{url_short}` | {f.secret_type} | `{f.secret_value}` | {f.source_tool} |"
            )
        lines += ["", "---", ""]

    def _md_cloud_buckets(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Cloud Storage Bucket Exposure", ""]
        if not s.cloud_bucket_findings:
            lines += ["_No open cloud buckets found._", "", "---", ""]
            return
        lines += [
            f"**Total findings:** {len(s.cloud_bucket_findings)}",
            "",
            "> ⚠️ Cloud bucket findings require **manual analyst verification**.",
            "> Do NOT attempt to read, write, or claim any bucket without explicit",
            "> written authorization from the target organization.",
            "",
            "| Provider | Bucket Name | URL | Public | Tool |",
            "|----------|-------------|-----|--------|------|",
        ]
        for b in s.cloud_bucket_findings:
            public = "🔓 YES" if b.is_public else "🔒 No (access denied)"
            lines.append(
                f"| {b.provider} | `{b.bucket_name}` | {b.url} | {public} | {b.source_tool} |"
            )
        lines += ["", "---", ""]

    def _md_harvested_urls(self, lines: List[str], s: ScanSession) -> None:
        if not s.harvested_urls:
            return
        interesting = [u for u in s.harvested_urls if u.is_interesting]
        js_files = [u for u in s.harvested_urls if u.is_js]
        lines += [
            "## Harvested URL Surface",
            "",
            f"**Total URLs harvested:** {len(s.harvested_urls)}  ",
            f"**JS files:** {len(js_files)}  ",
            f"**Interesting endpoints:** {len(interesting)}",
            "",
        ]
        if interesting:
            lines += [
                "### Interesting Endpoints (sample — top 50)",
                "",
                "| URL | Source |",
                "|-----|--------|",
            ]
            for u in interesting[:50]:
                lines.append(f"| {u.url[:100]} | {u.source} |")
            lines.append("")
        lines += ["---", ""]

    def _md_screenshots(self, lines: List[str], s: ScanSession) -> None:
        screenshotted = [h for h in s.live_hosts if h.screenshot_path]
        if not screenshotted:
            return
        lines += [
            "## Visual Reconnaissance (Screenshots)",
            "",
            f"**{len(screenshotted)} screenshots captured** via gowitness.",
            "Screenshots are stored in `output/screenshots/`.",
            "",
            "| URL | Screenshot |",
            "|-----|-----------|",
        ]
        for h in screenshotted[:30]:
            rel = h.screenshot_path or ""
            lines.append(f"| {h.url} | `{rel}` |")
        lines += ["", "---", ""]

    def _md_waf_detection(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## WAF Detection", ""]
        if not s.waf_detections:
            lines += ["_No WAF identified on live endpoints._", "", "---", ""]
            return
        lines += [
            f"**Protected endpoints:** {len(s.waf_detections)}",
            "",
            "| URL | Firewall |",
            "|-----|----------|",
        ]
        for url, waf_name in sorted(s.waf_detections.items()):
            lines.append(f"| {url} | **{waf_name}** |")
        lines += ["", "---", ""]

    def _md_waf_evasion(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## WAF Evasion Discoveries", ""]
        if not s.evasion_findings:
            lines += [
                "_No additional resources uncovered via WAF evasion techniques._",
                "", "---", "",
            ]
            return
        lines += [f"**Total evasion findings:** {len(s.evasion_findings)}", ""]
        for ev in s.evasion_findings:
            sev = ev.severity.upper() if isinstance(ev, EvasionFinding) else str(
                ev.get("info", {}).get("severity", "info")
            ).upper()
            if isinstance(ev, EvasionFinding):
                tid = ev.template_id
                matched = ev.matched_at
                desc = ev.name
                technique = ev.technique
            else:
                tid = str(ev.get("template-id", "Bypass"))
                matched = str(ev.get("matched-at", ""))
                desc = str(ev.get("info", {}).get("name", ""))
                technique = ""
            tech_note = f" ({technique})" if technique else ""
            lines.append(
                f"- **[{sev}]** `{tid}` on `{matched}` — {desc}{tech_note}"
            )
        lines += ["", "---", ""]

    def _md_tool_summary(self, lines: List[str], s: ScanSession) -> None:
        lines += ["## Tool Execution Summary", "",
                  "| Tool | Target | Duration | Return Code | Timed Out |",
                  "|------|--------|----------|-------------|-----------|"]
        for r in s.tool_results:
            lines.append(
                f"| {r.tool_name} | {r.target[:40]} | {r.duration_seconds:.1f}s "
                f"| {r.return_code} | {'Yes' if r.timed_out else 'No'} |"
            )
        lines += ["", "---", ""]

    def _md_warnings(self, lines: List[str], s: ScanSession) -> None:
        if not s.warnings and not s.errors:
            return
        lines += ["## Warnings & Errors", ""]
        for w in s.warnings:
            lines.append(f"- ⚠️ {w}")
        for e in s.errors:
            lines.append(f"- ❌ {e}")
        lines += ["", "---", ""]

    def _md_data_sources(self, lines: List[str], s: ScanSession) -> None:
        lines += [
            "## Data Source & Provider Summary",
            "",
            "| Source | Classification | Notes |",
            "|--------|---------------|-------|",
            "| crt.sh | Open/Free | Certificate Transparency logs — no API key required |",
            "| subfinder | Open/Free | Multi-source passive enumeration — some sources optional/keyed |",
            "| amass | Open/Free | Passive DNS enumeration — no key for passive mode |",
            "| dnsx | Open/Free | Fast bulk DNS resolution (ProjectDiscovery) |",
            "| gau | Open/Free | Passive URL harvesting (Wayback, OTX, CommonCrawl) |",
            "| waybackurls | Open/Free | Wayback Machine URL harvesting |",
            "| katana | Open/Free | Active web crawler (depth-limited, non-intrusive) |",
            "| subzy | Open/Free | Active subdomain takeover verification |",
            "| gowitness | Open/Free | Visual reconnaissance screenshots |",
            "| cloud_enum | Open/Free | Cloud bucket enumeration (S3, GCP, Azure, DO) |",
            "| arjun | Open/Free | HTTP parameter discovery for WAF evasion |",
            "| wafw00f | Open/Free | Web Application Firewall fingerprinting |",
            "| Shodan | Free-tier/Optional | Used only if SHODAN API key configured |",
            "| VirusTotal | Free-tier/Optional | Used only if VT API key configured |",
            "| nuclei | Open/Free | Community templates — MIT licensed |",
            "",
            "---",
            "",
        ]

    def _md_authenticated_followup(self, lines: List[str], s: ScanSession) -> None:
        lines += [
            "## Authenticated Validation Follow-Up",
            "",
            "> The following items were identified during unauthenticated automated",
            "> scanning and **require manual authenticated validation** by a security",
            "> analyst with appropriate access and written authorization.",
            "",
            "These are not automated findings — they are analyst tasks generated based",
            "on evidence from the automated phase. Each item explains what was found,",
            "why authentication may be needed, and what to check.",
            "",
        ]
        # Filter manual flags that need auth
        auth_flags = [f for f in s.manual_flags if f.auth_required]
        if not auth_flags:
            lines += ["_No authenticated validation items identified at this time._", "", "---", ""]
            return
        for flag in auth_flags:
            lines += [
                f"### {flag.flag_type.replace('_', ' ').title()}",
                f"**Target:** `{flag.target}`  ",
                f"**Observation:** {flag.observation}  ",
                f"**Significance:** {flag.significance}  ",
                f"**Evidence:** {flag.evidence}  ",
                f"**Raw data:** `{flag.raw_data_path}`  ",
                "",
                "**Analyst steps:**",
            ]
            for step in flag.analyst_steps:
                lines.append(f"1. {step}")
            lines += ["", "---" if flag != auth_flags[-1] else "", ""]
        lines += ["---", ""]

    def _md_manual_gateways(self, lines: List[str], s: ScanSession) -> None:
        lines += [
            "## ⚠️ Potential Manual Verification & Exploitation Gateways",
            "",
            "> **ANALYST ACTION REQUIRED**",
            ">",
            "> The items below represent findings from automated scanning that **cannot",
            "> be safely confirmed or exploited automatically**. Each item requires",
            "> direct analyst involvement, contextual judgment, and in many cases,",
            "> authenticated access or elevated privilege.",
            ">",
            "> **These steps must only be performed with explicit written authorization",
            "> for the target scope.**",
            "",
        ]
        if not s.manual_flags:
            lines += ["_No manual verification items at this time._", ""]
            return
        for i, flag in enumerate(s.manual_flags, 1):
            sev_emoji = {
                "critical": "🔴", "high": "🟠", "medium": "🟡",
                "low": "🔵", "info": "ℹ️",
            }.get(flag.severity_hint.value, "⚪")
            lines += [
                f"### {i}. {sev_emoji} {flag.flag_type.replace('_', ' ').title()}",
                "",
                f"| Field | Detail |",
                f"|-------|--------|",
                f"| **Target** | `{flag.target}` |",
                f"| **Type** | {flag.flag_type} |",
                f"| **Severity Hint** | {flag.severity_hint.value.upper()} |",
                f"| **Auth Required** | {'Yes — authenticated access needed' if flag.auth_required else 'No — unauthenticated validation possible'} |",
                f"| **Raw Data** | `{flag.raw_data_path}` |",
                "",
                f"**What was observed:**  ",
                f"{flag.observation}",
                "",
                f"**Why it matters:**  ",
                f"{flag.significance}",
                "",
                f"**Supporting evidence:**  ",
                f"{flag.evidence}",
                "",
                "**Recommended analyst actions:**",
                "",
            ]
            for step in flag.analyst_steps:
                lines.append(f"- {step}")
            lines += ["", "---" if i < len(s.manual_flags) else "", ""]

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def _render_html(self, session: ScanSession) -> Path:
        """Render the Markdown report as a self-contained HTML file."""
        # Build markdown first, then wrap in HTML
        md_lines: List[str] = []
        self._md_header(md_lines, session)
        self._md_executive_summary(md_lines, session)
        self._md_scope(md_lines, session)
        self._md_subdomains(md_lines, session)
        self._md_live_hosts(md_lines, session)
        self._md_ports(md_lines, session)
        self._md_directories(md_lines, session)
        self._md_vulnerabilities(md_lines, session)
        self._md_js_secrets(md_lines, session)
        self._md_cloud_buckets(md_lines, session)
        self._md_harvested_urls(md_lines, session)
        self._md_screenshots(md_lines, session)
        self._md_waf_detection(md_lines, session)
        self._md_waf_evasion(md_lines, session)
        self._md_tool_summary(md_lines, session)
        self._md_warnings(md_lines, session)
        self._md_data_sources(md_lines, session)
        self._md_authenticated_followup(md_lines, session)
        self._md_manual_gateways(md_lines, session)

        md_content = "\n".join(md_lines)

        try:
            import markdown as md_lib
            body = md_lib.markdown(
                md_content,
                extensions=["tables", "fenced_code", "toc", "nl2br"],
            )
        except ImportError:
            # Fallback: wrap raw markdown in <pre>
            log.warning("python-markdown not installed; using plain HTML fallback")
            body = f"<pre>{html.escape(md_content)}</pre>"

        html_content = self._html_template(session, body)
        path = self._out.report_path(session.session_id, "html")
        path.write_text(html_content, encoding="utf-8")
        log.info("HTML report written to %s", path)
        return path

    @staticmethod
    def _html_template(session: ScanSession, body: str) -> str:
        title = html.escape(f"Security Assessment Report — {', '.join(session.targets)}")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          max-width: 1200px; margin: 0 auto; padding: 2rem; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; border-bottom: 2px solid #21262d; padding-bottom: 0.5rem; }}
  h2 {{ color: #79c0ff; border-bottom: 1px solid #21262d; padding-bottom: 0.25rem; margin-top: 2rem; }}
  h3 {{ color: #d2a8ff; }}
  h4 {{ color: #ffa657; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th {{ background: #161b22; color: #58a6ff; padding: 0.5rem; text-align: left; border: 1px solid #30363d; }}
  td {{ padding: 0.4rem 0.5rem; border: 1px solid #21262d; vertical-align: top; }}
  tr:nth-child(even) {{ background: #161b22; }}
  code, pre {{ background: #161b22; padding: 0.2rem 0.4rem; border-radius: 4px;
               font-family: 'Courier New', monospace; color: #a5d6ff; }}
  pre {{ padding: 1rem; overflow-x: auto; }}
  blockquote {{ border-left: 4px solid #388bfd; padding: 0.5rem 1rem;
                background: #161b22; margin: 1rem 0; color: #8b949e; }}
  hr {{ border: none; border-top: 1px solid #21262d; margin: 2rem 0; }}
  a {{ color: #58a6ff; }}
  .banner {{ background: #1c1f26; border: 1px solid #f0883e;
             padding: 1rem; border-radius: 6px; margin-bottom: 2rem; color: #f0883e; }}
</style>
</head>
<body>
<div class="banner">
⚠️ AUTHORIZED USE ONLY — This report contains sensitive security assessment data.
Handle in accordance with your organization's data classification policy.
</div>
{body}
<hr>
<p style="color: #8b949e; font-size: 0.85rem; text-align: center;">
Generated by BountyMind | Session {html.escape(session.session_id)}
| {html.escape(session.start_time.strftime('%Y-%m-%d %H:%M UTC'))}
</p>
</body>
</html>
"""
