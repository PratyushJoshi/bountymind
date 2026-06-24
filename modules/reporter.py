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


def generate_manual_checklist(target: ScanSession) -> str:
    """Build a dynamic analyst checklist from the collected findings."""
    checklist = []

    admin_flags = [
        flag for flag in target.manual_flags
        if flag.flag_type in {"exposed_admin_panel", "default_credentials_panel"}
        or "admin" in flag.flag_type
    ]
    if admin_flags:
        checklist.append("<h3>Admin Panels - Default Credentials</h3><ul>")
        for flag in admin_flags:
            url = html.escape(str(flag.target))
            checklist.append(
                f"<li>Visit <code>{url}</code> - try admin:admin, test weak passwords</li>"
            )
        checklist.append("</ul>")

    if target.graphql_endpoints:
        checklist.append("<h3>GraphQL - Introspection & Exploitation</h3><ul>")
        for gql in target.graphql_endpoints:
            checklist.append(
                f"<li><code>{html.escape(gql)}</code> - run GraphQL Voyager, test introspection</li>"
            )
        checklist.append("</ul>")

    if target.sqli_findings:
        checklist.append("<h3>SQL Injection - Manual Verification</h3><ul>")
        for sqli in target.sqli_findings[:5]:
            parameter = html.escape(str(sqli.get("parameter", "")))
            checklist.append(
                f"<li>Parameter: <code>{parameter}</code> - test error-based and time-based payloads</li>"
            )
        checklist.append("</ul>")

    if target.xss_findings:
        checklist.append("<h3>XSS - PoC Generation</h3><ul>")
        for finding in target.xss_findings[:5]:
            data = html.escape(str(finding.get("data", finding.get("url", ""))))
            checklist.append(
                f"<li><code>{data}</code> - craft alert-based PoCs for each context</li>"
            )
        checklist.append("</ul>")

    if target.open_redirects:
        checklist.append("<h3>Open Redirect - Parameter Tampering</h3><ul>")
        for finding in target.open_redirects[:5]:
            matched = html.escape(str(finding.get("matched-at", finding.get("host", ""))))
            checklist.append(
                f"<li><code>{matched}</code> - try <code>?redirect=https://evil.com</code></li>"
            )
        checklist.append("</ul>")

    if target.ssrf_findings:
        checklist.append("<h3>SSRF - Internal & Cloud Metadata</h3><ul>")
        for finding in target.ssrf_findings[:5]:
            matched = html.escape(str(finding.get("matched-at", finding.get("host", ""))))
            checklist.append(
                f"<li><code>{matched}</code> - test 169.254.169.254 and cloud metadata endpoints</li>"
            )
        checklist.append("</ul>")

    if target.cors_misconfigs:
        checklist.append("<h3>CORS - Origin Spoofing</h3><ul>")
        for finding in target.cors_misconfigs[:5]:
            matched = html.escape(str(finding.get("matched-at", finding.get("host", ""))))
            checklist.append(
                f"<li><code>{matched}</code> - add Origin: https://evil.example and re-test</li>"
            )
        checklist.append("</ul>")

    if target.jwt_tokens:
        checklist.append("<h3>JWT Analysis</h3><ul>")
        for token in target.jwt_tokens[:3]:
            prefix = html.escape(token[:30] + ("..." if len(token) > 30 else ""))
            checklist.append(
                f"<li>Decode <code>{prefix}</code> - test alg:none, kid injection, weak secrets</li>"
            )
        checklist.append("</ul>")

    if target.ssti_findings:
        checklist.append("<h3>SSTI - RCE</h3><ul>")
        for finding in target.ssti_findings:
            checklist.append(
                f"<li><code>{html.escape(str(finding.get('url', '')))}</code> - test common template payloads</li>"
            )
        checklist.append("</ul>")

    if target.idor_findings:
        checklist.append("<h3>IDOR - Sequential ID Enumeration</h3><ul>")
        for finding in target.idor_findings[:5]:
            checklist.append(
                f"<li>Endpoint: <code>{html.escape(str(finding.get('url', '')))}</code> - change numeric IDs across accounts</li>"
            )
        checklist.append("</ul>")

    if target.path_traversal_findings:
        checklist.append("<h3>Path Traversal - File Read</h3><ul>")
        for finding in target.path_traversal_findings[:5]:
            matched = html.escape(str(finding.get("matched-at", finding.get("host", ""))))
            checklist.append(
                f"<li><code>{matched}</code> - test ../etc/passwd and related traversal payloads</li>"
            )
        checklist.append("</ul>")

    if target.race_condition_findings:
        checklist.append("<h3>Race Condition - Parallel Requests</h3><ul>")
        checklist.append("<li>Use Turbo Intruder or high-concurrency ffuf to stress the vulnerable action</li>")
        checklist.append("</ul>")

    if target.csrf_findings:
        checklist.append("<h3>CSRF - Craft PoC</h3><ul>")
        for finding in target.csrf_findings:
            checklist.append(
                f"<li>Form: <code>{html.escape(str(finding.get('matched-at', finding.get('host', ''))))}</code> - generate a CSRF PoC and verify token presence</li>"
            )
        checklist.append("</ul>")

    if target.websocket_findings:
        checklist.append("<h3>WebSocket - Cross-Site Hijacking</h3><ul>")
        for finding in target.websocket_findings:
            checklist.append(
                f"<li><code>{html.escape(str(finding.get('matched-at', finding.get('host', ''))))}</code> - check Origin validation and auth boundaries</li>"
            )
        checklist.append("</ul>")

    if target.oauth_findings:
        checklist.append("<h3>OAuth - Redirect URI / CSRF</h3><ul>")
        checklist.append("<li>Modify redirect_uri to an attacker-controlled domain and check state reuse</li>")
        checklist.append("</ul>")

    if target.cache_poisoning_findings:
        checklist.append("<h3>Cache Poisoning</h3><ul>")
        checklist.append("<li>Try X-Forwarded-Host and X-Forwarded-Scheme headers</li>")
        checklist.append("</ul>")

    if target.smuggling_findings:
        checklist.append("<h3>🚀 Request Smuggling – Exploit</h3><ul><li>Use smuggler output and Burp to poison the queue, hijack sessions, or bypass front-end security.</li></ul>")

    if target.prototype_pollution:
        checklist.append("<h3>🧬 Prototype Pollution – Craft Gadgets</h3><ul><li>For each polluted JS file, identify the library and try property-injection gadgets (e.g., <code>__proto__.isAdmin=true</code>).</li></ul>")

    if target.bypass_403_findings:
        checklist.append("<h3>🔓 Bypassed 403 Resources – Explore</h3><ul>")
        for b in target.bypass_403_findings[:5]:
            checklist.append(f"<li>Access {html.escape(b.get('original',''))} → see if sensitive content is now available.</li>")
        checklist.append("</ul>")

    if target.hidden_params:
        checklist.append("<h3>📝 Hidden Parameters – Fuzz Further</h3><ul><li>Test each parameter for SQLi, XSS, IDOR using your other modules.</li></ul>")

    if target.api_schema_findings:
        checklist.append("<h3>🧩 API Logic Flaws – Manual Review</h3><ul><li>Examine schemathesis output for missing authorization checks, mass assignment, etc.</li></ul>")

    if target.dast_findings:
        checklist.append("<h3>🎯 DAST Parameter Findings – Confirm & Weaponize</h3><ul>")
        for item in target.dast_findings[:8]:
            info = item.get("info", {}) if isinstance(item, dict) else {}
            name = info.get("name", item.get("template-id", "")) if isinstance(info, dict) else ""
            matched = item.get("matched-at", item.get("host", "")) if isinstance(item, dict) else ""
            checklist.append(
                f"<li>Reproduce <code>{html.escape(str(name))}</code> at "
                f"<code>{html.escape(str(matched))}</code> manually, then build a clean PoC "
                f"(reflected/stored context, encoding, WAF bypass).</li>"
            )
        checklist.append("</ul>")

    critical = [s for s in target.sensitive_paths if s.get("sensitivity") in {"critical", "high"}]
    if critical:
        checklist.append("<h3>Critical Sensitive Files - Inspect Contents</h3><ul>")
        for finding in critical[:10]:
            url = html.escape(f"{finding['base_url']}/{finding['path']}")
            checklist.append(
                f"<li><a href='{url}' target='_blank' style='color:var(--red);'>{url}</a> - check for credentials and secrets</li>"
            )
        checklist.append("</ul>")

    if any(".git" in str(item.get("path", "")) for item in target.sensitive_paths):
        checklist.append(
            "<h3>Exposed Git Repository</h3><ul><li>Run <code>git-dumper</code> to extract repository contents from the exposed <code>.git</code> directory</li></ul>"
        )

    checklist.append(
        """<h3>Authentication Bypass Tests</h3><ul>
        <li>Verb tampering: POST to GET, X-HTTP-Method-Override</li>
        <li>Parameter pollution: <code>?admin=false&admin=true</code></li>
        <li>JWT tokens: test <code>alg:none</code> and weak secrets</li>
    </ul>"""
    )

    return "\n".join(checklist)


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
                raw_data_path="output/parsed/cloud_buckets.json",
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
        session.end_time = datetime.datetime.now(datetime.timezone.utc)

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
        # All automated deep-scan findings come BEFORE the human-validation block.
        self._md_advanced_findings(lines, session)
        self._md_tool_summary(lines, session)
        self._md_warnings(lines, session)
        self._md_data_sources(lines, session)
        # --- Human validation & testing required (always last) ---
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
            "<div class='metrics-grid'>",
            f"<div class='metric-card'><h3>Sensitive Paths</h3><div class='value'>{len(s.sensitive_paths)}</div></div>",
            f"<div class='metric-card'><h3>SQLi</h3><div class='value'>{len(s.sqli_findings)}</div></div>",
            f"<div class='metric-card'><h3>XSS</h3><div class='value'>{len(s.xss_findings)}</div></div>",
            f"<div class='metric-card'><h3>Open Redirect</h3><div class='value'>{len(s.open_redirects)}</div></div>",
            f"<div class='metric-card'><h3>SSRF</h3><div class='value'>{len(s.ssrf_findings)}</div></div>",
            f"<div class='metric-card'><h3>JWT Tokens</h3><div class='value'>{len(s.jwt_tokens)}</div></div>",
            f"<div class='metric-card'><h3>SSTI</h3><div class='value'>{len(s.ssti_findings)}</div></div>",
            f"<div class='metric-card'><h3>IDOR</h3><div class='value'>{len(s.idor_findings)}</div></div>",
            f"<div class='metric-card'><h3>CSRF</h3><div class='value'>{len(s.csrf_findings)}</div></div>",
            f"<div class='metric-card'><h3>Cache Poison</h3><div class='value'>{len(s.cache_poisoning_findings)}</div></div>",
            f"<div class='metric-card'><h3>Smuggling</h3><div class='value'>{len(s.smuggling_findings)}</div></div>",
            f"<div class='metric-card'><h3>Proto Pollution</h3><div class='value'>{len(s.prototype_pollution)}</div></div>",
            f"<div class='metric-card'><h3>403 Bypass</h3><div class='value'>{len(s.bypass_403_findings)}</div></div>",
            f"<div class='metric-card'><h3>Hidden Params</h3><div class='value'>{len(s.hidden_params)}</div></div>",
            f"<div class='metric-card'><h3>API Schema</h3><div class='value'>{len(s.api_schema_findings)}</div></div>",
            f"<div class='metric-card'><h3>Mass Assign</h3><div class='value'>{len(s.mass_assignment_findings)}</div></div>",
            f"<div class='metric-card'><h3>DAST Fuzzing</h3><div class='value'>{len(s.dast_findings)}</div></div>",
            "</div>",
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
            "| s3scanner | Open/Free | Cloud bucket enumeration (S3) with HTTP fallback for AWS/Azure/GCP |",
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
            "# 🧑‍💻 HUMAN VALIDATION & TESTING REQUIRED",
            "",
            "> Everything above this point is **automated output**. Everything below",
            "> requires a human analyst to confirm, validate, and (where authorized)",
            "> exploit. This is intentionally the **final section** of the report so the",
            "> manual workload is consolidated in one place.",
            "",
            "---",
            "",
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
        checklist_html = generate_manual_checklist(s).strip()
        if not s.manual_flags and not checklist_html:
            lines += ["_No manual verification items at this time._", ""]
            return
        if checklist_html:
            lines.append(checklist_html)
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

    def _md_advanced_findings(self, lines: List[str], s: ScanSession) -> None:
        """Render the new advanced finding sections at the end of the report."""

        def section(title: str, body: str) -> None:
            lines.extend([f"## {title}", "", body, "", "---", ""])

        if s.sensitive_paths:
            rows = [
                "<table><thead><tr><th>Base URL</th><th>Path</th><th>Status</th><th>Sensitivity</th></tr></thead><tbody>",
            ]
            for item in s.sensitive_paths:
                rows.append(
                    f"<tr><td>{html.escape(str(item.get('base_url', '')))}</td><td class='code'>/{html.escape(str(item.get('path', '')))}</td><td>{item.get('status', '')}</td><td style='color:var(--red);'>{str(item.get('sensitivity', 'low')).upper()}</td></tr>"
                )
            rows.append("</tbody></table>")
            section("14. Sensitive Files & Directories", "\n".join(rows))

        if s.sqli_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.sqli_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('domain', item.get('url', ''))))}</code> - {html.escape(str(item.get('output', item)))}</li>")
            rows.append("</ul>")
            section("15. SQL Injection", "\n".join(rows))

        if s.xss_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.xss_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('url', item.get('matched-at', ''))))}</code> - {html.escape(str(item.get('payload', item.get('data', item))))}</li>")
            rows.append("</ul>")
            section("16. Cross-Site Scripting", "\n".join(rows))

        if s.open_redirects:
            rows = ["<ul class='findings-list'>"]
            for item in s.open_redirects[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("17. Open Redirects", "\n".join(rows))

        if s.ssrf_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.ssrf_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("18. SSRF", "\n".join(rows))

        if s.graphql_endpoints:
            rows = ["<ul class='findings-list'>"]
            for endpoint in s.graphql_endpoints:
                rows.append(f"<li><code>{html.escape(endpoint)}</code></li>")
            rows.append("</ul>")
            section("19. GraphQL Endpoints", "\n".join(rows))

        if s.cors_misconfigs:
            rows = ["<ul class='findings-list'>"]
            for item in s.cors_misconfigs[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("20. CORS Misconfigurations", "\n".join(rows))

        if s.jwt_tokens or s.jwt_issues:
            rows = ["<ul class='findings-list'>"]
            for token in s.jwt_tokens[:10]:
                rows.append(f"<li><code>{html.escape(token[:60] + ('...' if len(token) > 60 else ''))}</code></li>")
            for issue in s.jwt_issues[:10]:
                rows.append(f"<li>{html.escape(str(issue.get('output', issue)))}</li>")
            rows.append("</ul>")
            section("21. JWT Analysis", "\n".join(rows))

        if s.ssti_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.ssti_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('url', '')))}</code></li>")
            rows.append("</ul>")
            section("22. SSTI Findings", "\n".join(rows))

        if s.idor_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.idor_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('url', '')))}</code></li>")
            rows.append("</ul>")
            section("23. IDOR Findings", "\n".join(rows))

        if s.path_traversal_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.path_traversal_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("24. Path Traversal", "\n".join(rows))

        if s.csrf_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.csrf_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("25. CSRF Findings", "\n".join(rows))

        if s.websocket_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.websocket_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("26. WebSocket Findings", "\n".join(rows))

        if s.oauth_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.oauth_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("27. OAuth Findings", "\n".join(rows))

        if s.cache_poisoning_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.cache_poisoning_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('matched-at', item.get('host', ''))))}</code></li>")
            rows.append("</ul>")
            section("28. Cache Poisoning", "\n".join(rows))

        if s.info_disclosures:
            rows = ["<ul class='findings-list'>"]
            for item in s.info_disclosures[:50]:
                rows.append(
                    f"<li><code>{html.escape(str(item.get('url', '')))}</code> - {html.escape(str(item.get('path', '')))} (status {item.get('status', '')})</li>"
                )
            rows.append("</ul>")
            section("29. Information Disclosures", "\n".join(rows))

        if s.race_condition_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.race_condition_findings[:50]:
                rows.append(f"<li><code>{html.escape(str(item.get('url', '')))}</code></li>")
            rows.append("</ul>")
            section("30. Race Conditions", "\n".join(rows))

        if s.smuggling_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.smuggling_findings[:50]:
                rows.append(f"<li class='finding-item critical'><strong>Smuggling</strong> at {html.escape(str(item.get('url', '')))}</li>")
            rows.append("</ul>")
            section("31. HTTP Request Smuggling", "\n".join(rows))
        else:
            section("31. HTTP Request Smuggling", "<p>No request smuggling detected.</p>")

        if s.prototype_pollution:
            rows = ["<ul class='findings-list'>"]
            for item in s.prototype_pollution[:50]:
                rows.append(f"<li class='finding-item high'><code>{html.escape(str(item.get('js_url', '')))}</code> – see output</li>")
            rows.append("</ul>")
            section("32. Prototype Pollution", "\n".join(rows))
        else:
            section("32. Prototype Pollution", "<p>No client-side prototype pollution found.</p>")

        if s.bypass_403_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.bypass_403_findings[:50]:
                rows.append(f"<li class='finding-item medium'>Original: {html.escape(str(item.get('original', '')))} → {html.escape(str(item.get('bypass_method', '')))}</li>")
            rows.append("</ul>")
            section("33. 403 Bypasses", "\n".join(rows))
        else:
            section("33. 403 Bypasses", "<p>No 403 bypasses achieved.</p>")

        if s.hidden_params:
            rows = ["<ul class='findings-list'>"]
            for item in s.hidden_params[:50]:
                rows.append(f"<li class='finding-item info'><code>{html.escape(str(item.get('url', '')))}</code> → param: {html.escape(str(item.get('param', '')))}</li>")
            rows.append("</ul>")
            section("34. Hidden Parameters", "\n".join(rows))
        else:
            section("34. Hidden Parameters", "<p>No hidden parameters discovered.</p>")

        if s.api_schema_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.api_schema_findings[:50]:
                rows.append(f"<li class='finding-item high'><code>{html.escape(str(item.get('schema_url', '')))}</code> – failures found</li>")
            rows.append("</ul>")
            section("35. API Logic Bugs (Schemathesis)", "\n".join(rows))
        else:
            section("35. API Logic Bugs (Schemathesis)", "<p>No OpenAPI schema issues detected.</p>")

        if s.mass_assignment_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.mass_assignment_findings[:50]:
                rows.append(f"<li class='finding-item medium'><strong>{html.escape(str(item.get('template-id', '')))}</strong> at {html.escape(str(item.get('matched-at', '')))}</li>")
            rows.append("</ul>")
            section("36. Mass Assignment", "\n".join(rows))
        else:
            section("36. Mass Assignment", "<p>No mass assignment vulnerabilities.</p>")

        if s.dast_findings:
            rows = ["<ul class='findings-list'>"]
            for item in s.dast_findings[:100]:
                info = item.get("info", {}) if isinstance(item, dict) else {}
                name = info.get("name", item.get("template-id", "DAST finding")) if isinstance(info, dict) else item.get("template-id", "")
                sev = str(info.get("severity", "")).lower() if isinstance(info, dict) else ""
                sev_class = sev if sev in {"critical", "high", "medium", "info"} else "high"
                matched = item.get("matched-at", item.get("host", "")) if isinstance(item, dict) else ""
                rows.append(
                    f"<li class='finding-item {sev_class}'><strong>{html.escape(str(name))}</strong>"
                    f" [{html.escape(sev or 'n/a')}] at <code>{html.escape(str(matched))}</code></li>"
                )
            rows.append("</ul>")
            section("37. DAST Parameter Fuzzing (XSS/SQLi/SSTI/LFI/Redirect)", "\n".join(rows))
        else:
            section(
                "37. DAST Parameter Fuzzing (XSS/SQLi/SSTI/LFI/Redirect)",
                "<p>No DAST/fuzzing findings on parameterized URLs.</p>",
            )

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
        # All automated deep-scan findings come BEFORE the human-validation block.
        self._md_advanced_findings(md_lines, session)
        self._md_tool_summary(md_lines, session)
        self._md_warnings(md_lines, session)
        self._md_data_sources(md_lines, session)
        # --- Human validation & testing required (always last) ---
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
  :root {{
    --bg: #000000;
    --surface: #1c1c1e;
    --surface-2: #2c2c2e;
    --border: #3a3a3c;
    --text: #f5f5f7;
    --text-dim: #86868b;
    --accent: #30d158;
    --accent-dim: #1c4228;
    --cyan: #64d2ff;
    --purple: #bf5af2;
    --orange: #ff9f0a;
    --red: #ff453a;
    --yellow: #ffd60a;
    --mono: 'SF Mono', 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
    --sans: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: var(--sans);
    max-width: 1120px;
    margin: 0 auto;
    padding: 2.5rem 2rem 3rem;
    background: var(--bg);
    color: var(--text);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }}
  h1 {{
    color: var(--text);
    font-size: 1.75rem;
    font-weight: 600;
    letter-spacing: -0.02em;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.75rem;
    margin-bottom: 1.5rem;
  }}
  h2 {{
    color: var(--accent);
    font-size: 1.15rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    border-bottom: 1px solid var(--surface-2);
    padding-bottom: 0.35rem;
    margin-top: 2.5rem;
  }}
  h3 {{ color: var(--cyan); font-weight: 600; font-size: 1rem; }}
  h4 {{ color: var(--orange); font-weight: 600; }}
  table {{
    border-collapse: separate;
    border-spacing: 0;
    width: 100%;
    margin: 1rem 0;
    font-size: 0.9rem;
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }}
  th {{
    background: var(--surface);
    color: var(--text-dim);
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 0.65rem 0.85rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.55rem 0.85rem;
    border-bottom: 1px solid var(--surface-2);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:nth-child(even) td {{ background: rgba(28, 28, 30, 0.55); }}
  .metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 0.65rem;
    margin: 1.25rem 0 1.75rem;
  }}
  .metric-card {{
    background: linear-gradient(145deg, var(--surface) 0%, rgba(28,28,30,0.6) 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 0.85rem 1rem;
    backdrop-filter: blur(8px);
  }}
  .metric-card h3 {{
    margin: 0 0 0.4rem;
    font-size: 0.68rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-weight: 600;
  }}
  .metric-card .value {{
    font-size: 1.65rem;
    font-weight: 700;
    color: var(--text);
    line-height: 1;
    font-variant-numeric: tabular-nums;
  }}
  .findings-list {{ margin: 0.75rem 0 0; padding-left: 1.1rem; }}
  .finding-item {{ margin: 0.35rem 0; padding: 0.15rem 0; }}
  .finding-item.critical {{ color: var(--red); }}
  .finding-item.high {{ color: var(--orange); }}
  .finding-item.medium {{ color: var(--yellow); }}
  .finding-item.info {{ color: var(--cyan); }}
  code, pre, .code {{
    background: var(--surface);
    padding: 0.15rem 0.45rem;
    border-radius: 6px;
    font-family: var(--mono);
    font-size: 0.85em;
    color: var(--accent);
    border: 1px solid var(--surface-2);
  }}
  pre {{
    padding: 1rem 1.1rem;
    overflow-x: auto;
    border-radius: 12px;
    line-height: 1.45;
  }}
  blockquote {{
    border-left: 3px solid var(--accent);
    padding: 0.65rem 1rem;
    background: var(--surface);
    margin: 1rem 0;
    color: var(--text-dim);
    border-radius: 0 10px 10px 0;
  }}
  hr {{ border: none; border-top: 1px solid var(--surface-2); margin: 2.5rem 0; }}
  a {{ color: var(--cyan); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .banner {{
    background: linear-gradient(135deg, rgba(48,209,88,0.08) 0%, var(--surface) 100%);
    border: 1px solid var(--accent-dim);
    padding: 0.85rem 1.1rem;
    border-radius: 14px;
    margin-bottom: 2rem;
    color: var(--accent);
    font-size: 0.88rem;
    letter-spacing: 0.01em;
  }}
  section {{
    margin: 2rem 0;
    padding: 1.25rem 0 0;
    border-top: 1px solid var(--surface-2);
  }}
  .report-footer {{
    color: var(--text-dim);
    font-size: 0.78rem;
    text-align: center;
    letter-spacing: 0.03em;
  }}
</style>
</head>
<body>
<div class="banner">
  authorized use only — sensitive security assessment data. handle per your org classification policy.
</div>
{body}
<hr>
<p class="report-footer">
  BountyMind · session {html.escape(session.session_id)}
  · {html.escape(session.start_time.strftime('%Y-%m-%d %H:%M UTC'))}
</p>
</body>
</html>
"""
