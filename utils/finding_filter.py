"""
utils/finding_filter.py
-----------------------
False-positive reduction and confidence scoring for scan findings.

Goals:
- Keep high-signal, bounty-relevant bugs across all stacks (PHP, Java, Node, …)
- Drop or demote generic scanner noise (tech detect, missing headers, duplicates)
- Deduplicate identical hits from multiple nuclei passes
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.models import LiveHost, NucleiFinding, ScanSession, SecretFinding, Severity

log = get_logger("finding_filter")

# Nuclei template-id / name fragments that are almost always noise in bug-bounty context.
_FP_TEMPLATE_FRAGMENTS = frozenset([
    "tech-detect",
    "waf-detect",
    "favicon-detect",
    "form-detect",
    "options-method",
    "tcp-timestamp",
    "ssl-issuer",
    "ssl-dns",
    "deprecated-tls",
    "weak-cipher",
    "cipher-suite",
    "dns-saas",
    "dns-rebinding",
    "caa-fingerprint",
    "robots-txt",
    "security-txt",
    "sitemap",
    "favicon",
    "http-missing-security-headers",  # generic header bundle — too noisy alone
    "missing-security-headers",
    "x-frame-options",                # informational unless exploitable clickjacking proof
    "x-content-type-options",
    "strict-transport-security",      # missing HSTS — rarely accepted alone
    "content-security-policy",        # missing CSP — informational
    "permissions-policy",
    "referrer-policy",
    "cross-origin-embedder",
    "cross-origin-opener",
    "cross-origin-resource",
])

# Template/name hints that indicate a real, stack-specific vulnerability.
_HIGH_SIGNAL_FRAGMENTS = frozenset([
    "cve-",
    "rce",
    "sqli",
    "sql-injection",
    "xss",
    "ssrf",
    "lfi",
    "rfi",
    "traversal",
    "ssti",
    "idor",
    "auth-bypass",
    "unauth",
    "default-login",
    "takeover",
    "exposure",
    "misconfig",
    "disclosure",
    "injection",
    "upload",
    "deserialization",
    "xxe",
    "redirect",
    "csrf",
    "jwt",
    "graphql",
    "swagger",
    "actuator",
    "phpmyadmin",
    "wp-config",
    "env-file",
    "git-config",
    "backup",
    "shell",
    "command",
])

# Placeholder / example secret values (SecretFinder regex FPs).
_PLACEHOLDER_SECRET_VALUES = re.compile(
    r"(?i)^(example|test|dummy|placeholder|null|undefined|your[_-]?api[_-]?key|"
    r"xxx+|000+|12345|changeme|insert[_-]?here|<api[_-]?key>|sample|fake|"
    r"abcdefghijklmnopqrstuvwxyz|deadbeef|not[_-]?a[_-]?real|sk_test_xxx)$"
)

# Map detected technology strings → nuclei template tags for targeted second pass.
TECH_TO_NUCLEI_TAGS: Dict[str, List[str]] = {
    "php": ["php"],
    "wordpress": ["wordpress", "wp"],
    "wp-": ["wordpress", "wp"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "magento": ["magento"],
    "prestashop": ["prestashop"],
    "laravel": ["laravel"],
    "symfony": ["symfony", "php"],
    "java": ["java"],
    "spring": ["spring", "java"],
    "tomcat": ["tomcat", "java"],
    "weblogic": ["weblogic", "java"],
    "jboss": ["jboss", "java"],
    "struts": ["struts", "java"],
    "asp.net": ["aspnet", "iis"],
    "aspnet": ["aspnet", "iis"],
    "iis": ["iis", "microsoft"],
    "node": ["nodejs"],
    "nodejs": ["nodejs", "express"],
    "express": ["nodejs", "express"],
    "next.js": ["nodejs", "nextjs"],
    "react": ["react"],
    "angular": ["angular"],
    "vue": ["vue"],
    "python": ["python"],
    "django": ["django", "python"],
    "flask": ["flask", "python"],
    "ruby": ["ruby"],
    "rails": ["rails", "ruby"],
    "go": ["golang"],
    "golang": ["golang"],
    "nginx": ["nginx"],
    "apache": ["apache"],
    "graphql": ["graphql"],
    "jenkins": ["jenkins"],
    "kubernetes": ["kubernetes", "k8s"],
    "docker": ["docker"],
    "coldfusion": ["coldfusion"],
    "sharepoint": ["sharepoint", "microsoft"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elastic", "elasticsearch"],
    "grafana": ["grafana"],
    "gitlab": ["gitlab"],
    "confluence": ["confluence", "atlassian"],
    "jira": ["jira", "atlassian"],
    "shopify": ["shopify"],
    "cloudflare": ["cloudflare"],
}


class FindingFilter:
    """Apply FP reduction and confidence scoring to a completed scan session."""

    def __init__(self, config: ConfigManager) -> None:
        self._cfg = config

    @property
    def enabled(self) -> bool:
        return bool(self._cfg.get("scanning", "filter_false_positives", default=True))

    @property
    def dedupe(self) -> bool:
        return bool(self._cfg.get("scanning", "dedupe_findings", default=True))

    @property
    def suppress_generic_info(self) -> bool:
        return bool(self._cfg.get("scanning", "suppress_generic_info", default=True))

    @property
    def min_confidence(self) -> str:
        return str(self._cfg.get("scanning", "min_confidence", default="low")).lower()

    def apply(self, session: ScanSession) -> Dict[str, int]:
        """
        Filter session findings in-place. Returns stats dict:
        {nuclei_before, nuclei_after, nuclei_suppressed, secrets_suppressed, ...}
        """
        stats: Dict[str, int] = {}

        before = len(session.nuclei_findings)
        session.nuclei_findings = self.filter_nuclei(session.nuclei_findings)
        stats["nuclei_before"] = before
        stats["nuclei_after"] = len(session.nuclei_findings)
        stats["nuclei_suppressed"] = before - len(session.nuclei_findings)

        sec_before = len(session.secret_findings)
        session.secret_findings = self.filter_secrets(session.secret_findings)
        stats["secrets_suppressed"] = sec_before - len(session.secret_findings)

        # Dedupe / trim advanced scanner buckets (dict lists).
        session.dast_findings = self._dedupe_dict_findings(session.dast_findings)
        session.xss_findings = self._dedupe_dict_findings(session.xss_findings)
        session.sqli_findings = self._dedupe_dict_findings(session.sqli_findings)
        session.open_redirects = self._dedupe_dict_findings(session.open_redirects)
        session.cors_misconfigs = self._filter_cors(session.cors_misconfigs)
        session.info_disclosures = self._filter_info_disclosures(session.info_disclosures)

        session.filter_stats = stats
        if stats["nuclei_suppressed"] > 0 or stats.get("secrets_suppressed", 0) > 0:
            log.info(
                "Finding filter: nuclei %d→%d (-%d), secrets suppressed=%d",
                stats["nuclei_before"],
                stats["nuclei_after"],
                stats["nuclei_suppressed"],
                stats.get("secrets_suppressed", 0),
            )
        return stats

    def filter_nuclei(self, findings: List[NucleiFinding]) -> List[NucleiFinding]:
        if not self.enabled:
            return findings

        kept: List[NucleiFinding] = []
        seen: Set[Tuple[str, str]] = set()
        min_rank = _confidence_rank(self.min_confidence)

        for f in findings:
            key = (f.template_id.lower(), (f.matched_at or f.host or "").lower())
            if self.dedupe and key in seen:
                continue

            reason = self._nuclei_suppress_reason(f)
            if reason:
                log.debug("Suppressed nuclei FP: %s — %s", f.template_id, reason)
                continue

            confidence = self._score_nuclei_confidence(f)
            f.confidence = confidence
            if _confidence_rank(confidence) < min_rank:
                log.debug("Below min confidence (%s): %s", confidence, f.template_id)
                continue

            seen.add(key)
            kept.append(f)

        return kept

    def filter_secrets(self, findings: List[SecretFinding]) -> List[SecretFinding]:
        if not self.enabled:
            return findings
        kept: List[SecretFinding] = []
        seen: Set[Tuple[str, str]] = set()
        for f in findings:
            val = (f.secret_value or "").strip()
            if not val or _PLACEHOLDER_SECRET_VALUES.match(val):
                continue
            if len(val) < 8:
                continue
            key = (f.url, val[:32])
            if key in seen:
                continue
            seen.add(key)
            kept.append(f)
        return kept

    def _nuclei_suppress_reason(self, f: NucleiFinding) -> Optional[str]:
        tid = f.template_id.lower()
        name = f.name.lower()
        tags = {t.lower() for t in f.tags}

        # Never suppress confirmed high/critical with CVE unless pure detect noise.
        if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.cve_ids:
            if not any(frag in tid for frag in _FP_TEMPLATE_FRAGMENTS):
                return None

        if self.suppress_generic_info and f.severity == Severity.INFO:
            if tags & {"tech", "detect", "dns", "ssl", "tls", "network"}:
                return "generic info/tech/detect"
            if any(frag in tid or frag in name for frag in _FP_TEMPLATE_FRAGMENTS):
                return "generic info template"

        if any(frag in tid or frag in name for frag in _FP_TEMPLATE_FRAGMENTS):
            # Keep if high-signal tag also present (e.g. CVE on same template path).
            if not any(sig in tid or sig in name for sig in _HIGH_SIGNAL_FRAGMENTS):
                if f.severity not in (Severity.CRITICAL, Severity.HIGH):
                    return "known noisy template"

        # Empty match with no extraction on low/info.
        if f.severity in (Severity.INFO, Severity.LOW) and not f.extracted_results:
            if "detect" in tags and not f.cve_ids:
                return "detect-only without evidence"

        return None

    def _score_nuclei_confidence(self, f: NucleiFinding) -> str:
        tid = f.name.lower() + " " + f.template_id.lower()
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            if f.cve_ids or f.extracted_results:
                return "high"
            if any(sig in tid for sig in _HIGH_SIGNAL_FRAGMENTS):
                return "high"
            return "medium"
        if f.severity == Severity.MEDIUM:
            if f.cve_ids or f.extracted_results:
                return "high"
            if any(sig in tid for sig in _HIGH_SIGNAL_FRAGMENTS):
                return "medium"
            return "low"
        if f.extracted_results or f.cve_ids:
            return "medium"
        return "low"

    @staticmethod
    def _dedupe_dict_findings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen: Set[str] = set()
        out: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            key = str(item.get("matched-at") or item.get("url") or item.get("host") or item)
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out

    @staticmethod
    def _filter_cors(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop CORS hits that reflect the same origin (common FP)."""
        kept: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            host = str(item.get("host", "")).lower()
            matched = str(item.get("matched-at", "")).lower()
            # Nuclei CORS templates often include curl-command in metadata — skip null origins.
            raw = str(item).lower()
            if "access-control-allow-origin: null" in raw and "credentials" not in raw:
                continue
            if host and matched and host.replace("https://", "").replace("http://", "") in matched:
                if "evil" not in raw and "attacker" not in raw:
                    continue
            kept.append(item)
        return kept

    @staticmethod
    def _filter_info_disclosures(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Drop trivial info disclosures (tiny files, common static assets)."""
        trivial = re.compile(
            r"(favicon\.ico|robots\.txt|sitemap\.xml|\.css|\.js|\.png|\.jpg|\.gif|\.svg|"
            r"crossdomain\.xml|browserconfig\.xml|humans\.txt)$",
            re.I,
        )
        kept: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path", "") or item.get("url", ""))
            if trivial.search(path):
                continue
            length = item.get("length")
            if length is not None and int(length or 0) < 20:
                continue
            kept.append(item)
        return kept


def collect_tech_tags(live_hosts: List[LiveHost]) -> List[str]:
    """
    Derive nuclei ``-tags`` from technologies detected during probing.
    Enables framework/language-specific template runs (PHP, Java, Node, …).
    """
    blob_parts: List[str] = []
    for host in live_hosts:
        blob_parts.extend(host.technologies or [])
        if host.server_banner:
            blob_parts.append(host.server_banner)
        if host.title:
            blob_parts.append(host.title)
    blob = " ".join(blob_parts).lower()
    if not blob:
        return []

    tags: Set[str] = set()
    for needle, nuclei_tags in TECH_TO_NUCLEI_TAGS.items():
        if needle in blob:
            tags.update(nuclei_tags)
    return sorted(tags)


def _confidence_rank(level: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(level.lower(), 1)
