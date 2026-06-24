"""
modules/discovery.py
--------------------
DiscoveryModule: passive and active subdomain enumeration.

Tool selection rationale:
- subfinder (go / apt): ProjectDiscovery's passive subdomain enumerator.
  Queries 80+ passive sources without bruteforcing DNS.
  Source: https://github.com/projectdiscovery/subfinder
  Classification: Open / Free (some sources require API keys for higher limits)

- amass (go / apt): OWASP's comprehensive asset enumeration tool.
  Used in passive-only mode by default to avoid intrusive DNS queries.
  Source: https://github.com/owasp-amass/amass
  Classification: Open / Free

- crt.sh (free HTTP API): Certificate Transparency log search.
  No API key required. Used as a reliable direct fallback.
  Classification: Open / Free

Fallback chain: subfinder → amass → crt.sh direct HTTP query.
If all external tools fail, crt.sh HTTP is the minimum viable baseline.

Safety notes:
- amass runs with -passive flag by default (no DNS bruteforce).
- subfinder does not perform brute-force by design.
- CNAME validation is done passively (DNS resolution only, no probing).
"""

from __future__ import annotations

import json
import re
import socket
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

from utils.config_manager import ConfigManager
from utils.exceptions import ToolNotFoundError
from utils.logger import get_logger
from utils.models import SubdomainRecord
from utils.output_helpers import OutputManager, clean_domain_list, parse_line_delimited
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("discovery")

# Known dangling/takeover-prone CNAME patterns (provider-specific)
# These indicate a CNAME target that no longer resolves → takeover risk
TAKEOVER_CNAME_PATTERNS = [
    r"\.github\.io$",
    r"\.amazonaws\.com$",
    r"\.azurewebsites\.net$",
    r"\.cloudapp\.azure\.com$",
    r"\.heroku\.com$",
    r"\.wordpress\.com$",
    r"\.shopify\.com$",
    r"\.ghost\.io$",
    r"\.zendesk\.com$",
    r"\.freshdesk\.com$",
    r"\.unbounce\.com$",
    r"\.leadpages\.net$",
    r"\.bitbucket\.io$",
    r"\.pantheonsite\.io$",
    r"\.fastly\.net$",
]

TAKEOVER_PATTERNS_COMPILED = [re.compile(p) for p in TAKEOVER_CNAME_PATTERNS]


class DiscoveryModule:
    """
    Orchestrates passive subdomain enumeration across multiple tools/sources.

    Execution order for each target:
    1. subfinder (passive multi-source)
    2. amass (passive-only mode)
    3. crt.sh HTTP fallback (always attempted as additional source)
    4. DNS resolution + CNAME analysis for all discovered subdomains
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

    def run(self, targets: List[str]) -> List[SubdomainRecord]:
        """
        Run discovery for all targets. Returns deduplicated SubdomainRecord list.
        """
        self._progress.print_phase("Phase 1 — Subdomain Discovery")
        all_records: List[SubdomainRecord] = []

        task = self._progress.add_task(
            "[cyan]Discovery", total=len(targets), status="starting"
        )

        for target in targets:
            log.info("Starting discovery for target: %s", target)
            self._progress.update_status(task, f"target={target}")
            records = self._discover_target(target)
            all_records.extend(records)
            self._progress.advance(task, status=f"{len(records)} subdomains")
            log.info(
                "Discovery complete for %s: %d subdomains found",
                target, len(records),
            )

        # Save aggregated results
        self._save_results(all_records)
        self._progress.print_success(
            f"Discovery complete — {len(all_records)} total subdomains"
        )
        return all_records

    # ------------------------------------------------------------------
    # Per-target discovery
    # ------------------------------------------------------------------

    def _discover_target(self, target: str) -> List[SubdomainRecord]:
        """Run all discovery tools for a single target domain."""
        raw_subdomains: Dict[str, Set[str]] = {}  # source → set of domains

        # --- Tool 1: subfinder ---
        if self._cfg.is_tool_enabled("subfinder"):
            try:
                subs = self._run_subfinder(target)
                raw_subdomains["subfinder"] = subs
                log.debug("subfinder found %d subdomains for %s", len(subs), target)
            except ToolNotFoundError as exc:
                log.warning("subfinder not available: %s", exc)
                self._progress.print_warning(str(exc))
            except Exception as exc:
                log.warning("subfinder failed for %s: %s", target, exc)

        # --- Tool 2: amass ---
        if self._cfg.is_tool_enabled("amass"):
            try:
                subs = self._run_amass(target)
                raw_subdomains["amass"] = subs
                log.debug("amass found %d subdomains for %s", len(subs), target)
            except ToolNotFoundError as exc:
                log.warning("amass not available: %s", exc)
            except Exception as exc:
                log.warning("amass failed for %s: %s", target, exc)

        # --- Source 3: crt.sh (always attempted; no tool needed) ---
        try:
            subs = self._query_crtsh(target)
            raw_subdomains["crtsh"] = subs
            log.debug("crt.sh found %d subdomains for %s", len(subs), target)
        except Exception as exc:
            log.warning("crt.sh query failed for %s: %s", target, exc)

        # --- Merge and deduplicate ---
        all_subs: Set[str] = set()
        for source, subs in raw_subdomains.items():
            all_subs.update(subs)

        # Clean and validate
        cleaned = clean_domain_list(list(all_subs))

        # Apply max_subdomains safety limit
        max_subs = self._cfg.max_subdomains
        if len(cleaned) > max_subs:
            log.warning(
                "Subdomain count (%d) exceeds max_subdomains=%d for %s; truncating",
                len(cleaned), max_subs, target,
            )
            cleaned = cleaned[:max_subs]

        # --- DNS resolution + CNAME analysis ---
        # Prefer dnsx for bulk resolution when available; fall back to Python socket
        if self._cfg.dnsx_enabled and self._cfg.is_tool_enabled("dnsx") and \
                self._runner.check_binary_available(self._cfg.get_tool_binary("dnsx")):
            records = self._resolve_with_dnsx(cleaned, raw_subdomains)
        else:
            records = self._resolve_subdomains(cleaned, raw_subdomains)

        return records

    # ------------------------------------------------------------------
    # Tool runners
    # ------------------------------------------------------------------

    def _run_subfinder(self, target: str) -> Set[str]:
        """
        Run subfinder in passive mode.
        Why: Excellent passive coverage, 80+ sources, no bruteforce.
        """
        binary = self._cfg.get_tool_binary("subfinder")
        threads = self._cfg.subfinder_threads

        # Build passive source list from config (filter to subfinder-supported)
        source_filter = self._build_subfinder_sources()

        cmd = [binary, "-d", target, "-silent", "-t", str(threads)]
        if source_filter:
            cmd += ["-sources", ",".join(source_filter)]

        # Pass API keys as env vars (subfinder reads SHODAN_API_KEY, etc.)
        env = self._build_api_env()

        result = self._runner.run(
            tool_name="subfinder",
            cmd=cmd,
            target=target,
            timeout=self._cfg.tool_timeout,
            env=env,
            save_raw=True,
        )

        if result.return_code != 0 and not result.timed_out:
            log.debug(
                "subfinder exited %d for %s: %s",
                result.return_code, target, result.stderr[:200],
            )

        return set(parse_line_delimited(result.stdout))

    def _run_amass(self, target: str) -> Set[str]:
        """
        Run amass in passive-only mode.
        Why: OWASP standard; passive mode avoids active DNS bruteforce.
        """
        binary = self._cfg.get_tool_binary("amass")
        out_file = self._out.raw_path("amass", target, "txt")

        cmd = ["amass", "enum", "-passive", "-d", target, "-o", str(out_file)]

        if self._cfg.has_api_key("shodan"):
            # amass can use shodan via config file; log but don't auto-configure
            log.debug("Shodan API key present; amass may use it via ~/.config/amass/")

        result = self._runner.run(
            tool_name="amass",
            cmd=cmd,
            target=target,
            timeout=self._cfg.tool_timeout,
            save_raw=False,  # amass writes to file directly
        )

        # Read from output file
        subs: Set[str] = set()
        if out_file.exists():
            content = out_file.read_text(encoding="utf-8", errors="replace")
            subs = set(parse_line_delimited(content))

        return subs

    def _query_crtsh(self, target: str) -> Set[str]:
        """
        Query crt.sh Certificate Transparency API directly.
        Why: Completely free, no API key, independent of installed tools.
        This ensures a minimum baseline even when all tools are missing.
        Classification: Open / Free (public service)
        """
        url = f"https://crt.sh/?q=%.{target}&output=json"
        subdomains: Set[str] = set()

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconFramework/1.0 (authorized security testing)"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status != 200:
                    return subdomains
                data = json.loads(resp.read().decode("utf-8"))

            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.splitlines():
                    name = name.strip().lstrip("*.")
                    if name and target in name:
                        subdomains.add(name.lower())

        except urllib.error.URLError as exc:
            log.debug("crt.sh request failed for %s: %s", target, exc)
        except json.JSONDecodeError as exc:
            log.debug("crt.sh JSON parse failed for %s: %s", target, exc)
        except Exception as exc:
            log.debug("crt.sh unexpected error for %s: %s", target, exc)

        # Persist raw results
        raw_path = self._out.raw_path("crtsh", target, "json")
        try:
            raw_path.write_text(
                json.dumps(list(subdomains), indent=2), encoding="utf-8"
            )
        except OSError:
            pass

        return subdomains

    # ------------------------------------------------------------------
    # DNS resolution + CNAME analysis
    # ------------------------------------------------------------------

    def _resolve_subdomains(
        self,
        subdomains: List[str],
        source_map: Dict[str, Set[str]],
    ) -> List[SubdomainRecord]:
        """
        Resolve each subdomain to IPs and check for dangling CNAMEs.
        Uses a thread pool for concurrency.
        """
        records: List[SubdomainRecord] = []

        # Build reverse source map: domain → list of sources
        domain_sources: Dict[str, List[str]] = {}
        for source, subs in source_map.items():
            for sub in subs:
                domain_sources.setdefault(sub.lower(), []).append(source)

        max_workers = min(self._cfg.max_concurrency * 2, 30)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(self._resolve_single, sub): sub
                for sub in subdomains
            }
            for future in as_completed(futures):
                sub = futures[future]
                try:
                    record = future.result()
                    record.source = ", ".join(domain_sources.get(sub, ["unknown"]))
                    records.append(record)
                except Exception as exc:
                    log.debug("DNS resolution failed for %s: %s", sub, exc)
                    # Still create a record without IP info
                    records.append(
                        SubdomainRecord(
                            domain=sub,
                            source=", ".join(domain_sources.get(sub, ["unknown"])),
                        )
                    )

        return records

    def _resolve_single(self, domain: str) -> SubdomainRecord:
        """Resolve a single domain. Checks IPs and CNAME."""
        record = SubdomainRecord(domain=domain, source="")

        try:
            # Get A/AAAA records
            addr_infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC)
            ips = list({info[4][0] for info in addr_infos})
            record.ip_addresses = ips
        except socket.gaierror:
            # NXDOMAIN or resolution failure — potential dangling indicator
            record.ip_addresses = []

        # CNAME check (platform-independent via socket)
        try:
            cname = socket.getfqdn(domain)
            if cname and cname.lower() != domain.lower():
                record.cname = cname
                record.dangling_cname = self._is_potential_takeover(cname, record.ip_addresses)
        except Exception:
            pass

        return record

    def _is_potential_takeover(self, cname: str, ips: List[str]) -> bool:
        """
        Heuristic: CNAME points to a known cloud/SaaS provider and
        the target does not resolve to any IPs → possible subdomain takeover.
        """
        if ips:
            return False  # still resolves, less likely to be dangling
        for pattern in TAKEOVER_PATTERNS_COMPILED:
            if pattern.search(cname.lower()):
                return True
        return False

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_subfinder_sources(self) -> List[str]:
        """
        Map config passive_sources to subfinder-compatible source names.
        Only include sources that don't require API keys unless the key is set.
        """
        # Subfinder source names
        always_available = [
            "crtsh", "certspotter", "hackertarget", "dnsdumpster",
            "threatcrowd", "rapiddns", "riddler", "waybackarchive",
        ]
        optional_keyed = {
            "shodan": self._cfg.has_api_key("shodan"),
            "virustotal": self._cfg.has_api_key("virustotal"),
            "securitytrails": self._cfg.has_api_key("securitytrails"),
        }
        sources = list(always_available)
        for src, has_key in optional_keyed.items():
            if has_key:
                sources.append(src)
            else:
                log.debug(
                    "Skipping subfinder source '%s': API key not configured", src
                )
        return sources

    def _build_api_env(self) -> dict:
        """Build environment variables for tool API key injection."""
        env = {}
        if self._cfg.has_api_key("shodan"):
            env["SHODAN_API_KEY"] = self._cfg.api_key("shodan")
        if self._cfg.has_api_key("virustotal"):
            env["VIRUSTOTAL_API_KEY"] = self._cfg.api_key("virustotal")
        if self._cfg.has_api_key("securitytrails"):
            env["SECURITYTRAILS_API_KEY"] = self._cfg.api_key("securitytrails")
        return env

    def run_subzy(self, subdomains: List[SubdomainRecord]) -> List[SubdomainRecord]:
        """
        Run subzy for active subdomain takeover verification.

        Why subzy: While the framework performs heuristic CNAME analysis,
        subzy actively validates each subdomain against known takeover
        fingerprints for 50+ providers (GitHub Pages, Heroku, S3, etc.)
        Source: https://github.com/PentestPad/subzy
        Classification: Open / Free

        Safety: subzy only sends HTTP HEAD/GET requests to check if a
        subdomain resolves to a claimable page — it does NOT claim anything.
        """
        if not self._cfg.is_tool_enabled("subzy"):
            log.debug("subzy disabled in config; skipping active takeover check")
            return subdomains

        binary = self._cfg.get_tool_binary("subzy")
        if not self._runner.check_binary_available(binary):
            log.warning("subzy not found; skipping active takeover verification")
            self._progress.print_warning(
                "subzy not found. Install: go install github.com/PentestPad/subzy@latest"
            )
            return subdomains

        subs_file = self._out.base / "tmp_subzy_input.txt"
        subs_file.write_text(
            "\n".join(r.domain for r in subdomains), encoding="utf-8"
        )
        log.info("Running subzy takeover check on %d subdomains", len(subdomains))

        result = self._runner.run(
            tool_name="subzy",
            cmd=[binary, "run", "--targets", str(subs_file),
                 "--hide_fails", "--output", "json"],
            target="takeover-check",
            timeout=self._cfg.tool_timeout,
            save_raw=True,
        )
        subs_file.unlink(missing_ok=True)

        if result.return_code not in (0, 1):
            log.debug("subzy exited %d. Stderr: %s", result.return_code, result.stderr[:200])
            return subdomains

        import json as _json
        try:
            data = _json.loads(result.stdout)
            vuln_list = data if isinstance(data, list) else data.get("results", [])
            vuln_domains = {
                item.get("subdomain", "").lower()
                for item in vuln_list
                if item.get("vulnerable") or item.get("status") == "VULNERABLE"
            }
            for record in subdomains:
                if record.domain.lower() in vuln_domains:
                    record.dangling_cname = True
                    log.warning("subzy confirmed takeover candidate: %s", record.domain)
                    self._progress.print_warning(
                        f"Takeover candidate confirmed by subzy: {record.domain}"
                    )
        except (_json.JSONDecodeError, TypeError) as exc:
            log.debug("subzy output parse failed: %s", exc)

        return subdomains

    def _resolve_with_dnsx(
        self,
        subdomains: List[str],
        source_map: Dict[str, Set[str]],
    ) -> List[SubdomainRecord]:
        """
        Use dnsx for fast bulk DNS resolution.

        Why dnsx: ProjectDiscovery's dedicated DNS resolver handles thousands
        of subdomains concurrently with retries and wildcard filtering —
        much faster than Python socket threading for large sets.
        Source: https://github.com/projectdiscovery/dnsx
        Classification: Open / Free

        Falls back to _resolve_subdomains (Python socket) on failure.
        """
        import json as _json
        binary = self._cfg.get_tool_binary("dnsx")
        threads = self._cfg.dnsx_threads

        input_file = self._out.base / "tmp_dnsx_input.txt"
        input_file.write_text("\n".join(subdomains), encoding="utf-8")
        out_file = self._out.raw_path("dnsx", "batch", "json")

        result = self._runner.run(
            tool_name="dnsx",
            cmd=[binary, "-l", str(input_file), "-a", "-cname", "-resp",
                 "-json", "-o", str(out_file), "-silent", "-t", str(threads)],
            target="batch",
            timeout=self._cfg.tool_timeout,
            save_raw=False,
        )
        input_file.unlink(missing_ok=True)

        if result.return_code != 0:
            log.warning("dnsx failed (rc=%d); falling back to Python socket resolution",
                        result.return_code)
            return self._resolve_subdomains(subdomains, source_map)

        domain_sources: Dict[str, List[str]] = {}
        for source, subs in source_map.items():
            for sub in subs:
                domain_sources.setdefault(sub.lower(), []).append(source)

        records: List[SubdomainRecord] = []
        resolved_domains: set = set()

        if out_file.exists():
            for line in out_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = _json.loads(line)
                    host = data.get("host", "").lower()
                    a_records = data.get("a", [])
                    cname_list = data.get("cname", [])
                    cname = cname_list[0] if cname_list else None
                    resolved_domains.add(host)
                    is_dangling = bool(cname and not a_records and
                                       self._is_potential_takeover(cname, a_records))
                    records.append(SubdomainRecord(
                        domain=host,
                        source=", ".join(domain_sources.get(host, ["unknown"])),
                        ip_addresses=a_records,
                        cname=cname,
                        dangling_cname=is_dangling,
                    ))
                except (_json.JSONDecodeError, KeyError):
                    pass

        # Unresolved = NXDOMAIN (potential dangling)
        for sub in subdomains:
            if sub.lower() not in resolved_domains:
                records.append(SubdomainRecord(
                    domain=sub,
                    source=", ".join(domain_sources.get(sub.lower(), ["unknown"])),
                    ip_addresses=[],
                ))

        log.info("dnsx resolved %d/%d subdomains", len(resolved_domains), len(subdomains))
        return records

    def _save_results(self, records: List[SubdomainRecord]) -> None:
        """Persist aggregated results to parsed output."""
        data = [
            {
                "domain": r.domain,
                "source": r.source,
                "ip_addresses": r.ip_addresses,
                "cname": r.cname,
                "dangling_cname": r.dangling_cname,
            }
            for r in records
        ]
        for target in {r.domain.split(".")[-2] + "." + r.domain.split(".")[-1] for r in records if "." in r.domain}:
            path = self._out.save_parsed("discovery", target, data)
            log.debug("Saved discovery results to %s", path)
