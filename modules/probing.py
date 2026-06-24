"""
modules/probing.py
------------------
ProbingModule: live host verification, port scanning, service detection,
HTTP probing, technology/WAF detection, and directory discovery.

Tool selection rationale:

- httpx (go): ProjectDiscovery's HTTP prober. Captures status, title,
  tech, headers, redirects in one pass. Non-intrusive by design.
  Source: https://github.com/projectdiscovery/httpx
  Classification: Open / Free
  Fallback: httprobe (simpler; enabled in config) if httpx is unavailable

- nmap (apt): Industry-standard port scanner. Used with conservative timing
  (-T2) and service version detection (no script intensity > 3).
  Classification: Open / Free
  Safety: -T2 timing, limited port set, no aggressive scripts

- whatweb (apt): Technology fingerprinting. Passive HTTP header analysis.
  Classification: Open / Free

- wafw00f (apt): WAF detection tool. Passive fingerprinting via HTTP.
  Classification: Open / Free

- ffuf (apt/go): Fast directory/file brute-forcer. Used with very low
  rate limits and shallow recursion to stay non-disruptive.
  Source: https://github.com/ffuf/ffuf
  Classification: Open / Free
  Fallback: dirsearch (github) if ffuf is unavailable

- dirsearch (github): Python-based dir scanner. Alternative to ffuf.
  Source: https://github.com/maurosoria/dirsearch
  Classification: Open / Free

Safety notes:
- nmap uses -T2 (polite) timing and limited port list by default.
- ffuf uses rate_limit=10 req/s and no recursion by default.
- No credential stuffing, brute-force auth, or intrusive scripts.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.config_manager import ConfigManager
from utils.exceptions import ToolNotFoundError
from utils.logger import get_logger
from utils.models import DirectoryFinding, LiveHost, PortService, SubdomainRecord
from utils.output_helpers import OutputManager, parse_line_delimited
from utils.progress import ProgressManager
from utils.runner import CommandRunner
from utils.wordlists import get_wordlist

log = get_logger("probing")

# Paths that indicate interesting/sensitive endpoints worth flagging
INTERESTING_PATH_PATTERNS = re.compile(
    r"(admin|administrator|login|dashboard|portal|console|panel|api|swagger|"
    r"openapi|graphql|metrics|debug|health|actuator|management|config|backup|"
    r"\.env|\.git|\.svn|\.htaccess|\.htpasswd|web\.config|phpinfo|server-status|"
    r"wp-admin|wp-login|phpmyadmin|cpanel|plesk|webmail|remote|vpn|upload|"
    r"install|setup|xmlrpc|\.bak|\.sql|\.zip|\.tar|\.log)",
    re.IGNORECASE,
)


class ProbingModule:
    """
    Performs live host probing, port scanning, and directory discovery
    on the subdomain list produced by DiscoveryModule.
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
        self,
        targets: List[str],
        subdomains: List[SubdomainRecord],
    ) -> Tuple[List[LiveHost], List[PortService], List[DirectoryFinding]]:
        """
        Run all probing phases. Returns (live_hosts, port_services, dir_findings).
        """
        self._progress.print_phase("Phase 1 — Live Host Probing & Service Detection")

        # Build full host list: original targets + discovered subdomains
        all_hosts = list({r.domain for r in subdomains} | set(targets))
        log.info("Probing %d hosts", len(all_hosts))

        # 1. HTTP probing
        live_hosts = self._probe_http(all_hosts)
        self._progress.print_success(
            f"HTTP probing complete — {len(live_hosts)} live hosts"
        )

        # 2. Port scanning (on live hosts + original targets)
        port_services: List[PortService] = []
        if self._cfg.port_scan_enabled:
            scan_targets = list({h.url.split("//")[-1].split("/")[0].split(":")[0]
                                  for h in live_hosts} | set(targets))
            # Prefer naabu for fast broad discovery, fall back to nmap for depth
            if self._cfg.naabu_enabled and self._cfg.is_tool_enabled("naabu") and \
                    self._runner.check_binary_available(self._cfg.get_tool_binary("naabu")):
                port_services = self._scan_ports_naabu(scan_targets)
            else:
                port_services = self._scan_ports(scan_targets)
            self._progress.print_success(
                f"Port scan complete — {len(port_services)} open ports"
            )

        # 3. Technology & WAF detection
        if self._cfg.tech_detection_enabled or self._cfg.waf_detection_enabled:
            live_hosts = self._enrich_hosts(live_hosts)

        # 4. Directory/file discovery
        dir_findings: List[DirectoryFinding] = []
        if self._cfg.dir_discovery_enabled:
            live_urls = [h.url for h in live_hosts]
            dir_findings = self._discover_dirs(live_urls)
            self._progress.print_success(
                f"Directory discovery complete — {len(dir_findings)} paths found"
            )

        # Persist results
        self._save_results(live_hosts, port_services, dir_findings)
        return live_hosts, port_services, dir_findings

    # ------------------------------------------------------------------
    # HTTP probing
    # ------------------------------------------------------------------

    def _probe_http(self, hosts: List[str]) -> List[LiveHost]:
        """
        Probe all hosts for live HTTP/HTTPS services using httpx.
        Falls back to httprobe if httpx is unavailable.
        """
        live_hosts: List[LiveHost] = []

        # Build URL list (try both http and https)
        urls = []
        for host in hosts:
            if host.startswith(("http://", "https://")):
                urls.append(host)
            else:
                urls.append(f"http://{host}")
                urls.append(f"https://{host}")

        # Write URL list to a temp file
        url_list_path = self._out.base / "tmp_probe_list.txt"
        url_list_path.write_text("\n".join(urls), encoding="utf-8")

        task = self._progress.add_task("[cyan]HTTP Probing", total=len(urls))

        if self._cfg.is_tool_enabled("httpx"):
            live_hosts = self._run_httpx(url_list_path)
        elif self._cfg.is_tool_enabled("httprobe"):
            live_hosts = self._run_httprobe(hosts)
        else:
            log.warning("Neither httpx nor httprobe is enabled; skipping HTTP probing")
            self._progress.print_warning("httpx/httprobe not available — skipping HTTP probing")

        self._progress.advance(task, amount=len(urls))
        url_list_path.unlink(missing_ok=True)
        return live_hosts

    def _run_httpx(self, url_list_path: Path) -> List[LiveHost]:
        """
        Run httpx with JSON output for structured parsing.
        Captures: status, title, tech, content-length, location, server.
        """
        binary = self._cfg.get_tool_binary("httpx")
        timeout = self._cfg.http_timeout
        threads = self._cfg.http_threads

        cmd = [
            binary,
            "-l", str(url_list_path),
            "-json",
            "-silent",
            "-timeout", str(timeout),
            "-threads", str(threads),
            "-title",
            "-status-code",
            "-content-length",
            "-location",
            "-tech-detect",
            "-server",
            "-no-color",
        ]

        if self._cfg.get("probing", "follow_redirects", default=True):
            cmd += ["-follow-redirects", "-max-redirects", "5"]

        result = self._runner.run(
            tool_name="httpx",
            cmd=cmd,
            target="batch",
            timeout=self._cfg.tool_timeout,
            save_raw=True,
        )

        return self._parse_httpx_output(result.stdout)

    def _parse_httpx_output(self, stdout: str) -> List[LiveHost]:
        """Parse httpx JSON output lines into LiveHost records."""
        hosts = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = LiveHost(
                    url=data.get("url", ""),
                    status_code=data.get("status-code", 0),
                    title=data.get("title", ""),
                    redirect_url=data.get("location") or None,
                    content_length=data.get("content-length", 0),
                    technologies=data.get("tech", []),
                    server_banner=data.get("webserver", ""),
                    headers=data.get("headers", {}),
                )
                if host.url:
                    hosts.append(host)
            except json.JSONDecodeError:
                log.debug("httpx: could not parse JSON line: %s", line[:100])
        return hosts

    def _run_httprobe(self, hosts: List[str]) -> List[LiveHost]:
        """
        Fallback HTTP prober — simpler than httpx, less metadata.
        """
        binary = self._cfg.get_tool_binary("httprobe")
        hosts_str = "\n".join(hosts)

        # httprobe reads from stdin
        import subprocess
        import os
        try:
            self._runner._ensure_pipx_path()
            proc = subprocess.run(
                [binary],
                input=hosts_str,
                capture_output=True,
                text=True,
                timeout=self._cfg.tool_timeout,
                env=os.environ,
            )
            live_urls = parse_line_delimited(proc.stdout)
            return [LiveHost(url=u, status_code=200) for u in live_urls]
        except Exception as exc:
            log.warning("httprobe failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Port scanning
    # ------------------------------------------------------------------

    def _scan_ports(self, hosts: List[str]) -> List[PortService]:
        """
        Run nmap with conservative settings for service detection.
        Timing T2 (polite), limited port set, no aggressive scripts.
        """
        if not self._cfg.is_tool_enabled("nmap"):
            log.info("nmap disabled in config; skipping port scan")
            return []

        binary = self._cfg.get_tool_binary("nmap")
        ports = self._cfg.ports
        timing = f"-{self._cfg.nmap_timing}"
        nmap_flags = self._cfg.nmap_flags.split()
        services: List[PortService] = []

        task = self._progress.add_task(
            "[cyan]Port Scanning", total=len(hosts)
        )

        for host in hosts:
            self._progress.update_status(task, f"host={host}")
            try:
                host_services = self._run_nmap_host(host, binary, ports, timing, nmap_flags)
                services.extend(host_services)
                log.debug("nmap found %d ports on %s", len(host_services), host)
            except ToolNotFoundError as exc:
                log.warning("nmap not available: %s", exc)
                self._progress.print_warning("nmap not found — skipping port scan")
                break
            except Exception as exc:
                log.warning("nmap failed for %s: %s", host, exc)
            self._progress.advance(task, status=f"{len(services)} ports")

        return services

    def _run_nmap_host(
        self,
        host: str,
        binary: str,
        ports: str,
        timing: str,
        extra_flags: List[str],
    ) -> List[PortService]:
        """Run nmap for a single host and parse grepable output."""
        out_file = self._out.raw_path("nmap", host, "gnmap")

        cmd = [binary, timing, "-p", ports] + extra_flags + [
            "-oG", str(out_file), "--open", host
        ]

        result = self._runner.run(
            tool_name="nmap",
            cmd=cmd,
            target=host,
            timeout=self._cfg.tool_timeout,
            save_raw=False,  # we write oG directly
        )

        return self._parse_nmap_gnmap(host, out_file)

    def _parse_nmap_gnmap(self, host: str, gnmap_path: Path) -> List[PortService]:
        """Parse nmap grepable output for open ports and service info."""
        services: List[PortService] = []
        if not gnmap_path.exists():
            return services

        content = gnmap_path.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            if not line.startswith("Host:"):
                continue
            # Extract ports section
            port_section_match = re.search(r"Ports: (.+?)(?:\s+Ignored|$)", line)
            if not port_section_match:
                continue
            for port_entry in port_section_match.group(1).split(","):
                port_entry = port_entry.strip()
                # Format: port/state/proto/owner/service/rpc_info/version
                parts = port_entry.split("/")
                if len(parts) < 3:
                    continue
                if parts[1].strip() != "open":
                    continue
                services.append(
                    PortService(
                        host=host,
                        port=int(parts[0].strip()),
                        protocol=parts[2].strip() or "tcp",
                        service=parts[4].strip() if len(parts) > 4 else "",
                        version=parts[6].strip() if len(parts) > 6 else "",
                    )
                )
        return services

    # ------------------------------------------------------------------
    # Technology & WAF enrichment
    # ------------------------------------------------------------------

    def _enrich_hosts(self, live_hosts: List[LiveHost]) -> List[LiveHost]:
        """Run whatweb and wafw00f on live hosts to enrich metadata."""
        enriched = []
        task = self._progress.add_task(
            "[cyan]Tech/WAF Detection", total=len(live_hosts)
        )

        for host in live_hosts:
            self._progress.update_status(task, f"url={host.url}")

            if self._cfg.tech_detection_enabled and self._cfg.is_tool_enabled("whatweb"):
                try:
                    techs = self._run_whatweb(host.url)
                    if techs:
                        host.technologies = list(set(host.technologies + techs))
                except Exception as exc:
                    log.debug("whatweb failed for %s: %s", host.url, exc)

            if self._cfg.waf_detection_enabled and self._cfg.is_tool_enabled("wafw00f"):
                try:
                    waf = self._run_wafw00f(host.url)
                    if waf:
                        host.waf = waf
                except Exception as exc:
                    log.debug("wafw00f failed for %s: %s", host.url, exc)

            enriched.append(host)
            self._progress.advance(task)

        return enriched

    def _run_whatweb(self, url: str) -> List[str]:
        """Run whatweb for technology fingerprinting."""
        binary = self._cfg.get_tool_binary("whatweb")
        result = self._runner.run(
            tool_name="whatweb",
            cmd=[binary, "--no-errors", "--quiet", url],
            target=url,
            timeout=30,
            save_raw=True,
        )
        # Parse simple whatweb output: URL [status] Tech1, Tech2, ...
        techs = []
        for line in result.stdout.splitlines():
            m = re.search(r"\[(\d+)\]\s+(.+)$", line)
            if m:
                raw_techs = m.group(2)
                for t in raw_techs.split(","):
                    t = t.strip()
                    if t and not t.startswith("http"):
                        techs.append(t.split("[")[0].strip())
        return techs

    def _run_wafw00f(self, url: str) -> Optional[str]:
        """Run wafw00f for WAF detection."""
        binary = self._cfg.get_tool_binary("wafw00f")
        result = self._runner.run(
            tool_name="wafw00f",
            cmd=[binary, "-a", "-o", "/dev/null", url],
            target=url,
            timeout=30,
            save_raw=True,
        )
        # Look for: "The site ... is behind ... WAF"
        for line in result.stdout.splitlines():
            m = re.search(r"behind (.+?)(?:WAF|Firewall|$)", line, re.IGNORECASE)
            if m:
                return m.group(1).strip()
        return None

    # ------------------------------------------------------------------
    # Directory discovery
    # ------------------------------------------------------------------

    def _discover_dirs(self, urls: List[str]) -> List[DirectoryFinding]:
        """Run directory/file discovery on live URLs."""
        wordlist = get_wordlist("directories", "config/common_dirs.txt")
        if not wordlist:
            log.warning("No valid wordlist found; skipping directory discovery")
            self._progress.print_warning(
                "Directory discovery wordlist not found. "
                "Install seclists: sudo apt install seclists"
            )
            return []

        findings: List[DirectoryFinding] = []
        task = self._progress.add_task(
            "[cyan]Directory Discovery", total=len(urls)
        )

        for url in urls:
            self._progress.update_status(task, f"url={url}")
            try:
                if self._cfg.is_tool_enabled("ffuf"):
                    url_findings = self._run_ffuf(url, wordlist)
                elif self._cfg.is_tool_enabled("dirsearch"):
                    url_findings = self._run_dirsearch(url, wordlist)
                else:
                    log.warning("Neither ffuf nor dirsearch enabled; skipping dir scan for %s", url)
                    url_findings = []

                findings.extend(url_findings)
                log.debug("Directory discovery: %d paths found on %s", len(url_findings), url)
            except ToolNotFoundError as exc:
                log.warning("Dir discovery tool not found: %s", exc)
                self._progress.print_warning(str(exc))
                break
            except Exception as exc:
                log.warning("Dir discovery failed for %s: %s", url, exc)

            self._progress.advance(task, status=f"{len(findings)} found")

        return findings

    def _run_ffuf(self, url: str, wordlist: str) -> List[DirectoryFinding]:
        """
        Run ffuf with safe, low-rate settings.
        Why: Fast, widely used, configurable rate limiting.
        Default: 10 req/s, no recursion, common status codes.
        """
        binary = self._cfg.get_tool_binary("ffuf")
        rate = self._cfg.dir_rate_limit
        match_codes = self._cfg.dir_match_codes
        timeout = self._cfg.dir_timeout
        recursion = self._cfg.dir_recursion_depth
        out_file = self._out.raw_path("ffuf", url.replace("://", "_"), "json")

        fuzz_url = url.rstrip("/") + "/FUZZ"
        cmd = [
            binary,
            "-u", fuzz_url,
            "-w", wordlist,
            "-mc", match_codes,
            "-rate", str(rate),
            "-timeout", str(timeout),
            "-o", str(out_file),
            "-of", "json",
            "-s",  # silent
        ]
        if recursion > 0:
            cmd += ["-recursion", "-recursion-depth", str(recursion)]

        result = self._runner.run(
            tool_name="ffuf",
            cmd=cmd,
            target=url,
            timeout=self._cfg.tool_timeout,
            save_raw=False,
        )

        return self._parse_ffuf_output(url, out_file)

    def _parse_ffuf_output(self, base_url: str, json_path: Path) -> List[DirectoryFinding]:
        """Parse ffuf JSON output."""
        findings = []
        if not json_path.exists():
            return findings
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            for result in data.get("results", []):
                full_url = result.get("url", "")
                status = result.get("status", 0)
                length = result.get("length", 0)
                location = result.get("redirectlocation", "")
                finding = DirectoryFinding(
                    url=full_url,
                    status_code=status,
                    content_length=length,
                    redirect_url=location,
                    source_tool="ffuf",
                    is_interesting=bool(INTERESTING_PATH_PATTERNS.search(full_url)),
                )
                findings.append(finding)
        except (json.JSONDecodeError, KeyError) as exc:
            log.debug("ffuf output parse error for %s: %s", base_url, exc)
        return findings

    def _run_dirsearch(self, url: str, wordlist: str) -> List[DirectoryFinding]:
        """
        Fallback directory scanner using dirsearch.
        Why: Python-based, no compilation needed, good fallback to ffuf.
        """
        binary = self._cfg.get_tool_binary("dirsearch")
        rate = self._cfg.dir_rate_limit
        match_codes = self._cfg.dir_match_codes
        out_file = self._out.raw_path("dirsearch", url.replace("://", "_"), "json")

        # dirsearch may be invoked as a script
        if binary.endswith(".py"):
            script = Path(binary)
            venv_python = script.parent / "venv" / "bin" / "python"
            python_bin = str(venv_python) if venv_python.exists() else "python3"
            cmd_base = [python_bin, binary]
        else:
            cmd_base = [binary]

        cmd = cmd_base + [
            "-u", url,
            "-w", wordlist,
            "-i", match_codes,
            "--rate-limit", str(rate),
            "--format", "json",
            "-o", str(out_file),
            "--quiet",
        ]

        result = self._runner.run(
            tool_name="dirsearch",
            cmd=cmd,
            target=url,
            timeout=self._cfg.tool_timeout,
            save_raw=False,
        )

        return self._parse_dirsearch_output(url, out_file)

    def _parse_dirsearch_output(self, base_url: str, json_path: Path) -> List[DirectoryFinding]:
        """Parse dirsearch JSON output."""
        findings = []
        if not json_path.exists():
            return findings
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
            results = data.get("results", data) if isinstance(data, dict) else data
            for entry in results:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path", "")
                full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
                finding = DirectoryFinding(
                    url=full_url,
                    status_code=entry.get("status", 0),
                    content_length=entry.get("content-length", 0),
                    redirect_url=entry.get("redirect", ""),
                    source_tool="dirsearch",
                    is_interesting=bool(INTERESTING_PATH_PATTERNS.search(full_url)),
                )
                findings.append(finding)
        except (json.JSONDecodeError, KeyError) as exc:
            log.debug("dirsearch parse error for %s: %s", base_url, exc)
        return findings

    # ------------------------------------------------------------------
    # Naabu fast port scanner (optional, disabled by default)
    # ------------------------------------------------------------------

    def _scan_ports_naabu(self, hosts: List[str]) -> List[PortService]:
        """
        Run naabu for fast port scanning.

        Why naabu: ProjectDiscovery's port scanner is significantly faster
        than nmap for initial broad discovery, making it useful when scanning
        large subdomain sets. Used as an opt-in alternative to nmap.
        Source: https://github.com/projectdiscovery/naabu
        Classification: Open / Free

        Safety: Disabled by default (nmap preferred). When enabled, uses
        conservative rate limiting and top-N port presets only.

        Note: naabu requires root/CAP_NET_RAW on Linux for SYN scanning.
        Falls back to CONNECT scan automatically if unprivileged.
        """
        binary = self._cfg.get_tool_binary("naabu")
        ports = self._cfg.naabu_ports
        rate = self._cfg.naabu_rate

        out_file = self._out.raw_path("naabu", "batch", "json")
        services: List[PortService] = []

        task = self._progress.add_task(
            "[cyan]Port Scan (naabu)", total=len(hosts), status="starting"
        )

        for host in hosts:
            self._progress.update_status(task, f"host={host}")
            try:
                cmd = [
                    binary,
                    "-host", host,
                    "-json",
                    "-o", str(out_file),
                    "-silent",
                    "-rate", str(rate),
                ]
                # Map port preset to naabu flags
                if ports == "top-100":
                    cmd += ["-top-ports", "100"]
                elif ports == "top-1000":
                    cmd += ["-top-ports", "1000"]
                else:
                    cmd += ["-p", ports]

                result = self._runner.run(
                    tool_name="naabu",
                    cmd=cmd,
                    target=host,
                    timeout=self._cfg.tool_timeout,
                    save_raw=False,
                )
                if out_file.exists():
                    host_services = self._parse_naabu_output(host, out_file)
                    services.extend(host_services)
                    log.debug("naabu found %d ports on %s", len(host_services), host)
                    out_file.unlink(missing_ok=True)
            except Exception as exc:
                log.warning("naabu failed for %s: %s", host, exc)
            self._progress.advance(task, status=f"{len(services)} ports")

        return services

    def _parse_naabu_output(self, host: str, json_path: Path) -> List[PortService]:
        """Parse naabu JSON output lines into PortService records."""
        services = []
        for line in json_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                port = data.get("port")
                ip = data.get("ip", host)
                if port:
                    services.append(PortService(
                        host=ip,
                        port=int(port),
                        protocol="tcp",
                    ))
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        return services

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_results(
        self,
        live_hosts: List[LiveHost],
        port_services: List[PortService],
        dir_findings: List[DirectoryFinding],
    ) -> None:
        """Save parsed results to output/parsed/."""
        self._out.save_parsed("probing", "live_hosts", [
            {
                "url": h.url,
                "status_code": h.status_code,
                "title": h.title,
                "redirect_url": h.redirect_url,
                "technologies": h.technologies,
                "waf": h.waf,
                "server_banner": h.server_banner,
            }
            for h in live_hosts
        ])

        self._out.save_parsed("probing", "port_services", [
            {
                "host": p.host,
                "port": p.port,
                "protocol": p.protocol,
                "service": p.service,
                "version": p.version,
            }
            for p in port_services
        ])

        self._out.save_parsed("probing", "dir_findings", [
            {
                "url": d.url,
                "status_code": d.status_code,
                "content_length": d.content_length,
                "redirect_url": d.redirect_url,
                "source_tool": d.source_tool,
                "is_interesting": d.is_interesting,
            }
            for d in dir_findings
        ])
