"""
modules/advanced_scanners.py
----------------------------
High-impact, detection-oriented scanner integrations used after the
core discovery, probing, and secret harvesting phases.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from utils.logger import get_logger
from utils.models import CloudBucketFinding, TargetContext
from utils.runner import CommandRunner
from utils.wordlists import get_wordlist

log = get_logger("advanced_scanners")


class _ScannerBase:
    def __init__(self, logger, runner: CommandRunner) -> None:
        self.logger = logger
        self.runner = runner

    def _workspace_dir(self) -> Path:
        """Per-run output base (isolated per website/session via the runner)."""
        return self.runner.base_dir

    def _parsed_dir(self) -> Path:
        path = self.runner.base_dir / "parsed"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _raw_dir(self) -> Path:
        path = self.runner.base_dir / "raw"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _safe_name(value: str) -> str:
        return (
            value.replace("://", "_")
            .replace("/", "_")
            .replace("\\", "_")
            .replace(":", "_")
            .replace("?", "_")
            .replace("&", "_")
            .strip("_")
        )

    @staticmethod
    def _live_urls(target: TargetContext) -> List[str]:
        urls = []
        seen = set()
        for host in target.live_hosts:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            if not url:
                continue
            if url not in seen:
                seen.add(url)
                urls.append(url)
        return urls

    @staticmethod
    def _param_urls(target: TargetContext, limit: int = 1500) -> List[str]:
        """
        Collect URLs that carry query parameters (``?foo=bar``) from harvested
        URLs and live hosts. These are the prime candidates for active testing
        (reflected XSS, SQLi, SSTI, LFI, open-redirect, IDOR, etc.).
        """
        urls: List[str] = []
        seen: set = set()

        def _add(url: Optional[str]) -> None:
            if not url or "?" not in url or "=" not in url:
                return
            if url not in seen:
                seen.add(url)
                urls.append(url)

        for item in getattr(target, "harvested_urls", []) or []:
            url = item.get("url") if isinstance(item, dict) else getattr(item, "url", None)
            _add(url)
        for host in getattr(target, "live_hosts", []) or []:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            _add(url)

        return urls[:limit]

    @staticmethod
    def _live_domains(target: TargetContext) -> List[str]:
        domains = []
        seen = set()
        for host in target.live_hosts:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            if not url:
                continue
            domain = url.split("//", 1)[-1].split("/", 1)[0].strip()
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
        return domains

    def _write_live_urls_file(self, target: TargetContext) -> Path:
        path = self._parsed_dir() / f"live_urls_{target.domain}.txt"
        path.write_text("\n".join(self._live_urls(target)), encoding="utf-8")
        return path

    @staticmethod
    def _append_jsonl_findings(path: Path, bucket: List[Dict[str, Any]]) -> None:
        if not path.exists():
            return
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        bucket.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return

    @staticmethod
    def _parse_json_payload(payload: str) -> List[Dict[str, Any]]:
        payload = (payload or "").strip()
        if not payload:
            return []
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            findings: List[Dict[str, Any]] = []
            for line in payload.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return findings

        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            if isinstance(data.get("results"), list):
                return [item for item in data["results"] if isinstance(item, dict)]
            return [data]
        return []


class SQLiScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        self.logger.info("Starting SQLi detection on live endpoints...")
        if not shutil.which("sqlmap"):
            return
        urls = self._live_urls(target)
        if not urls:
            return

        param_file = self._parsed_dir() / f"params_{target.domain}.txt"
        param_file.parent.mkdir(parents=True, exist_ok=True)
        param_lines: List[str] = []
        seen: set = set()

        # Source 1: parameterized URLs harvested from gau/waybackurls/katana.
        for url in self._param_urls(target, limit=200):
            if url not in seen:
                seen.add(url)
                param_lines.append(url)

        # Source 2: active parameter discovery with arjun (optional).
        if shutil.which("arjun"):
            for url in urls[:20]:
                result = self.runner.run(
                    tool_name="arjun",
                    cmd=["arjun", "-u", url, "--get", "--post", "--stable"],
                    target=url,
                    timeout=60,
                    save_raw=False,
                )
                output = result.stdout or ""
                for line in output.splitlines():
                    line = line.strip()
                    if "http" in line and "?" in line and line not in seen:
                        seen.add(line)
                        param_lines.append(line)

        param_file.write_text("\n".join(param_lines), encoding="utf-8")
        if not param_file.exists() or param_file.stat().st_size == 0:
            self.logger.info("SQLi: no parameterized endpoints discovered; skipping")
            return

        output_dir = self._workspace_dir() / "sqlmap" / target.domain
        output_dir.mkdir(parents=True, exist_ok=True)

        waf_flags: List[str] = []
        if getattr(target, "waf_detections", None):
            waf_flags = ["--tamper=space2comment,between,randomcase", "--skip-waf"]

        result = self.runner.run(
            tool_name="sqlmap",
            cmd=[
                "sqlmap", "-m", str(param_file),
                "--batch", "--random-agent",
                "--level", "2", "--risk", "2",
                "--output-dir", str(output_dir),
                "--technique", "BEUSTQ",
                "--smart",
                *waf_flags,
            ],
            target=target.domain,
            timeout=3600,
            save_raw=False,
            check_exists=False,
        )

        stdout = result.stdout or ""
        if stdout:
            for line in stdout.splitlines():
                normalized = line.lower()
                if "identified the following injection point" in normalized or "parameter:" in normalized:
                    target.sqli_findings.append({
                        "domain": target.domain,
                        "output": line.strip(),
                    })


class XSSScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("dalfox"):
            return

        # Prioritize parameterized URLs (real XSS surface), then fall back to
        # live host roots so nothing is missed.
        param_urls = self._param_urls(target, limit=1000)
        live_urls = self._live_urls(target)
        combined: List[str] = list(dict.fromkeys(param_urls + live_urls))
        if not combined:
            return

        url_file = self._parsed_dir() / f"xss_urls_{target.domain}.txt"
        url_file.write_text("\n".join(combined), encoding="utf-8")
        out_file = self._raw_dir() / f"dalfox_{target.domain}.json"

        self.runner.run(
            tool_name="dalfox",
            cmd=[
                "dalfox", "file", str(url_file),
                "--format", "json",
                "--output", str(out_file),
                "--silence", "--delay", "100",
            ],
            target=target.domain,
            timeout=1200,
            save_raw=False,
            check_exists=False,
        )

        if not out_file.exists():
            return

        try:
            with out_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, list):
                target.xss_findings = data
            elif isinstance(data, dict):
                results = data.get("results")
                if isinstance(results, list):
                    target.xss_findings = results
                else:
                    target.xss_findings.append(data)
        except Exception:
            pass


class AdvancedNucleiScans(_ScannerBase):
    def scan_open_redirects(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_redirect_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "open-redirect/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.open_redirects)

    def scan_ssrf(self, target: TargetContext) -> None:
        if not shutil.which("interactsh-client"):
            return
        live_urls = self._write_live_urls_file(target)
        interactsh = self.runner.run(
            tool_name="interactsh-client",
            cmd=["interactsh-client", "-n", "1", "-o", "stdout"],
            target=target.domain,
            timeout=5,
            save_raw=False,
            check_exists=False,
        )
        interactsh_url = (interactsh.stdout or "").strip()
        if not interactsh_url:
            return

        out_file = self._raw_dir() / f"nuclei_ssrf_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "ssrf/",
                "-var", f"interactsh-url={interactsh_url}",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.ssrf_findings)

    def scan_cors(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_cors_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "cors/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=300,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.cors_misconfigs)

    def scan_csrf(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_csrf_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "csrf/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.csrf_findings)

    def scan_websockets(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_ws_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "websockets/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.websocket_findings)

    def scan_oauth(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_oauth_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "oauth/,openid/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.oauth_findings)

    def scan_cache_poisoning(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_cache_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "cache-poisoning/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.cache_poisoning_findings)

    def scan_path_traversal(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_lfi_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls),
                "-t", "path-traversal/,local-file-include/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.path_traversal_findings)


class GraphQLFinder(_ScannerBase):
    def find_graphql(self, target: TargetContext) -> None:
        for host in target.live_hosts:
            url = host.get("url", "") if isinstance(host, dict) else getattr(host, "url", "")
            if not url:
                continue
            base = url.rstrip("/")
            for path in ["graphql", "gql", "v1/graphql"]:
                candidate = f"{base}/{path}"
                result = self.runner.run(
                    tool_name="curl",
                    cmd=["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", candidate],
                    target=candidate,
                    timeout=20,
                    save_raw=False,
                    check_exists=False,
                )
                if result.stdout and "200" in result.stdout:
                    if candidate not in target.graphql_endpoints:
                        target.graphql_endpoints.append(candidate)


class InfoDisclosure(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        wordlist = Path(get_wordlist("files", "config/sensitive_files.txt"))

        for host in target.live_hosts[:30]:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            if not url:
                continue
            safe_host = self._safe_name(url)
            out_file = self._raw_dir() / f"ffuf_sensitive_{target.domain}_{safe_host}.json"
            self.runner.run(
                tool_name="ffuf",
                cmd=[
                    "ffuf", "-w", str(wordlist), "-u", f"{url.rstrip('/')}/FUZZ",
                    "-sa", "-se", "-sf", "-json", "-o", str(out_file),
                    "-t", "20", "-p", "0.1",
                ],
                target=url,
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if not out_file.exists():
                continue
            try:
                with out_file.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                for res in data.get("results", []):
                    status = res.get("status")
                    if status in [200, 301, 302]:
                        fuzz_input = res.get("input") or {}
                        target.info_disclosures.append({
                            "url": url,
                            "path": fuzz_input.get("FUZZ"),
                            "status": status,
                            "length": res.get("length"),
                        })
            except Exception:
                continue

class JWTScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("jwt_tool"):
            return

        tokens = set(target.jwt_tokens)
        for secret in target.secret_findings:
            val = getattr(secret, "secret_value", "") or ""
            if val.startswith("eyJ"):
                tokens.add(val)

        for host in target.live_hosts:
            url = host.get("url") if isinstance(host, dict) else getattr(host, "url", None)
            if not url:
                continue
            result = self.runner.run(
                tool_name="curl",
                cmd=["curl", "-sI", url],
                target=url,
                timeout=20,
                save_raw=False,
                check_exists=False,
            )
            for line in (result.stdout or "").splitlines():
                if line.lower().startswith("authorization: bearer"):
                    tok = line.split("Bearer ", 1)[-1].strip()
                    if tok:
                        tokens.add(tok)

        target.jwt_tokens = list(tokens)
        if not tokens:
            return

        jwt_dir = self._workspace_dir() / "jwt" / target.domain
        jwt_dir.mkdir(parents=True, exist_ok=True)
        for token in list(tokens)[:10]:
            result = self.runner.run(
                tool_name="jwt_tool",
                cmd=[
                    "jwt_tool", token, "-t", str(jwt_dir / "token.txt"),
                    "-C", "-d", "wordlist/jwt.secrets.list",
                ],
                target=target.domain,
                timeout=300,
                save_raw=False,
                check_exists=False,
            )
            if result.stdout:
                target.jwt_issues.append({"token": token, "output": result.stdout})


class SSTIScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        # tplmap is legacy Python 2 software and is no longer bootstrapped, so
        # this scanner is a no-op unless a user supplies their own `tplmap` on
        # PATH. Server-side template injection is still covered by the nuclei
        # DAST fuzzing phase, which runs by default.
        if not shutil.which("tplmap"):
            return
        for url in self._live_urls(target)[:20]:
            result = self.runner.run(
                tool_name="tplmap",
                cmd=["tplmap", "-u", url, "--os-shell", "--force", "--level", "1"],
                target=url,
                timeout=60,
                save_raw=False,
                check_exists=False,
            )
            output = result.stdout or ""
            if output and "Tested parameters appear to be injectable" in output:
                target.ssti_findings.append({"url": url, "output": output})


class IDORScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        urls = self._live_urls(target)
        if not urls:
            return
        numbers_file = Path("config") / "idor_numbers.txt"
        if not numbers_file.exists():
            numbers_file.parent.mkdir(parents=True, exist_ok=True)
            numbers_file.write_text("\n".join(str(i) for i in range(1, 200)) + "\nadmin\ntest" + "\n", encoding="utf-8")

        for url in urls[:15]:
            safe_name = self._safe_name(url)
            out_file = self._raw_dir() / f"ffuf_idor_{target.domain}_{safe_name}.json"
            result = self.runner.run(
                tool_name="ffuf",
                cmd=[
                    "ffuf", "-u", f"{url.rstrip('/')}/user/profile/FUZZ",
                    "-w", str(numbers_file),
                    "-sa", "-se", "-sf",
                    "-o", str(out_file),
                    "-t", "10", "-p", "0.5",
                ],
                target=url,
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if result.stdout:
                target.idor_findings.append({"url": url, "output": result.stdout})


class RaceConditionTester(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        for host in self._live_urls(target)[:10]:
            result = self.runner.run(
                tool_name="ffuf",
                cmd=[
                    "ffuf", "-u", f"{host.rstrip('/')}/api/coupon/apply",
                    "-X", "POST", "-d", "code=TEST",
                    "-w", "config/numbers.txt",
                    "-sa", "-se", "-sf",
                    "-o", str(self._raw_dir() / f"race_{target.domain}.json"),
                    "-t", "50", "-p", "0.001",
                ],
                target=host,
                timeout=60,
                save_raw=False,
                check_exists=False,
            )
            if result.stdout:
                target.race_condition_findings.append({"url": host, "output": result.stdout})


class CSRFTester(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_csrf_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "csrf/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.csrf_findings)


class WebSocketTester(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_ws_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "websockets/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.websocket_findings)


class OAuthTester(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_oauth_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "oauth/,openid/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.oauth_findings)


class CachePoisoningTester(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_cache_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "cache-poisoning/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.cache_poisoning_findings)


class PathTraversalScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        live_urls = self._write_live_urls_file(target)
        out_file = self._raw_dir() / f"nuclei_lfi_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls),
                "-t", "path-traversal/,local-file-include/",
                "-jsonl", "-o", str(out_file), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(out_file, target.path_traversal_findings)


class SensitiveDirectoryScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        wordlist = Path(get_wordlist("sensitive", "config/sensitive_dirs.txt"))
        max_depth = 3
        for host in self._live_urls(target)[:30]:
            base_url = host.rstrip("/")
            self._fuzz_directory(base_url, target.domain, wordlist, target)
            discovered = self._discovered_dirs(target.sensitive_paths, base_url)
            for depth in range(2, max_depth + 1):
                if not discovered:
                    break
                new_discovered: List[str] = []
                for dir_url in discovered[:10]:
                    self._fuzz_directory(dir_url, target.domain, wordlist, target)
                    new_discovered.extend(self._discovered_dirs(target.sensitive_paths, dir_url))
                discovered = new_discovered

    def _fuzz_directory(self, base_url: str, domain: str, wordlist: Path, target: TargetContext) -> None:
        out_file = self._raw_dir() / f"ffuf_sensitive_{domain}_{os.getpid()}.json"
        self.runner.run(
            tool_name="ffuf",
            cmd=[
                "ffuf", "-w", str(wordlist), "-u", f"{base_url}/FUZZ",
                "-sa", "-se", "-sf", "-json", "-o", str(out_file),
                "-t", "20", "-p", "0.1", "-fc", "404",
            ],
            target=base_url,
            timeout=180,
            save_raw=False,
            check_exists=False,
        )
        if not out_file.exists():
            return
        try:
            with out_file.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            for res in data.get("results", []):
                status = res.get("status")
                if status in [200, 301, 302, 403]:
                    fuzz_input = res.get("input") or {}
                    path = fuzz_input.get("FUZZ")
                    sensitivity = self._classify_sensitivity(path or "")
                    target.sensitive_paths.append({
                        "base_url": base_url,
                        "path": path,
                        "status": status,
                        "length": res.get("length", 0),
                        "sensitivity": sensitivity,
                    })
        except Exception:
            pass

    @staticmethod
    def _discovered_dirs(findings: List[Dict[str, Any]], base_url: str) -> List[str]:
        dirs = []
        for finding in findings:
            if finding.get("base_url") == base_url and finding.get("status") in [301, 302]:
                dirs.append(f"{finding['base_url'].rstrip('/')}/{str(finding['path']).strip('/')}")
        return dirs

    @staticmethod
    def _classify_sensitivity(path: str) -> str:
        p = path.lower()
        if any(x in p for x in [".git", ".svn", ".env", ".aws", ".htpasswd", "id_rsa"]):
            return "critical"
        if any(x in p for x in ["backup", "dump", ".sql", ".bak", "config", "wp-config"]):
            return "high"
        if any(x in p for x in ["log", ".log", "debug", "trace", "phpinfo"]):
            return "medium"
        return "low"

class CloudBucketScanner(_ScannerBase):
    """Scan for open S3, Azure, and GCP buckets using s3scanner plus HTTP checks."""

    def scan_buckets(self, target: TargetContext) -> None:
        self.logger.info("Enumerating cloud storage buckets...")
        keywords = {target.domain, target.session_id}
        keywords.update(self._live_domains(target))
        keywords.update({sub.domain for sub in getattr(target, "subdomains", []) if getattr(sub, "domain", "")})
        keywords.update({item.split(".", 1)[0] for item in self._live_domains(target)})

        if shutil.which("s3scanner"):
            self._run_s3scanner(keywords, target)
        else:
            self.logger.warning("s3scanner not found, falling back to HTTP checks.")

        self._run_http_checks(keywords, target)
        self.logger.info("Cloud scan complete. %d open buckets found.", len(target.cloud_bucket_findings))

    def _run_s3scanner(self, keywords: set[str], target: TargetContext) -> None:
        keyword_file = self._parsed_dir() / f"cloud_keywords_{target.domain}.txt"
        keyword_file.parent.mkdir(parents=True, exist_ok=True)
        with keyword_file.open("w", encoding="utf-8") as fh:
            for kw in sorted(k for k in keywords if k):
                fh.write(f"{kw}\n")
                fh.write(f"{kw}-dev\n")
                fh.write(f"{kw}-prod\n")
                fh.write(f"{kw}-backup\n")
                fh.write(f"dev-{kw}\n")
                fh.write(f"prod-{kw}\n")

        result = self.runner.run(
            tool_name="s3scanner",
            cmd=["s3scanner", "--list", str(keyword_file), "--json"],
            target=target.domain,
            timeout=300,
            save_raw=False,
            check_exists=False,
        )

        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if data.get("exists") or data.get("public"):
                target.cloud_bucket_findings.append(CloudBucketFinding(
                    provider=str(data.get("provider", "aws")).lower(),
                    bucket_name=data.get("name", ""),
                    url=data.get("url", ""),
                    is_public=bool(data.get("public", False)),
                    finding_detail=json.dumps(data, ensure_ascii=False),
                    source_tool="s3scanner",
                ))

    def _run_http_checks(self, keywords: set[str], target: TargetContext) -> None:
        for kw in sorted(k for k in keywords if k):
            candidates = [
                ("AWS", f"http://{kw}.s3.amazonaws.com"),
                ("AWS", f"http://{kw}-dev.s3.amazonaws.com"),
                ("AWS", f"http://dev-{kw}.s3.amazonaws.com"),
                ("Azure", f"http://{kw}.blob.core.windows.net"),
                ("GCP", f"http://storage.googleapis.com/{kw}"),
            ]
            for cloud, url in candidates:
                if self._test_url(url):
                    target.cloud_bucket_findings.append(CloudBucketFinding(
                        provider=cloud.lower(),
                        bucket_name=kw,
                        url=url,
                        is_public=True,
                        finding_detail=f"HTTP fallback matched {url}",
                        source_tool="http",
                    ))

    @staticmethod
    def _test_url(url: str, timeout: int = 5) -> bool:
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=False)
            return response.status_code in [200, 403]
        except Exception:
            return False


class CORSScanner(_ScannerBase):
    def scan_cors(self, target: TargetContext) -> None:
        AdvancedNucleiScans(self.logger, self.runner).scan_cors(target)


class SmugglerScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("smuggler"):
            return

        self.logger.info("Testing for HTTP request smuggling...")
        for url in self._live_urls(target)[:20]:
            result = self.runner.run(
                tool_name="smuggler",
                cmd=["smuggler", "-u", url, "--json"],
                target=url,
                timeout=60,
                save_raw=False,
                check_exists=False,
            )
            output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
            if not output:
                continue
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and data.get("vulnerable"):
                target.smuggling_findings.append({"url": url, "details": data})


class PrototypePollutionScanner(_ScannerBase):
    def __init__(self, logger, runner: CommandRunner, js_miner: Optional[object]) -> None:
        super().__init__(logger, runner)
        self.js_miner = js_miner

    def scan(self, target: TargetContext) -> None:
        if not shutil.which("ppfuzz") or self.js_miner is None:
            return

        self.logger.info("Scanning JavaScript for prototype pollution...")
        js_urls = self._collect_js_urls(target)
        for js_url in js_urls[:30]:
            result = self.runner.run(
                tool_name="ppfuzz",
                cmd=["ppfuzz", "-u", js_url],
                target=js_url,
                timeout=30,
                save_raw=False,
                check_exists=False,
            )
            output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
            if output and "Prototype pollution found" in output:
                target.prototype_pollution.append({"js_url": js_url, "output": output})

    def _collect_js_urls(self, target: TargetContext) -> List[str]:
        if hasattr(self.js_miner, "collect_js_urls"):
            try:
                return list(dict.fromkeys(self.js_miner.collect_js_urls(target)))
            except Exception:
                pass
        if hasattr(self.js_miner, "get_js_urls"):
            try:
                return list(dict.fromkeys(self.js_miner.get_js_urls(target.harvested_urls)))
            except Exception:
                return []
        return []


class Bypass403Scanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        command = self._ensure_bypass_403_tool()
        if not command:
            return

        self.logger.info("Attempting 403 bypass on restricted resources...")
        forbidden = self._collect_forbidden_urls(target)
        for url in list(forbidden)[:20]:
            result = self.runner.run(
                tool_name="bypass-403",
                cmd=command + [url],
                target=url,
                timeout=30,
                save_raw=False,
                check_exists=False,
            )
            output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
            if output and "200 OK" in output:
                target.bypass_403_findings.append({
                    "original": url,
                    "bypass_method": output.splitlines()[0] if output else "unknown",
                })

    def _collect_forbidden_urls(self, target: TargetContext) -> List[str]:
        forbidden: List[str] = []
        seen = set()

        for finding in target.directory_findings:
            if isinstance(finding, dict):
                status = finding.get("status") or finding.get("status_code")
                base_url = finding.get("base_url", "")
                path = finding.get("path", "")
                if status in {401, 403} and base_url and path:
                    url = f"{str(base_url).rstrip('/')}/{str(path).lstrip('/')}"
                else:
                    url = finding.get("url", "")
            else:
                status = getattr(finding, "status_code", None)
                url = getattr(finding, "url", "")
            if status in {401, 403} and url and url not in seen:
                seen.add(url)
                forbidden.append(url)

        for finding in target.sensitive_paths:
            if not isinstance(finding, dict):
                continue
            status = finding.get("status")
            base_url = finding.get("base_url", "")
            path = finding.get("path", "")
            if status in {401, 403} and base_url and path:
                url = f"{str(base_url).rstrip('/')}/{str(path).lstrip('/')}"
                if url not in seen:
                    seen.add(url)
                    forbidden.append(url)

        return forbidden

    def _ensure_bypass_403_tool(self) -> List[str]:
        binary = shutil.which("bypass-403")
        if binary:
            return [binary]

        repo_dir = Path("tools") / "bypass-403"
        script = repo_dir / "bypass-403.sh"
        if not script.exists():
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            result = self.runner.run(
                tool_name="git",
                cmd=["git", "clone", "https://github.com/iamj0ker/bypass-403.git", str(repo_dir)],
                target="bypass-403",
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code != 0 and not script.exists():
                return []

        if not script.exists():
            return []

        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        link_path = local_bin / "bypass-403"
        if not link_path.exists() and not link_path.is_symlink():
            try:
                if os.name == "nt":
                    wrapper = local_bin / "bypass-403.cmd"
                    wrapper.write_text(
                        f'@echo off\r\nbash "{script.resolve()}" %*\r\n',
                        encoding="utf-8",
                    )
                else:
                    os.symlink(str(script.resolve()), str(link_path))
            except OSError:
                pass

        binary = shutil.which("bypass-403") or shutil.which("bypass-403.cmd")
        if binary:
            return [binary]

        bash = shutil.which("bash")
        if bash:
            return [bash, str(script.resolve())]
        sh = shutil.which("sh")
        if sh:
            return [sh, str(script.resolve())]

        return []


class HiddenParamScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("x8"):
            return

        self.logger.info("Discovering hidden parameters with x8...")
        wordlist = self._wordlist_path()
        for url in self._live_urls(target)[:20]:
            result = self.runner.run(
                tool_name="x8",
                cmd=["x8", "-u", url, "--wordlist", str(wordlist)],
                target=url,
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            output = "\n".join(part for part in [result.stdout, result.stderr] if part).strip()
            if not output:
                continue
            for line in output.splitlines():
                if "Parameter found" in line:
                    target.hidden_params.append({"url": url, "param": line.strip()})

    @staticmethod
    def _wordlist_path() -> Path:
        seclists = Path("/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt")
        if seclists.exists():
            return seclists

        path = Path("config") / "parameter_names.txt"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "\n".join([
                    "id", "user", "account", "token", "redirect", "next", "page",
                    "lang", "search", "q", "debug", "role", "admin", "filter",
                ]) + "\n",
                encoding="utf-8",
            )
        return path


class SchemaFuzzer(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("schemathesis"):
            return

        schema_urls = self._schema_urls(target)
        if not schema_urls:
            return

        for url in schema_urls[:5]:
            result = self.runner.run(
                tool_name="schemathesis",
                cmd=["schemathesis", "run", "--checks", "all", "--output-format", "json", url],
                target=url,
                timeout=600,
                save_raw=False,
                check_exists=False,
            )
            output = (result.stdout or "").strip()
            if not output:
                continue
            try:
                results = json.loads(output)
            except json.JSONDecodeError:
                continue

            has_failures = False
            if isinstance(results, dict):
                has_failures = bool(results.get("has_failures"))
            elif isinstance(results, list):
                has_failures = any(
                    isinstance(item, dict) and bool(item.get("has_failures"))
                    for item in results
                )

            if has_failures:
                target.api_schema_findings.append({"schema_url": url, "results": results})

    @staticmethod
    def _schema_urls(target: TargetContext) -> List[str]:
        schema_names = {"swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml"}
        urls: List[str] = []
        seen = set()
        for disc in target.info_disclosures:
            if not isinstance(disc, dict):
                continue
            path = str(disc.get("path", ""))
            if path not in schema_names:
                continue
            base_url = str(disc.get("url", ""))
            if not base_url:
                continue
            schema_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
            if schema_url not in seen:
                seen.add(schema_url)
                urls.append(schema_url)
        return urls


class MassAssignmentScanner(_ScannerBase):
    def scan(self, target: TargetContext) -> None:
        if not shutil.which("nuclei"):
            return

        live_urls = self._write_live_urls_file(target)
        raw = self._raw_dir() / f"nuclei_mass_assignment_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(live_urls), "-t", "mass-assignment/",
                "-jsonl", "-o", str(raw), "-silent",
            ],
            target=target.domain,
            timeout=600,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(raw, target.mass_assignment_findings)


class DASTFuzzingScanner(_ScannerBase):
    """
    Run nuclei's DAST / fuzzing templates against parameterized URLs harvested
    from gau / waybackurls / katana.

    This is the highest-yield bug-bounty surface: it actively fuzzes query
    parameters for reflected XSS, SQLi, SSTI, LFI/path-traversal, open redirect,
    CRLF, SSRF (OAST), and more, using nuclei's `-dast` engine. Detection only —
    no destructive exploitation tags are run.
    """

    def __init__(self, logger, runner: CommandRunner, max_urls: int = 1500) -> None:
        super().__init__(logger, runner)
        self.max_urls = max_urls

    def scan(self, target: TargetContext) -> None:
        if not shutil.which("nuclei"):
            return

        param_urls = self._param_urls(target, limit=self.max_urls)
        if not param_urls:
            self.logger.info("DAST: no parameterized URLs to fuzz; skipping")
            return

        url_file = self._parsed_dir() / f"dast_urls_{target.domain}.txt"
        url_file.write_text("\n".join(param_urls), encoding="utf-8")
        url_file = self._dedupe_params(url_file, target.domain)
        self.logger.info("DAST fuzzing parameterized URLs with nuclei...")

        raw = self._raw_dir() / f"nuclei_dast_{target.domain}.jsonl"
        self.runner.run(
            tool_name="nuclei",
            cmd=[
                "nuclei", "-l", str(url_file),
                "-dast",
                "-jsonl", "-o", str(raw), "-silent",
                "-rate-limit", "50",
                "-exclude-tags", "dos,brute-force,bruteforce,intrusive,destructive,exploit",
            ],
            target=target.domain,
            timeout=1800,
            save_raw=False,
            check_exists=False,
        )
        self._append_jsonl_findings(raw, target.dast_findings)
        self.logger.info("DAST fuzzing complete: %d findings", len(target.dast_findings))

    def _dedupe_params(self, url_file: Path, domain: str) -> Path:
        """Collapse near-duplicate parameterized URLs with uro when available."""
        if not shutil.which("uro"):
            return url_file
        deduped = self._parsed_dir() / f"dast_urls_{domain}_uro.txt"
        self.runner.run(
            tool_name="uro",
            cmd=["uro", "-i", str(url_file), "-o", str(deduped)],
            target="dast-dedupe",
            timeout=120,
            save_raw=False,
            check_exists=False,
        )
        if deduped.exists() and deduped.stat().st_size > 0:
            return deduped
        return url_file
