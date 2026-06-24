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
from typing import Any, Dict, List

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

    @staticmethod
    def _workspace_dir() -> Path:
        return Path("output")

    @staticmethod
    def _parsed_dir() -> Path:
        path = Path("output") / "parsed"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _raw_dir() -> Path:
        path = Path("output") / "raw"
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
        urls = self._live_urls(target)
        if not urls or not shutil.which("sqlmap") or not shutil.which("arjun"):
            return

        param_file = self._parsed_dir() / f"params_{target.domain}.txt"
        param_file.parent.mkdir(parents=True, exist_ok=True)
        param_lines: List[str] = []
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
                if "http" in line and "?" in line:
                    param_lines.append(line)

        param_file.write_text("\n".join(param_lines), encoding="utf-8")
        if not param_file.exists() or param_file.stat().st_size == 0:
            return

        output_dir = Path("output") / "sqlmap" / target.domain
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
        urls = self._live_urls(target)
        if not urls:
            return

        url_file = self._write_live_urls_file(target)
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

        jwt_dir = Path("output") / "jwt" / target.domain
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
        keyword_file = Path("output") / "parsed" / f"cloud_keywords_{target.domain}.txt"
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
