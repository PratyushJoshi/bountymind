"""
modules/updater.py
------------------
ToolUpdater: validates tool installation, detects versions, suggests updates,
and refreshes nuclei templates.

Supported tool source types (tracked in config):
  apt     — managed via apt/apt-get on Debian-based systems
  go      — installed via 'go install <module>@latest'
  github  — cloned from GitHub or downloaded as a release binary
  local   — custom user-provided path; framework does not manage updates

Why this approach:
  Kali Linux ships many security tools via apt, but Go-based tools from
  ProjectDiscovery (nuclei, httpx, subfinder) are often more current on
  their GitHub releases than in distro packages. Supporting both source
  types lets the framework adapt to mixed installations.

Safety:
  - This module only checks versions and suggests install commands.
  - It does NOT automatically run apt install or go install without
    the --update-tools flag being explicitly passed by the user.
  - nuclei template updates (-update-templates) are the exception:
    they are triggered automatically as they are safe, read-only.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.platform_utils import PlatformInfo
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("updater")

PROJECT_REPO_URL = "https://github.com/PratyushJoshi/bountymind.git"


@dataclass
class ToolStatus:
    name: str
    enabled: bool
    source: str
    binary: str
    found: bool
    version: str = ""
    install_hint: str = ""
    update_hint: str = ""
    notes: str = ""


# Map from tool name → (go install module, apt package, version flag)
TOOL_REGISTRY: Dict[str, Dict] = {
    "subfinder": {
        "go_module": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "apt_package": "subfinder",
        "version_flag": "-version",
    },
    "amass": {
        "go_module": "github.com/owasp-amass/amass/v4/...",
        "apt_package": "amass",
        "version_flag": "-version",
    },
    "httpx": {
        "go_module": "github.com/projectdiscovery/httpx/cmd/httpx",
        "apt_package": "httpx-toolkit",
        "version_flag": "-version",
    },
    "httprobe": {
        "go_module": "github.com/tomnomnom/httprobe",
        "apt_package": "",
        "version_flag": "--help",
    },
    "nuclei": {
        "go_module": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "apt_package": "nuclei",
        "version_flag": "-version",
    },
    "ffuf": {
        "go_module": "github.com/ffuf/ffuf/v2",
        "apt_package": "ffuf",
        "version_flag": "-V",
    },
    "dirsearch": {
        "go_module": "",
        "apt_package": "",
        "git_repo": "https://github.com/maurosoria/dirsearch.git",
        "git_dest": "/opt/dirsearch",
        "version_flag": "--version",
    },
    "nmap": {
        "go_module": "",
        "apt_package": "nmap",
        "version_flag": "--version",
    },
    "whatweb": {
        "go_module": "",
        "apt_package": "whatweb",
        "version_flag": "--version",
    },
    "wafw00f": {
        "go_module": "",
        "apt_package": "wafw00f",
        "version_flag": "--version",
    },
    # ------------------------------------------------------------------
    # Extended tools (AegisAutomata integration)
    # ------------------------------------------------------------------
    "gau": {
        "go_module": "github.com/lc/gau/v2/cmd/gau",
        "apt_package": "",
        "version_flag": "--version",
        "notes": "GetAllURLs — passive URL harvesting from AlienVault, Wayback, CommonCrawl",
    },
    "waybackurls": {
        "go_module": "github.com/tomnomnom/waybackurls",
        "apt_package": "",
        "version_flag": "--help",
        "notes": "Fetch URLs from the Wayback Machine for a domain",
    },
    "katana": {
        "go_module": "github.com/projectdiscovery/katana/cmd/katana",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "Next-gen web crawler with JS rendering support",
    },
    "dnsx": {
        "go_module": "github.com/projectdiscovery/dnsx/cmd/dnsx",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "Fast bulk DNS resolver — replaces Python socket threading for large sets",
    },
    "naabu": {
        "go_module": "github.com/projectdiscovery/naabu/v2/cmd/naabu",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "Fast port scanner — disabled by default; nmap preferred for safety",
    },
    "subzy": {
        "go_module": "github.com/PentestPad/subzy",
        "apt_package": "",
        "version_flag": "version",
        "notes": "Active subdomain takeover verification tool",
    },
    "gowitness": {
        "go_module": "github.com/sensepost/gowitness",
        "apt_package": "",
        "version_flag": "version",
        "notes": "Web screenshot utility using a headless browser",
    },
    "secretfinder": {
        "go_module": "",
        "apt_package": "",
        "git_repo": "https://github.com/m4ll0k/SecretFinder.git",
        "git_dest": "tools/SecretFinder",
        "pip_requirements": "tools/SecretFinder/requirements.txt",
        "version_flag": "--help",
        "notes": "JavaScript secret/credential mining tool",
    },
    "arjun": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "arjun",
        "version_flag": "--help",
        "notes": "HTTP parameter discovery — used for WAF evasion parameter mining",
    },
    "s3scanner": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "s3scanner",
        "version_flag": "--help",
        "notes": "S3 bucket misconfiguration scanner",
    },
    "uro": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "uro",
        "version_flag": "--help",
        "notes": "URL deduplication and filtering utility",
    },
    "xnlinkfinder": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "xnlinkfinder",
        "version_flag": "--help",
        "notes": "Extract endpoints and parameters from JS/HTML",
    },
    "cdncheck": {
        "go_module": "github.com/projectdiscovery/cdncheck/cmd/cdncheck",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "CDN/WAF provider detection helper",
    },
    "shuffledns": {
        "go_module": "github.com/projectdiscovery/shuffledns/cmd/shuffledns",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "Mass DNS brute-force wrapper (disabled in safe mode by default)",
    },
    "notify": {
        "go_module": "github.com/projectdiscovery/notify/cmd/notify",
        "apt_package": "",
        "version_flag": "-version",
        "notes": "Notification dispatcher for scan output",
    },
    "dalfox": {
        "go_module": "github.com/hahwul/dalfox/v2",
        "apt_package": "",
        "version_flag": "version",
        "notes": "XSS parameter analyzer — manual follow-up only",
    },
    "jwt_tool": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "jwt_tool",
        "version_flag": "--help",
        "notes": "JWT analysis and tamper testing utility",
    },
    "tplmap": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "tplmap",
        "version_flag": "--help",
        "notes": "Template injection detector and exploitation helper",
    },
    "sqlmap": {
        "go_module": "",
        "apt_package": "sqlmap",
        "version_flag": "--version",
        "notes": "SQL injection tool — not run automatically; env check only",
    },
    "trufflehog": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "truffleHog",
        "version_flag": "--help",
        "notes": "Secret scanning — optional manual follow-up",
    },
}

# pipx-managed Python CLIs (Kali-safe isolated installs)
PYTHON_PIPX_TOOLS: Dict[str, str] = {
    "s3scanner": "s3scanner",
    "uro": "uro",
    "xnlinkfinder": "xnlinkfinder",
    "wafw00f": "wafw00f",
    "arjun": "arjun",
    "jwt_tool": "jwt_tool",
    "tplmap": "tplmap",
}

# High-bounty optional Python scanners installed via pipx/pip during bootstrap.
# (Only genuine PyPI packages belong here. smuggler/ppfuzz/x8 are NOT pip packages
#  — they are handled by dedicated git/cargo bootstrappers below.)
PYTHON_PIPX_ADVANCED: Dict[str, str] = {
    "schemathesis": "schemathesis",
}

# Rust/cargo-based scanners (installed via `cargo install` during bootstrap).
CARGO_BOOTSTRAP_TOOLS: Dict[str, str] = {
    "ppfuzz": "ppfuzz",  # client-side prototype pollution fuzzer
    "x8": "x8",          # hidden parameter discovery
}

# Git-cloned script tools that get a small PATH wrapper.
GIT_WRAPPER_TOOLS: Dict[str, Dict[str, str]] = {
    "smuggler": {
        "repo": "https://github.com/defparam/smuggler.git",
        "dest": "tools/smuggler",
        "script": "smuggler.py",
    },
    "bypass-403": {
        "repo": "https://github.com/iamj0ker/bypass-403.git",
        "dest": "tools/bypass-403",
        "script": "bypass-403.sh",
    },
}

# Go tools installed during full bootstrap
GO_BOOTSTRAP_TOOLS: Dict[str, str] = {
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "subzy": "github.com/PentestPad/subzy@latest",
    "gowitness": "github.com/sensepost/gowitness@latest",
    "cdncheck": "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "shuffledns": "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
    "notify": "github.com/projectdiscovery/notify/cmd/notify@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
}

# Required binaries for verify_environment() / --check-env exit code
CORE_ENV_TOOLS: List[str] = [
    "nuclei", "httpx", "subfinder", "ffuf", "whatweb", "nmap",
]

OPTIONAL_ENV_TOOLS: List[str] = [
    "dalfox", "sqlmap", "trufflehog", "jwt_tool", "tplmap",
    "smuggler", "ppfuzz", "x8", "schemathesis", "bypass-403",
]


class ToolUpdater:
    """
    Checks tool availability, reports status, and emits install/update hints.
    Optionally runs safe update operations when --update-tools is passed.
    """

    def __init__(
        self,
        config: ConfigManager,
        runner: CommandRunner,
        progress: ProgressManager,
        platform: PlatformInfo,
    ) -> None:
        self._cfg = config
        self._runner = runner
        self._progress = progress
        self._platform = platform

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_environment(self) -> List[ToolStatus]:
        """
        Check all configured tools and return their status.
        Logs warnings for missing tools without raising errors.
        """
        log.info("Running environment health check...")
        statuses: List[ToolStatus] = []

        for tool_name, registry in TOOL_REGISTRY.items():
            if not self._cfg.is_tool_enabled(tool_name):
                log.debug("Tool %s is disabled in config; skipping check", tool_name)
                continue
            status = self._check_tool(tool_name, registry)
            statuses.append(status)

            if not status.found:
                log.warning(
                    "Tool not found: %s — %s",
                    tool_name, status.install_hint,
                )
                self._progress.print_warning(
                    f"{tool_name} not found. {status.install_hint}"
                )
            else:
                log.debug(
                    "Tool available: %s %s (source=%s)",
                    tool_name, status.version, status.source,
                )

        self._print_status_table(statuses)
        return statuses

    def verify_environment(self) -> bool:
        """
        Verify bootstrap-managed tools are callable.
        Returns True when all required tools are on PATH.
        """
        required = (
            list(PYTHON_PIPX_TOOLS.keys())
            + list(GO_BOOTSTRAP_TOOLS.keys())
            + CORE_ENV_TOOLS
        )
        missing = [t for t in required if not self._tool_available(t)]
        optional_missing = [t for t in OPTIONAL_ENV_TOOLS if not self._tool_available(t)]

        if missing:
            log.warning("Missing required tools: %s", ", ".join(missing))
            self._progress.print_error(
                f"Missing required tools: {', '.join(missing)}"
            )
            self._progress.print_info("Run: bountymind --bootstrap")
            return False

        if optional_missing:
            log.info("Optional tools not installed: %s", ", ".join(optional_missing))
            self._progress.print_warning(
                f"Optional tools not installed: {', '.join(optional_missing)}"
            )

        log.info("Environment check passed. All required tools available.")
        self._progress.print_success("Environment check passed. All required tools available.")
        return True

    def bootstrap_all_tools(self, dry_run: bool = False) -> None:
        """One-shot installation of all external dependencies."""
        self._progress.print_phase("Bootstrapping All Reconnaissance Tools")
        log.info("Bootstrapping all required reconnaissance tools...")

        if dry_run:
            self._progress.print_info("Dry-run: showing bootstrap actions only")
            self._ensure_pipx(dry_run=True)
            for tool, pkg in PYTHON_PIPX_TOOLS.items():
                self._progress.print_info(f"Would pipx install: {tool} ({pkg})")
            for tool, pkg in PYTHON_PIPX_ADVANCED.items():
                self._progress.print_info(f"Would pipx install: {tool} ({pkg})")
            for tool, pkg in CARGO_BOOTSTRAP_TOOLS.items():
                self._progress.print_info(f"Would cargo install: {tool} ({pkg})")
            for tool, meta in GIT_WRAPPER_TOOLS.items():
                self._progress.print_info(f"Would clone + wrap: {tool} ({meta['repo']})")
            for tool, repo in GO_BOOTSTRAP_TOOLS.items():
                self._progress.print_info(f"Would go install: {tool} ({repo})")
            self._progress.print_info("Would apt install: sqlmap")
            self._progress.print_info("Would clone SecretFinder + venv")
            self._update_nuclei_templates(dry_run=True)
            return

        # Python framework requirements
        req_file = Path(__file__).parent.parent / "requirements.txt"
        if req_file.exists() and self._platform.has_pip:
            self._progress.print_info("Installing Python requirements...")
            self._runner.run(
                tool_name="pip3",
                cmd=["pip3", "install", "-q", "-r", str(req_file)],
                target="requirements",
                timeout=300,
                save_raw=False,
                check_exists=False,
            )

        self._ensure_pipx(dry_run=False)
        self._bootstrap_pipx_tools(dry_run=False)
        self._bootstrap_pipx_advanced_tools(dry_run=False)
        self._bootstrap_cargo_tools(dry_run=False)
        self._bootstrap_smuggler(dry_run=False)
        self._bootstrap_bypass_403(dry_run=False)
        self._bootstrap_go_tools(dry_run=False)
        self._bootstrap_sqlmap(dry_run=False)
        self._bootstrap_secretfinder_venv(dry_run=False)
        self._update_nuclei_templates(dry_run=False)

        log.info("Bootstrap finished. All tools installed.")
        self._progress.print_success("Bootstrap finished. Run `bountymind --check-env` to verify.")

    def _tool_available(self, name: str) -> bool:
        return bool(self._platform.resolve_binary(name) or shutil.which(name))

    def _ensure_pipx_on_path(self) -> None:
        pipx_bin = Path.home() / ".local" / "bin"
        current = os.environ.get("PATH", "")
        if pipx_bin.exists() and str(pipx_bin) not in current:
            os.environ["PATH"] = current + os.pathsep + str(pipx_bin)

    def _ensure_pipx(self, dry_run: bool = False) -> None:
        if shutil.which("pipx"):
            self._ensure_pipx_on_path()
            return
        if not self._platform.is_linux or not self._platform.has_apt:
            log.debug("pipx not available; falling back to pip3 for Python tools")
            return

        self._progress.print_info("Installing pipx (Kali-safe Python tool isolation)...")
        if dry_run:
            return

        self._runner.run(
            tool_name="apt",
            cmd=["sudo", "apt", "update", "-y"],
            target="pipx",
            timeout=300,
            save_raw=False,
            check_exists=False,
        )
        result = self._runner.run(
            tool_name="apt",
            cmd=["sudo", "apt", "install", "-y", "pipx"],
            target="pipx",
            timeout=300,
            save_raw=False,
            check_exists=False,
        )
        if result.return_code == 0:
            self._ensure_pipx_on_path()
            self._progress.print_success("pipx installed")
        else:
            self._progress.print_warning("pipx install failed; using pip3 fallback")

    def _bootstrap_pipx_tools(self, dry_run: bool = False) -> None:
        use_pipx = shutil.which("pipx") is not None
        self._progress.print_phase("Python Security Tools")

        for tool, pkg in PYTHON_PIPX_TOOLS.items():
            if self._tool_available(tool):
                if use_pipx and not dry_run:
                    self._runner.run(
                        tool_name="pipx",
                        cmd=["pipx", "upgrade", pkg],
                        target=tool,
                        timeout=120,
                        save_raw=False,
                        check_exists=False,
                    )
                continue

            if dry_run:
                self._progress.print_info(f"Would install {tool}")
                continue

            self._progress.print_info(f"Installing {tool}...")
            if use_pipx:
                result = self._runner.run(
                    tool_name="pipx",
                    cmd=["pipx", "install", pkg],
                    target=tool,
                    timeout=300,
                    save_raw=False,
                    check_exists=False,
                )
            else:
                result = self._runner.run(
                    tool_name="pip3",
                    cmd=["pip3", "install", "-q", pkg],
                    target=tool,
                    timeout=300,
                    save_raw=False,
                    check_exists=False,
                )

            if result.return_code == 0:
                self._progress.print_success(f"Installed {tool}")
            else:
                self._progress.print_warning(f"Failed to install {tool}")
                if tool == "tplmap":
                    self._bootstrap_tplmap_fallback(dry_run=dry_run)

    def _bootstrap_pipx_advanced_tools(self, dry_run: bool = False) -> None:
        """Install optional high-bounty Python scanners via pipx/pip."""
        use_pipx = shutil.which("pipx") is not None
        self._progress.print_phase("Advanced Python Security Tools")

        for tool, pkg in PYTHON_PIPX_ADVANCED.items():
            if self._tool_available(tool):
                if use_pipx and not dry_run:
                    self._runner.run(
                        tool_name="pipx",
                        cmd=["pipx", "upgrade", pkg],
                        target=tool,
                        timeout=120,
                        save_raw=False,
                        check_exists=False,
                    )
                continue

            if dry_run:
                self._progress.print_info(f"Would install {tool}")
                continue

            self._progress.print_info(f"Installing {tool}...")
            if use_pipx:
                result = self._runner.run(
                    tool_name="pipx",
                    cmd=["pipx", "install", pkg],
                    target=tool,
                    timeout=300,
                    save_raw=False,
                    check_exists=False,
                )
            else:
                result = self._runner.run(
                    tool_name="pip3",
                    cmd=["pip3", "install", "-q", pkg],
                    target=tool,
                    timeout=300,
                    save_raw=False,
                    check_exists=False,
                )

            if result.return_code == 0:
                self._progress.print_success(f"Installed {tool}")
            else:
                self._progress.print_warning(f"Failed to install {tool} (optional)")

    def _bootstrap_bypass_403(self, dry_run: bool = False) -> None:
        """Clone bypass-403 script and expose it on PATH when missing."""
        if self._tool_available("bypass-403"):
            return

        repo_dir = Path("tools") / "bypass-403"
        script = repo_dir / "bypass-403.sh"

        if dry_run:
            self._progress.print_info("Would clone bypass-403 and link into ~/.local/bin")
            return

        if not script.exists():
            self._progress.print_info("Cloning bypass-403...")
            result = self._runner.run(
                tool_name="git",
                cmd=["git", "clone", "https://github.com/iamj0ker/bypass-403.git", str(repo_dir)],
                target="bypass-403",
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code != 0 and not script.exists():
                self._progress.print_warning("bypass-403 clone failed (optional)")
                return

        if not script.exists():
            return

        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            wrapper = local_bin / "bypass-403.cmd"
            wrapper.write_text(
                f'@echo off\r\nbash "{script.resolve()}" %*\r\n',
                encoding="utf-8",
            )
        else:
            link_path = local_bin / "bypass-403"
            try:
                if link_path.exists() or link_path.is_symlink():
                    link_path.unlink()
                os.symlink(str(script.resolve()), str(link_path))
            except OSError as exc:
                log.debug("Could not link bypass-403: %s", exc)
                return

        self._ensure_pipx_on_path()
        self._progress.print_success("bypass-403 ready (local wrapper)")

    def _bootstrap_cargo_tools(self, dry_run: bool = False) -> None:
        """Install Rust/cargo scanners (ppfuzz, x8) via `cargo install`."""
        if not self._platform.has_cargo:
            if any(not self._tool_available(t) for t in CARGO_BOOTSTRAP_TOOLS):
                self._progress.print_warning(
                    "cargo (Rust) not found — skipping ppfuzz/x8. "
                    "Install Rust: https://rustup.rs then re-run --bootstrap"
                )
            return

        self._progress.print_phase("Rust Security Tools (cargo)")
        for tool, crate in CARGO_BOOTSTRAP_TOOLS.items():
            if self._tool_available(tool):
                continue
            if dry_run:
                self._progress.print_info(f"Would cargo install {crate}")
                continue
            self._progress.print_info(f"cargo installing {tool}...")
            result = self._runner.run(
                tool_name="cargo",
                cmd=["cargo", "install", crate],
                target=tool,
                timeout=900,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code == 0:
                # cargo installs to ~/.cargo/bin — make sure that's on PATH
                self._ensure_cargo_on_path()
                self._progress.print_success(f"Installed {tool}")
            else:
                self._progress.print_warning(f"Failed to install {tool} (optional)")

    def _ensure_cargo_on_path(self) -> None:
        cargo_bin = Path.home() / ".cargo" / "bin"
        current = os.environ.get("PATH", "")
        if cargo_bin.exists() and str(cargo_bin) not in current:
            os.environ["PATH"] = current + os.pathsep + str(cargo_bin)

    def _bootstrap_smuggler(self, dry_run: bool = False) -> None:
        """Clone defparam/smuggler and expose a `smuggler` wrapper on PATH."""
        if self._tool_available("smuggler"):
            return

        meta = GIT_WRAPPER_TOOLS["smuggler"]
        repo_dir = Path(meta["dest"])
        script = repo_dir / meta["script"]

        if dry_run:
            self._progress.print_info("Would clone smuggler and link into ~/.local/bin")
            return

        if not script.exists():
            self._progress.print_info("Cloning smuggler...")
            result = self._runner.run(
                tool_name="git",
                cmd=["git", "clone", meta["repo"], str(repo_dir)],
                target="smuggler",
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code != 0 and not script.exists():
                self._progress.print_warning("smuggler clone failed (optional)")
                return
        if not script.exists():
            return

        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            wrapper = local_bin / "smuggler.cmd"
            wrapper.write_text(
                f'@echo off\r\npython "{script.resolve()}" %*\r\n', encoding="utf-8"
            )
        else:
            wrapper = local_bin / "smuggler"
            wrapper.write_text(
                "#!/bin/bash\n"
                f'exec python3 "{script.resolve()}" "$@"\n',
                encoding="utf-8",
            )
            try:
                os.chmod(wrapper, 0o755)
            except OSError:
                pass
        self._ensure_pipx_on_path()
        self._progress.print_success("smuggler ready (local wrapper)")

    def _bootstrap_tplmap_fallback(self, dry_run: bool = False) -> None:
        """Install tplmap from GitHub if pipx/pip installation is unavailable."""
        tplmap_dir = Path("tools") / "tplmap"
        venv_dir = tplmap_dir / "venv"
        wrapper = Path.home() / ".local" / "bin" / "tplmap"

        if dry_run:
            self._progress.print_info("Would clone tplmap and create a local wrapper")
            return

        if not tplmap_dir.exists():
            self._progress.print_info("Cloning tplmap repository...")
            result = self._runner.run(
                tool_name="git",
                cmd=["git", "clone", "https://github.com/epinna/tplmap.git", str(tplmap_dir)],
                target="tplmap",
                timeout=120,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code != 0:
                self._progress.print_warning("tplmap clone failed")
                return

        if not venv_dir.exists():
            self._runner.run(
                tool_name="python3",
                cmd=["python3", "-m", "venv", str(venv_dir)],
                target="tplmap-venv",
                timeout=60,
                save_raw=False,
                check_exists=False,
            )

        pip_bin = venv_dir / "bin" / "pip"
        req_file = tplmap_dir / "requirements.txt"
        if pip_bin.exists() and req_file.exists():
            self._runner.run(
                tool_name="pip",
                cmd=[str(pip_bin), "install", "-r", str(req_file)],
                target="tplmap-deps",
                timeout=180,
                save_raw=False,
                check_exists=False,
            )

        wrapper.parent.mkdir(parents=True, exist_ok=True)
        script = (
            "#!/bin/bash\n"
            f"{str((venv_dir / 'bin' / 'python').resolve())} {str((tplmap_dir / 'tplmap.py').resolve())} \"$@\"\n"
        )
        wrapper.write_text(script, encoding="utf-8")
        os.chmod(wrapper, 0o755)
        self._ensure_pipx_on_path()
        self._progress.print_success("tplmap ready (local wrapper)")

    def _bootstrap_sqlmap(self, dry_run: bool = False) -> None:
        if not self._platform.is_linux or not self._platform.has_apt:
            return
        if self._tool_available("sqlmap"):
            return
        if dry_run:
            self._progress.print_info("Would apt install: sqlmap")
            return

        self._progress.print_info("Installing sqlmap via apt...")
        self._runner.run(
            tool_name="apt",
            cmd=["sudo", "apt", "update", "-y"],
            target="sqlmap",
            timeout=300,
            save_raw=False,
            check_exists=False,
        )
        result = self._runner.run(
            tool_name="apt",
            cmd=["sudo", "apt", "install", "-y", "sqlmap"],
            target="sqlmap",
            timeout=300,
            save_raw=False,
            check_exists=False,
        )
        if result.return_code == 0:
            self._progress.print_success("Installed sqlmap")
        else:
            self._progress.print_warning("Failed to install sqlmap")

    def _bootstrap_go_tools(self, dry_run: bool = False) -> None:
        if not self._platform.has_go:
            self._progress.print_warning("Go not found — skipping Go tool bootstrap")
            return

        self._progress.print_phase("Go Security Tools")
        go_bin = self._platform.go_bin_dir or (Path.home() / "go" / "bin")

        for tool, repo in GO_BOOTSTRAP_TOOLS.items():
            if self._tool_available(tool):
                continue
            if dry_run:
                self._progress.print_info(f"Would go install {tool}")
                continue

            self._progress.print_info(f"go installing {tool}...")
            result = self._runner.run(
                tool_name="go-install",
                cmd=["go", "install", "-v", repo],
                target=tool,
                timeout=600,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code == 0:
                self._promote_go_binary(tool, go_bin)
                self._progress.print_success(f"Installed {tool}")
            else:
                self._progress.print_warning(f"Failed to install {tool}")

    def _promote_go_binary(self, tool: str, go_bin: Path) -> None:
        """Copy a Go-built binary onto PATH (~/.local/bin, then /usr/local/bin)."""
        src = go_bin / tool
        if not src.exists():
            resolved = self._platform.resolve_binary(tool)
            if resolved:
                src = Path(resolved)
            else:
                return

        local_bin = Path.home() / ".local" / "bin"
        local_bin.mkdir(parents=True, exist_ok=True)
        dest = local_bin / tool
        try:
            shutil.copy2(src, dest)
            os.chmod(dest, 0o755)
            self._ensure_pipx_on_path()
        except OSError as exc:
            log.debug("Could not copy %s to ~/.local/bin: %s", tool, exc)

        system_dest = Path(f"/usr/local/bin/{tool}")
        if system_dest.exists() or not shutil.which("sudo"):
            return
        try:
            subprocess.run(
                ["sudo", "cp", str(src), str(system_dest)],
                check=False,
                timeout=30,
                capture_output=True,
            )
            subprocess.run(
                ["sudo", "chmod", "+x", str(system_dest)],
                check=False,
                timeout=10,
                capture_output=True,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _bootstrap_secretfinder_venv(self, dry_run: bool = False) -> None:
        secretfinder_dir = Path(
            self._cfg.get(
                "secret_scanning", "secretfinder_path",
                default="tools/SecretFinder/SecretFinder.py",
            )
        ).parent

        script_path = secretfinder_dir / "SecretFinder.py"
        if script_path.exists():
            return

        if dry_run:
            self._progress.print_info(f"Would clone SecretFinder to {secretfinder_dir}")
            return

        self._progress.print_info("Cloning SecretFinder...")
        secretfinder_dir.parent.mkdir(parents=True, exist_ok=True)
        result = self._runner.run(
            tool_name="git",
            cmd=[
                "git", "clone",
                "https://github.com/m4ll0k/SecretFinder.git",
                str(secretfinder_dir),
            ],
            target="secretfinder",
            timeout=120,
            save_raw=False,
            check_exists=False,
        )
        if result.return_code != 0:
            self._progress.print_warning("SecretFinder clone failed")
            return

        venv_dir = secretfinder_dir / "venv"
        if not venv_dir.exists():
            self._runner.run(
                tool_name="python3",
                cmd=["python3", "-m", "venv", str(venv_dir)],
                target="secretfinder-venv",
                timeout=60,
                save_raw=False,
                check_exists=False,
            )

        pip_bin = venv_dir / "bin" / "pip"
        req_file = secretfinder_dir / "requirements.txt"
        if pip_bin.exists() and req_file.exists():
            self._runner.run(
                tool_name="pip",
                cmd=[str(pip_bin), "install", "-r", str(req_file)],
                target="secretfinder-deps",
                timeout=180,
                save_raw=False,
                check_exists=False,
            )
            self._progress.print_success("SecretFinder ready (venv)")

    def install_advanced_tools(self, dry_run: bool = False) -> None:
        """
        Install Python-based security tools via pipx/pip (wafw00f, arjun, s3scanner).
        Safe to call on first run after git clone.
        """
        pipx_tools = dict(PYTHON_PIPX_ADVANCED)  # schemathesis (real pip package)
        pip_tools = {
            "wafw00f": "wafw00f",
            "arjun": "arjun",
            "s3scanner": "s3scanner",
            "jwt_tool": "jwt_tool",
            "tplmap": "tplmap",
        }
        use_pipx = shutil.which("pipx") is not None
        if use_pipx:
            self._ensure_pipx_on_path()

        self._progress.print_phase("Installing Python Security Tools")
        for tool_name, pip_package in pipx_tools.items():
            if shutil.which(tool_name) or self._platform.resolve_binary(tool_name):
                log.debug("%s already available", tool_name)
                continue
            if dry_run:
                installer = "pipx install" if use_pipx else "pip3 install"
                self._progress.print_info(f"Would run: {installer} {pip_package}")
                continue
            self._progress.print_info(f"Installing {tool_name}...")
            if use_pipx:
                result = self._runner.run(
                    tool_name="pipx",
                    cmd=["pipx", "install", pip_package],
                    target=tool_name,
                    timeout=300,
                    save_raw=False,
                    check_exists=False,
                )
            else:
                result = self._runner.run(
                    tool_name="pip3",
                    cmd=["pip3", "install", "-q", pip_package],
                    target=tool_name,
                    timeout=180,
                    save_raw=False,
                    check_exists=False,
                )
            if result.return_code == 0:
                self._progress.print_success(f"Installed {tool_name}")
            else:
                hint = f"pipx install {pip_package}" if use_pipx else self._platform.pip_install_hint(pip_package)
                self._progress.print_warning(
                    f"Failed to install {tool_name}. Run manually: {hint}"
                )

        for tool_name, pip_package in pip_tools.items():
            if not self._cfg.is_tool_enabled(tool_name):
                continue
            if shutil.which(tool_name) or self._platform.resolve_binary(tool_name):
                log.debug("%s already available", tool_name)
                continue
            hint = self._platform.pip_install_hint(pip_package)
            if dry_run:
                self._progress.print_info(f"Would install: {hint}")
                continue
            self._progress.print_info(f"Installing {tool_name} via pip...")
            result = self._runner.run(
                tool_name="pip3",
                cmd=["pip3", "install", "-q", pip_package],
                target=tool_name,
                timeout=180,
                save_raw=False,
                check_exists=False,
            )
            if result.return_code == 0:
                self._progress.print_success(f"Installed {tool_name}")
            else:
                self._progress.print_warning(
                    f"Failed to install {tool_name}. Run manually: {hint}"
                )
                if tool_name == "tplmap":
                    self._bootstrap_tplmap_fallback(dry_run=dry_run)

        # Rust + git-based high-bounty scanners (correct install methods)
        self._bootstrap_cargo_tools(dry_run=dry_run)
        self._bootstrap_smuggler(dry_run=dry_run)
        self._bootstrap_bypass_403(dry_run=dry_run)

    def auto_install_missing(self, dry_run: bool = False) -> None:
        """
        Lightweight auto-install on first scan — delegates to bootstrap subset.
        """
        if dry_run:
            self.bootstrap_all_tools(dry_run=True)
            return
        self.bootstrap_all_tools(dry_run=False)

    def update_tools(self, dry_run: bool = False) -> None:
        """
        Suggest or run updates for installed Go/apt tools.
        If dry_run=True, only prints what would be run.
        """
        self._progress.print_phase("Tool Update Check")
        self.install_advanced_tools(dry_run=dry_run)
        statuses = self.check_environment()

        for status in statuses:
            if not status.found:
                self._progress.print_info(
                    f"MISSING {status.name}: {status.install_hint}"
                )
                continue

            if status.update_hint:
                if dry_run:
                    self._progress.print_info(
                        f"UPDATE AVAILABLE {status.name}: {status.update_hint}"
                    )
                else:
                    self._run_update(status)

        # Always update nuclei templates (safe, read-only)
        self._update_nuclei_templates(dry_run)

        # Ensure SecretFinder is cloned (safe, one-time git clone)
        if self._cfg.secret_scanning_enabled:
            self.ensure_secretfinder(dry_run)

    def self_update(self, dry_run: bool = False) -> int:
        """
        Fast-forward this local BountyMind checkout from GitHub and rerun
        install.sh only when new repository changes were applied.

        Returns a process-style exit code:
        - 0: up to date, updated successfully, or dry-run completed
        - 1: update/install failed or repository state is unsafe
        """
        self._progress.print_phase("BountyMind Self Update")
        repo_root = self._git(["rev-parse", "--show-toplevel"]).strip()
        if not repo_root:
            self._progress.print_error("This command must be run inside a git checkout.")
            return 1

        repo = Path(repo_root)
        current_branch = self._git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo).strip()
        if not current_branch or current_branch == "HEAD":
            self._progress.print_error("Cannot self-update from a detached HEAD checkout.")
            return 1

        before = self._git(["rev-parse", "HEAD"], cwd=repo).strip()
        remote_ref = ""
        upstream = self._git(
            ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
            cwd=repo,
            allow_failure=True,
        ).strip()
        if not upstream:
            upstream = self._default_upstream(repo)
        if upstream:
            remote_ref = upstream
        else:
            remote_ref = "FETCH_HEAD"
        if not upstream:
            self._progress.print_warning(
                f"No upstream branch found. Falling back to official repo: {PROJECT_REPO_URL}"
            )

        if dry_run:
            fetch_msg = (
                f"git fetch origin --prune ({repo})"
                if upstream else f"git fetch {PROJECT_REPO_URL} ({repo})"
            )
            self._progress.print_info(f"Would run: {fetch_msg}")
            self._progress.print_info(f"Would fast-forward {current_branch} from {remote_ref}")
            self._progress.print_info("Would run install.sh only if HEAD changes")
            return 0

        unstaged = self._run_git(["diff", "--quiet"], cwd=repo)
        staged = self._run_git(["diff", "--cached", "--quiet"], cwd=repo)
        if unstaged.returncode != 0 or staged.returncode != 0:
            self._progress.print_error(
                "Tracked local changes are present. Commit or stash them before running --update."
            )
            return 1

        self._progress.print_info("Fetching latest changes from GitHub...")
        fetch_args = ["fetch", "origin", "--prune"] if upstream else ["fetch", PROJECT_REPO_URL]
        fetch = self._run_git(fetch_args, cwd=repo)
        if fetch.returncode != 0:
            self._progress.print_error(f"git fetch failed: {fetch.stderr.strip()[:300]}")
            return 1

        counts = self._git(
            ["rev-list", "--left-right", "--count", f"HEAD...{remote_ref}"],
            cwd=repo,
            allow_failure=True,
        ).split()
        if len(counts) != 2:
            self._progress.print_error(f"Could not compare HEAD with {remote_ref}.")
            return 1
        ahead, behind = (int(counts[0]), int(counts[1]))
        if behind == 0:
            self._progress.print_success("BountyMind is already up to date.")
            return 0
        if ahead > 0:
            self._progress.print_error(
                f"Local branch has {ahead} commit(s) not on {remote_ref}. "
                "Refusing automatic update to avoid overwriting local work."
            )
            return 1

        self._progress.print_info(f"Applying {behind} upstream commit(s) with a fast-forward update...")
        update_args = ["pull", "--ff-only"] if upstream else ["merge", "--ff-only", "FETCH_HEAD"]
        update = self._run_git(update_args, cwd=repo)
        if update.returncode != 0:
            self._progress.print_error(f"git fast-forward failed: {update.stderr.strip()[:500]}")
            return 1

        after = self._git(["rev-parse", "HEAD"], cwd=repo).strip()
        if after == before:
            self._progress.print_success("No repository changes applied; install.sh not needed.")
            return 0

        self._progress.print_success(f"Updated BountyMind: {before[:8]} -> {after[:8]}")
        return self._run_installer_after_update(repo)

    def _default_upstream(self, repo: Path) -> str:
        for branch in ("origin/main", "origin/master"):
            if self._git(["rev-parse", "--verify", branch], cwd=repo, allow_failure=True).strip():
                return branch
        return ""

    def _run_installer_after_update(self, repo: Path) -> int:
        installer = repo / "install.sh"
        if not installer.exists():
            self._progress.print_warning("install.sh not found after update; skipping installer.")
            return 0
        if os.name == "nt":
            self._progress.print_warning(
                "Repository updated, but install.sh is Linux-only. "
                "Run it from Kali/Ubuntu/Debian to refresh external tools."
            )
            return 0
        if not shutil.which("bash"):
            self._progress.print_error("bash not found; cannot run install.sh.")
            return 1

        cmd = ["bash", str(installer)]
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            if not shutil.which("sudo"):
                self._progress.print_error("install.sh needs root; sudo is not available.")
                return 1
            cmd = ["sudo", *cmd]

        self._progress.print_info("Repository changed; running install.sh to refresh tools...")
        result = subprocess.run(cmd, cwd=str(repo), text=True)
        if result.returncode == 0:
            self._progress.print_success("Self-update complete and install.sh finished successfully.")
            return 0
        self._progress.print_error(f"install.sh failed with exit code {result.returncode}.")
        return result.returncode or 1

    def _git(
        self,
        args: List[str],
        cwd: Optional[Path] = None,
        allow_failure: bool = False,
    ) -> str:
        result = self._run_git(args, cwd=cwd)
        if result.returncode != 0 and not allow_failure:
            return ""
        return result.stdout or ""

    @staticmethod
    def _run_git(args: List[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=300,
        )

    # ------------------------------------------------------------------
    # Per-tool check
    # ------------------------------------------------------------------

    def _check_tool(self, name: str, registry: dict) -> ToolStatus:
        """Check a single tool's availability and version."""
        binary = self._cfg.get_tool_binary(name)
        source = self._cfg.get_tool_source(name)
        enabled = self._cfg.is_tool_enabled(name)

        # Resolve binary path
        resolved = self._platform.resolve_binary(binary) or shutil.which(binary)
        found = resolved is not None

        version = ""
        if found:
            version_flag = registry.get("version_flag", "--version")
            version = self._runner.get_version(resolved or binary, version_flag)
            version = self._clean_version_string(name, version)

        install_hint = self._build_install_hint(name, registry, source)
        update_hint = self._build_update_hint(name, registry, source) if found else ""

        return ToolStatus(
            name=name,
            enabled=enabled,
            source=source,
            binary=binary,
            found=found,
            version=version,
            install_hint=install_hint,
            update_hint=update_hint,
        )

    # ------------------------------------------------------------------
    # Install / update hints
    # ------------------------------------------------------------------

    def _build_install_hint(self, name: str, registry: dict, source: str) -> str:
        """Build a human-readable install command for the tool."""
        if source == "go" and registry.get("go_module"):
            return self._platform.go_install_hint(registry["go_module"])
        if source == "apt" and registry.get("apt_package"):
            return self._platform.apt_install_hint(registry["apt_package"])
        if source == "pip" and registry.get("pip_package"):
            return self._platform.pip_install_hint(registry["pip_package"])
        if source == "github" and registry.get("git_repo"):
            hint = self._platform.git_clone_hint(
                registry["git_repo"],
                registry.get("git_dest", f"/opt/{name}"),
            )
            if registry.get("pip_requirements"):
                hint += f" && pip3 install -r {registry['pip_requirements']}"
            return hint
        # Generic fallback priority: apt > go > pip
        if registry.get("apt_package"):
            return self._platform.apt_install_hint(registry["apt_package"])
        if registry.get("go_module"):
            return self._platform.go_install_hint(registry["go_module"])
        if registry.get("pip_package"):
            return self._platform.pip_install_hint(registry["pip_package"])
        return f"Install {name} manually and ensure it is on your PATH."

    def _build_update_hint(self, name: str, registry: dict, source: str) -> str:
        """Build a human-readable update command for the tool."""
        if source == "go" and registry.get("go_module"):
            return self._platform.go_install_hint(registry["go_module"])
        if source == "apt" and registry.get("apt_package"):
            return f"sudo apt update && sudo apt upgrade -y {registry['apt_package']}"
        if source == "pip" and registry.get("pip_package"):
            return f"pip3 install --upgrade {registry['pip_package']}"
        if source == "github" and registry.get("git_repo"):
            dest = registry.get("git_dest", f"/opt/{name}")
            return f"cd {dest} && git pull"
        return ""

    # ------------------------------------------------------------------
    # Nuclei template update
    # ------------------------------------------------------------------

    def _update_nuclei_templates(self, dry_run: bool = False) -> None:
        """Update nuclei templates. Safe: only downloads template files."""
        if not self._cfg.is_tool_enabled("nuclei"):
            return

        binary = self._cfg.get_tool_binary("nuclei")
        if not (self._platform.resolve_binary(binary) or shutil.which(binary)):
            log.debug("Skipping template update: nuclei not found")
            return

        if dry_run:
            self._progress.print_info(
                "Would run: nuclei -update-templates"
            )
            return

        log.info("Updating nuclei templates...")
        result = self._runner.run(
            tool_name="nuclei",
            cmd=[binary, "-update-templates"],
            target="template-update",
            timeout=180,
            save_raw=False,
        )
        if result.return_code == 0:
            self._progress.print_success("Nuclei templates updated")
            log.info("Nuclei templates updated successfully")
        else:
            log.warning(
                "Nuclei template update failed (rc=%d). Stderr: %s",
                result.return_code, result.stderr[:200],
            )
            self._progress.print_warning(
                f"Nuclei template update failed. Run manually: {binary} -update-templates"
            )

    def ensure_secretfinder(self, dry_run: bool = False) -> bool:
        """
        Clone SecretFinder from GitHub if not present (venv-isolated deps).
        Returns True if SecretFinder is available after this call.
        """
        from pathlib import Path as _Path
        dest = _Path(self._cfg.get("secret_scanning", "secretfinder_path",
                                    default="tools/SecretFinder/SecretFinder.py"))

        if dest.exists():
            log.debug("SecretFinder already present at %s", dest)
            return True

        self._bootstrap_secretfinder_venv(dry_run)
        return dest.exists()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _run_update(self, status: ToolStatus) -> None:
        """Actually run an update command for a tool (non-apt only)."""
        if status.source == "go" and status.update_hint:
            log.info("Updating %s via go install...", status.name)
            result = self._runner.run(
                tool_name="go-install",
                cmd=["go", "install"] + status.update_hint.split()[-1:],
                target=status.name,
                timeout=120,
                save_raw=False,
            )
            if result.return_code == 0:
                self._progress.print_success(f"Updated {status.name}")
            else:
                self._progress.print_warning(
                    f"Failed to update {status.name}. Run manually: {status.update_hint}"
                )
        elif status.source == "github" and status.update_hint:
            log.info("Updating %s via git pull...", status.name)
            result = self._runner.run(
                tool_name="git-pull",
                cmd=["bash", "-c", status.update_hint],
                target=status.name,
                timeout=60,
                save_raw=False,
            )
            if result.return_code == 0:
                self._progress.print_success(f"Updated {status.name}")
        else:
            # apt tools: just print the update hint
            self._progress.print_info(
                f"To update {status.name}: {status.update_hint}"
            )

    def _clean_version_string(self, tool_name: str, raw: str) -> str:
        """Extract a clean version string from tool output."""
        if not raw:
            return "unknown"
        # Try to extract semantic version pattern
        m = re.search(r"v?\d+\.\d+[\.\d]*", raw)
        return m.group(0) if m else raw.split("\n")[0][:50]

    def _print_status_table(self, statuses: List[ToolStatus]) -> None:
        """Print a tool status summary table to the console."""
        rows = []
        for s in statuses:
            status_icon = "✓" if s.found else "✗"
            rows.append([
                s.name,
                status_icon,
                s.version or "—",
                s.source,
                s.install_hint[:60] if not s.found else "installed",
            ])
        self._progress.print_summary_table(
            rows,
            ["Tool", "Status", "Version", "Source", "Hint"],
            "Tool Environment Status",
        )
