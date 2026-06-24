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

import re
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from utils.config_manager import ConfigManager
from utils.logger import get_logger
from utils.platform_utils import PlatformInfo
from utils.progress import ProgressManager
from utils.runner import CommandRunner

log = get_logger("updater")


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
    "cloud_enum": {
        "go_module": "",
        "apt_package": "",
        "pip_package": "cloud_enum",
        "version_flag": "--help",
        "notes": "Cloud bucket enumeration — AWS S3, GCP, Azure Blob",
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
}


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

    def install_advanced_tools(self, dry_run: bool = False) -> None:
        """
        Install Python-based security tools via pip (wafw00f, arjun, cloud_enum).
        Safe to call on first run after git clone.
        """
        pip_tools = {
            "wafw00f": "wafw00f",
            "arjun": "arjun",
            "cloud_enum": "cloud_enum",
        }
        self._progress.print_phase("Installing Python Security Tools")
        for tool_name, pip_package in pip_tools.items():
            if not self._cfg.is_tool_enabled(tool_name) and tool_name != "cloud_enum":
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

    def auto_install_missing(self, dry_run: bool = False) -> None:
        """
        Bootstrap missing tools after git clone — installs pip tools, Go tools,
        and refreshes nuclei templates without requiring manual install.sh.
        """
        self._progress.print_phase("Auto-Bootstrap (missing tools)")
        log.info("Running auto-install for missing tools...")

        # 1. Python requirements
        from pathlib import Path as _Path
        req_file = _Path(__file__).parent.parent / "requirements.txt"
        if req_file.exists() and not dry_run and self._platform.has_pip:
            self._progress.print_info("Installing Python requirements...")
            self._runner.run(
                tool_name="pip3",
                cmd=["pip3", "install", "-q", "-r", str(req_file)],
                target="requirements",
                timeout=300,
                save_raw=False,
                check_exists=False,
            )

        # 2. Pip-based security tools
        self.install_advanced_tools(dry_run=dry_run)

        # 3. Go-based tools (if go is available)
        if self._platform.has_go and not dry_run:
            for tool_name, registry in TOOL_REGISTRY.items():
                if not self._cfg.is_tool_enabled(tool_name):
                    continue
                if registry.get("go_module") and not registry.get("pip_package"):
                    binary = self._cfg.get_tool_binary(tool_name)
                    if self._platform.resolve_binary(binary) or shutil.which(binary):
                        continue
                    module = registry["go_module"]
                    self._progress.print_info(f"Installing {tool_name} via go install...")
                    result = self._runner.run(
                        tool_name="go-install",
                        cmd=["go", "install", f"{module}@latest"],
                        target=tool_name,
                        timeout=300,
                        save_raw=False,
                        check_exists=False,
                    )
                    if result.return_code == 0:
                        self._progress.print_success(f"Installed {tool_name}")

        # 4. SecretFinder clone
        if self._cfg.secret_scanning_enabled:
            self.ensure_secretfinder(dry_run)

        # 5. Nuclei templates
        self._update_nuclei_templates(dry_run)

        if not dry_run:
            self._progress.print_success("Auto-bootstrap complete")

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
        Clone SecretFinder from GitHub if not present.
        Safe: read-only git clone + pip install of its requirements.
        Returns True if SecretFinder is available after this call.
        """
        from pathlib import Path as _Path
        dest = _Path(self._cfg.get("secret_scanning", "secretfinder_path",
                                    default="tools/SecretFinder/SecretFinder.py"))
        repo_dir = dest.parent

        if dest.exists():
            log.debug("SecretFinder already present at %s", dest)
            return True

        if dry_run:
            self._progress.print_info(
                f"Would clone SecretFinder to {repo_dir}"
            )
            return False

        self._progress.print_info("Cloning SecretFinder from GitHub...")
        log.info("Cloning SecretFinder to %s", repo_dir)
        result = self._runner.run(
            tool_name="git",
            cmd=["git", "clone", "https://github.com/m4ll0k/SecretFinder.git",
                 str(repo_dir)],
            target="secretfinder",
            timeout=60,
            save_raw=False,
            check_exists=False,
        )
        if result.return_code != 0:
            log.warning("SecretFinder clone failed: %s", result.stderr[:200])
            return False

        req_file = repo_dir / "requirements.txt"
        if req_file.exists():
            self._runner.run(
                tool_name="pip3",
                cmd=["pip3", "install", "-r", str(req_file)],
                target="secretfinder-deps",
                timeout=120,
                save_raw=False,
                check_exists=False,
            )

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
