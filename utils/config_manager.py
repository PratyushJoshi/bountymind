"""
utils/config_manager.py
-----------------------
Handles loading, validation, and access to the framework configuration.

Design decisions:
- ConfigManager is a singleton-style class initialized once at startup.
- Missing API keys emit warnings but never raise errors.
- Invalid required config sections raise ConfigurationError.
- Provides typed helper methods for each config section.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from utils.exceptions import ConfigurationError


class ConfigManager:
    """
    Loads config/config.yaml and exposes strongly-typed accessors.

    Usage::
        cfg = ConfigManager("config/config.yaml")
        cfg.get_tool_binary("nuclei")  # -> "nuclei"
        cfg.api_key("shodan")          # -> "" if not set
    """

    DEFAULT_CONFIG_PATH = Path("config/config.yaml")
    EXAMPLE_CONFIG_PATH = Path("config/config.example.yaml")

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._path = Path(config_path) if config_path else self.DEFAULT_CONFIG_PATH
        self._data: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load and parse the YAML config file."""
        if not self._path.exists():
            self._attempt_create_from_example()

        if not self._path.exists():
            raise ConfigurationError(
                f"Config file not found: {self._path}\n"
                f"Create it by copying config/config.example.yaml:\n"
                f"  cp config/config.example.yaml config/config.yaml"
            )

        with open(self._path, "r", encoding="utf-8") as fh:
            try:
                self._data = yaml.safe_load(fh) or {}
            except yaml.YAMLError as exc:
                raise ConfigurationError(
                    f"Failed to parse config file {self._path}: {exc}"
                ) from exc

        self._validate()

    def _attempt_create_from_example(self) -> None:
        """Try to auto-create config.yaml from config.example.yaml."""
        if self.EXAMPLE_CONFIG_PATH.exists():
            shutil.copy(self.EXAMPLE_CONFIG_PATH, self._path)
        # If example also absent, the caller will raise ConfigurationError

    def _validate(self) -> None:
        """Validate that required top-level sections exist."""
        required_sections = ["general", "tools", "discovery", "probing", "scanning"]
        missing = [s for s in required_sections if s not in self._data]
        if missing:
            raise ConfigurationError(
                f"Config file is missing required sections: {missing}. "
                f"Check config/config.example.yaml for the expected format."
            )

    # ------------------------------------------------------------------
    # Generic accessors
    # ------------------------------------------------------------------

    def get(self, *keys: str, default: Any = None) -> Any:
        """Traverse nested config keys safely, returning default if absent."""
        node = self._data
        for key in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(key, default)
            if node is None:
                return default
        return node

    # ------------------------------------------------------------------
    # General settings
    # ------------------------------------------------------------------

    @property
    def output_dir(self) -> Path:
        return Path(self.get("general", "output_dir", default="output"))

    @property
    def log_file(self) -> Path:
        return Path(self.get("general", "log_file", default="logs/framework.log"))

    @property
    def log_level(self) -> str:
        return str(self.get("general", "log_level", default="INFO")).upper()

    @property
    def max_concurrency(self) -> int:
        return int(self.get("general", "max_concurrency", default=5))

    @property
    def tool_timeout(self) -> int:
        return int(self.get("general", "tool_timeout", default=300))

    @property
    def report_formats(self) -> List[str]:
        formats = self.get("general", "report_formats", default=["markdown"])
        return [f.lower() for f in formats]

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    def api_key(self, provider: str) -> str:
        """Return an API key by provider name, or empty string if absent."""
        key = self.get("api_keys", provider, default="")
        return str(key).strip() if key else ""

    def has_api_key(self, provider: str) -> bool:
        return bool(self.api_key(provider))

    # ------------------------------------------------------------------
    # Tool configuration
    # ------------------------------------------------------------------

    def tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Return the full config dict for a named tool."""
        return self.get("tools", tool_name, default={}) or {}

    def is_tool_enabled(self, tool_name: str) -> bool:
        return bool(self.tool_config(tool_name).get("enabled", True))

    def get_tool_binary(self, tool_name: str) -> str:
        """
        Return the resolved binary name/path for a tool.
        Checks custom 'path' first, falls back to 'binary', then tool_name.
        """
        cfg = self.tool_config(tool_name)
        custom_path = str(cfg.get("path", "")).strip()
        if custom_path:
            return custom_path
        binary = str(cfg.get("binary", tool_name)).strip()
        return binary or tool_name

    def get_tool_source(self, tool_name: str) -> str:
        return str(self.tool_config(tool_name).get("source", "apt"))

    # ------------------------------------------------------------------
    # Discovery settings
    # ------------------------------------------------------------------

    @property
    def passive_sources(self) -> List[str]:
        return list(self.get("discovery", "passive_sources", default=[]))

    @property
    def max_subdomains(self) -> int:
        return int(self.get("discovery", "max_subdomains", default=500))

    @property
    def amass_passive_only(self) -> bool:
        return bool(self.get("discovery", "amass_passive_only", default=True))

    @property
    def subfinder_threads(self) -> int:
        return int(self.get("discovery", "subfinder_threads", default=10))

    # ------------------------------------------------------------------
    # Probing settings
    # ------------------------------------------------------------------

    @property
    def http_timeout(self) -> int:
        return int(self.get("probing", "http_timeout", default=10))

    @property
    def http_threads(self) -> int:
        return int(self.get("probing", "http_threads", default=20))

    @property
    def ports(self) -> str:
        return str(self.get("probing", "ports", default="80,443,8080,8443"))

    @property
    def nmap_timing(self) -> str:
        return str(self.get("probing", "nmap_timing", default="T2"))

    @property
    def nmap_flags(self) -> str:
        return str(self.get("probing", "nmap_flags", default="-sV --version-intensity 3"))

    @property
    def port_scan_enabled(self) -> bool:
        return bool(self.get("probing", "port_scan_enabled", default=True))

    @property
    def tech_detection_enabled(self) -> bool:
        return bool(self.get("probing", "tech_detection_enabled", default=True))

    @property
    def waf_detection_enabled(self) -> bool:
        return bool(self.get("probing", "waf_detection_enabled", default=True))

    @property
    def dir_discovery_enabled(self) -> bool:
        return bool(self.get("probing", "dir_discovery_enabled", default=True))

    @property
    def dir_wordlist(self) -> str:
        primary = str(self.get("probing", "dir_wordlist", default=""))
        if primary and os.path.exists(primary):
            return primary
        fallback = str(self.get("probing", "dir_wordlist_fallback", default=""))
        if fallback and os.path.exists(fallback):
            return fallback
        return ""

    @property
    def dir_rate_limit(self) -> int:
        return int(self.get("probing", "dir_rate_limit", default=10))

    @property
    def dir_recursion_depth(self) -> int:
        return int(self.get("probing", "dir_recursion_depth", default=0))

    @property
    def dir_match_codes(self) -> str:
        return str(self.get("probing", "dir_match_codes", default="200,204,301,302,307,401,403"))

    @property
    def dir_timeout(self) -> int:
        return int(self.get("probing", "dir_timeout", default=10))

    # ------------------------------------------------------------------
    # Scanning settings
    # ------------------------------------------------------------------

    @property
    def nuclei_severity_levels(self) -> List[str]:
        return list(self.get("scanning", "severity_levels", default=["info", "low", "medium", "high", "critical"]))

    @property
    def nuclei_excluded_tags(self) -> List[str]:
        return list(self.get("scanning", "excluded_tags", default=["dos", "fuzz", "brute-force", "intrusive"]))

    @property
    def nuclei_included_tags(self) -> List[str]:
        return list(self.get("scanning", "included_tags", default=[]))

    @property
    def nuclei_rate_limit(self) -> int:
        return int(self.get("scanning", "nuclei_rate_limit", default=50))

    @property
    def nuclei_bulk_size(self) -> int:
        return int(self.get("scanning", "nuclei_bulk_size", default=25))

    @property
    def nuclei_concurrency(self) -> int:
        return int(self.get("scanning", "nuclei_concurrency", default=10))

    @property
    def nuclei_timeout(self) -> int:
        return int(self.get("scanning", "nuclei_timeout", default=10))

    @property
    def nuclei_templates_path(self) -> str:
        return str(self.tool_config("nuclei").get("templates_path", "") or "")

    @property
    def dast_enabled(self) -> bool:
        return bool(self.get("scanning", "dast_enabled", default=True))

    @property
    def dast_max_urls(self) -> int:
        return int(self.get("scanning", "dast_max_urls", default=1500))

    # ------------------------------------------------------------------
    # Reporting settings
    # ------------------------------------------------------------------

    @property
    def organization(self) -> str:
        return str(self.get("reporting", "organization", default="Security Assessment Team"))

    @property
    def report_title(self) -> str:
        return str(self.get("reporting", "report_title", default="Automated Reconnaissance & Vulnerability Assessment"))

    @property
    def include_raw_references(self) -> bool:
        return bool(self.get("reporting", "include_raw_references", default=True))

    # ------------------------------------------------------------------
    # Safety settings
    # ------------------------------------------------------------------

    @property
    def safe_mode(self) -> bool:
        return bool(self.get("safety", "safe_mode", default=True))

    @property
    def unauthenticated_only(self) -> bool:
        return bool(self.get("safety", "unauthenticated_only", default=True))

    @property
    def global_rate_limit(self) -> int:
        return int(self.get("safety", "global_rate_limit", default=20))

    # ------------------------------------------------------------------
    # Scope settings
    # ------------------------------------------------------------------

    @property
    def scope_extra_domains(self) -> List[str]:
        return list(self.get("scope", "domains", default=[]))

    @property
    def scope_strict(self) -> bool:
        return bool(self.get("scope", "strict", default=True))

    @property
    def scope_block_third_party(self) -> bool:
        return bool(self.get("scope", "block_third_party", default=True))

    @property
    def scope_blocklist_extra(self) -> List[str]:
        return list(self.get("scope", "blocklist_extra", default=[]))

    @property
    def scope_allowlist_extra(self) -> List[str]:
        return list(self.get("scope", "allowlist", default=[]))

    # ------------------------------------------------------------------
    # URL harvesting settings (gau, waybackurls, katana)
    # ------------------------------------------------------------------

    @property
    def harvesting_enabled(self) -> bool:
        return bool(self.get("url_harvesting", "enabled", default=True))

    @property
    def harvesting_max_urls(self) -> int:
        return int(self.get("url_harvesting", "max_urls_per_target", default=2000))

    @property
    def katana_depth(self) -> int:
        return int(self.get("url_harvesting", "katana_depth", default=3))

    @property
    def katana_js_crawl(self) -> bool:
        return bool(self.get("url_harvesting", "katana_js_crawl", default=True))

    # ------------------------------------------------------------------
    # Secret scanning settings (SecretFinder)
    # ------------------------------------------------------------------

    @property
    def secret_scanning_enabled(self) -> bool:
        return bool(self.get("secret_scanning", "enabled", default=True))

    @property
    def secretfinder_path(self) -> str:
        return str(self.get("secret_scanning", "secretfinder_path",
                            default="tools/SecretFinder/SecretFinder.py"))

    @property
    def secret_scan_max_js_files(self) -> int:
        return int(self.get("secret_scanning", "max_js_files", default=50))

    # ------------------------------------------------------------------
    # Screenshot settings (gowitness)
    # ------------------------------------------------------------------

    @property
    def screenshots_enabled(self) -> bool:
        return bool(self.get("screenshots", "enabled", default=True))

    @property
    def screenshots_timeout(self) -> int:
        return int(self.get("screenshots", "timeout_seconds", default=600))

    @property
    def screenshots_max_hosts(self) -> int:
        return int(self.get("screenshots", "max_hosts", default=100))

    # ------------------------------------------------------------------
    # Naabu (fast port scanner) settings
    # ------------------------------------------------------------------

    @property
    def naabu_enabled(self) -> bool:
        return bool(self.get("probing", "naabu_enabled", default=False))

    @property
    def naabu_ports(self) -> str:
        return str(self.get("probing", "naabu_ports", default="top-100"))

    @property
    def naabu_rate(self) -> int:
        return int(self.get("probing", "naabu_rate", default=1000))

    # ------------------------------------------------------------------
    # Dnsx settings
    # ------------------------------------------------------------------

    @property
    def dnsx_enabled(self) -> bool:
        return bool(self.get("discovery", "dnsx_enabled", default=True))

    @property
    def dnsx_threads(self) -> int:
        return int(self.get("discovery", "dnsx_threads", default=100))
