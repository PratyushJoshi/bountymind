"""
utils/platform_utils.py
-----------------------
Platform detection and environment helpers.

Detects OS, distro, package managers, and Go/Python tool paths so the
rest of the framework can adapt install suggestions and tool paths
without being hardcoded to Kali.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logger import get_logger

log = get_logger("platform")


class PlatformInfo:
    """
    Detects the current Linux environment and exposes helpers for
    tool path resolution and update command generation.

    Supported environments:
    - Kali Linux
    - Ubuntu (all flavours)
    - Debian and derivatives
    - Generic Linux (best-effort)
    """

    def __init__(self) -> None:
        self._os = platform.system().lower()
        self._distro: Optional[str] = None
        self._distro_version: Optional[str] = None
        self._go_bin_dir: Optional[Path] = None
        self._detect()

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    def _detect(self) -> None:
        """Populate distro info and Go bin path."""
        self._distro, self._distro_version = self._detect_linux_distro()
        self._go_bin_dir = self._detect_go_bin_dir()
        log.debug(
            "Platform: os=%s distro=%s version=%s go_bin=%s",
            self._os, self._distro, self._distro_version, self._go_bin_dir,
        )

    def _detect_linux_distro(self) -> Tuple[str, str]:
        """Read /etc/os-release to identify the distro."""
        os_release = Path("/etc/os-release")
        if not os_release.exists():
            return "unknown", ""
        info: Dict[str, str] = {}
        try:
            with open(os_release) as fh:
                for line in fh:
                    line = line.strip()
                    if "=" in line:
                        key, _, val = line.partition("=")
                        info[key] = val.strip('"')
        except OSError:
            return "unknown", ""

        distro = info.get("ID", "unknown").lower()
        version = info.get("VERSION_ID", "")
        return distro, version

    def _detect_go_bin_dir(self) -> Optional[Path]:
        """
        Find where 'go install' places binaries.
        Checks GOPATH/bin first, then ~/go/bin.
        """
        gopath = os.environ.get("GOPATH")
        if gopath:
            p = Path(gopath) / "bin"
            if p.exists():
                return p

        default = Path.home() / "go" / "bin"
        if default.exists():
            return default

        # Try 'go env GOPATH' if the go binary is available
        if shutil.which("go"):
            try:
                result = subprocess.run(
                    ["go", "env", "GOPATH"],
                    capture_output=True, text=True, timeout=5,
                )
                gopath_env = result.stdout.strip()
                if gopath_env:
                    p = Path(gopath_env) / "bin"
                    if p.exists():
                        return p
                    return p  # return even if it doesn't exist yet
            except Exception:
                pass

        return None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_linux(self) -> bool:
        return self._os == "linux"

    @property
    def is_kali(self) -> bool:
        return self._distro == "kali"

    @property
    def is_ubuntu(self) -> bool:
        return self._distro in ("ubuntu", "linuxmint", "pop")

    @property
    def is_debian_based(self) -> bool:
        return self._distro in (
            "kali", "ubuntu", "debian", "linuxmint", "pop",
            "parrot", "zorin", "elementary", "raspbian",
        )

    @property
    def distro_name(self) -> str:
        return self._distro or "unknown"

    @property
    def distro_version(self) -> str:
        return self._distro_version or ""

    @property
    def go_bin_dir(self) -> Optional[Path]:
        return self._go_bin_dir

    @property
    def has_apt(self) -> bool:
        return shutil.which("apt") is not None or shutil.which("apt-get") is not None

    @property
    def has_go(self) -> bool:
        return shutil.which("go") is not None

    @property
    def has_pip(self) -> bool:
        return shutil.which("pip3") is not None or shutil.which("pip") is not None

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def resolve_binary(self, binary: str) -> Optional[str]:
        """
        Try to locate a binary using:
        1. System PATH (shutil.which)
        2. GOPATH/bin
        3. Common Kali/tool directories
        """
        # 1. System PATH
        found = shutil.which(binary)
        if found:
            return found

        # 2. Go bin directory
        if self._go_bin_dir:
            go_path = self._go_bin_dir / binary
            if go_path.exists() and os.access(go_path, os.X_OK):
                return str(go_path)

        # 3. Common manual install locations
        common_paths: List[Path] = [
            Path("/usr/local/bin") / binary,
            Path("/usr/bin") / binary,
            Path("/opt") / binary / binary,
            Path.home() / ".local" / "bin" / binary,
        ]
        for candidate in common_paths:
            if candidate.exists() and os.access(candidate, os.X_OK):
                return str(candidate)

        return None

    # ------------------------------------------------------------------
    # Install hints
    # ------------------------------------------------------------------

    def apt_install_hint(self, package: str) -> str:
        return f"sudo apt update && sudo apt install -y {package}"

    def go_install_hint(self, module: str) -> str:
        return f"go install {module}@latest"

    def pip_install_hint(self, package: str) -> str:
        return f"pip3 install {package}"

    def git_clone_hint(self, repo_url: str, dest: str) -> str:
        return f"git clone {repo_url} {dest}"

    def summary(self) -> str:
        lines = [
            f"OS         : {platform.system()} {platform.release()}",
            f"Distro     : {self.distro_name} {self.distro_version}",
            f"Kali       : {self.is_kali}",
            f"Ubuntu     : {self.is_ubuntu}",
            f"Debian     : {self.is_debian_based}",
            f"apt        : {self.has_apt}",
            f"go         : {self.has_go}",
            f"go bin dir : {self.go_bin_dir}",
        ]
        return "\n".join(lines)
