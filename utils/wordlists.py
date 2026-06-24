"""Helpers for selecting useful wordlists with SecLists fallbacks."""

from __future__ import annotations

import os
from pathlib import Path


def get_wordlist(category: str, fallback_path: str) -> str:
    """
    Return the best available wordlist from SecLists for the given category,
    otherwise use the fallback path (which will be created if missing).
    """
    seclists_base = "/usr/share/seclists/Discovery"
    mapping = {
        "directories": [
            f"{seclists_base}/Web-Content/common.txt",
            f"{seclists_base}/Web-Content/directory-list-2.3-medium.txt",
        ],
        "files": [
            f"{seclists_base}/Web-Content/raft-large-files.txt",
            f"{seclists_base}/Web-Content/quickhits.txt",
        ],
        "sensitive": [
            f"{seclists_base}/Web-Content/Sensitive-Hack2teach.txt",
            f"{seclists_base}/Web-Content/Common-DB-Backups.txt",
        ],
        "dns": [f"{seclists_base}/DNS/subdomains-top1million-5000.txt"],
    }

    for candidate in mapping.get(category, []):
        if os.path.isfile(candidate):
            return candidate

    fallback = Path(fallback_path)
    fallback.parent.mkdir(parents=True, exist_ok=True)
    if not fallback.exists():
        if category == "directories":
            fallback.write_text("\n".join(["admin", "api", "v1", "config", "dev", "staging", "login", "backup"]), encoding="utf-8")
        elif category == "files":
            fallback.write_text("\n".join([".env", "swagger.json", "package.json", "Dockerfile"]), encoding="utf-8")
        elif category == "sensitive":
            fallback.write_text("\n".join([".git/HEAD", ".env", ".aws/credentials", "backup.sql"]), encoding="utf-8")
        elif category == "dns":
            fallback.write_text("\n".join(["www", "mail", "ftp", "localhost"]), encoding="utf-8")
        else:
            fallback.touch()
    return str(fallback)