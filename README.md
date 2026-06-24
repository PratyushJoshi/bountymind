# BountyMind

**Automated Reconnaissance, Vulnerability Assessment, Deep Bug Detection & WAF Evasion Framework**

> **AUTHORIZED USE ONLY** — Run only against systems you own or have explicit written permission to test.

---

## Quick Start (Linux)

```bash
git clone https://github.com/PratyushJoshi/bountymind.git
cd bountymind
sudo ./install.sh          # full system install (recommended)
```

Or install manually and let BountyMind bootstrap missing tools:

```bash
pip3 install -e .
bountymind --bootstrap       # installs pipx + go + cargo + git-based tools
bountymind --check-env       # verify (exit 1 if required tools missing)
```

---

## CLI Usage

After installation, `bountymind` is available globally:

```bash
# Single domain
bountymind -d example.com

# Multiple targets from a list file
bountymind -l targets.txt

# Verbose live progress + detailed logs
bountymind -d example.com -v

# Install/update tools
bountymind --bootstrap
bountymind --update-tools
bountymind --update-tools --dry-run    # show what would be installed, change nothing

# Environment check
bountymind --check-env

# Full help
bountymind --help
```

### Target Options

| Flag | Description |
|------|-------------|
| `-d, --domain DOMAIN` | Scan a single domain |
| `-l, --list FILE` | Scan domains listed in a file (one per line) |
| `-f, --file FILE` | Alias for `-l` |

### Run Options

| Flag | Description |
|------|-------------|
| `--config FILE` | Path to config YAML (default: `config/config.yaml`) |
| `--output-dir DIR` | Override output directory (default: `output/`) |
| `--format FORMAT` | Report format(s): `markdown`, `html`, or `markdown,html` |
| `--concurrency N` | Override max concurrency |
| `--auth TOKEN` | Optional auth token attached to the shared target context |
| `-v, --verbose` | Detailed console output (INFO level) |

### Tool Management

| Flag | Description |
|------|-------------|
| `--bootstrap` | Install all external tools (pipx, Go, cargo, git wrappers, SecretFinder) then exit unless a target is given |
| `--update-tools` | Update tools + nuclei templates, then continue with the scan |
| `--dry-run` | With `--bootstrap`/`--update-tools`: show what would be installed without running |
| `--check-env` | Verify tool availability (exit 1 if **required** tools are missing) |
| `--no-auto-bootstrap` | Do not auto-install missing tools on first scan |

### Phase Skips

| Flag | Skips |
|------|-------|
| `--skip-discovery` | Subdomain discovery (probe targets directly) |
| `--skip-scanning` | Nuclei vulnerability scanning |
| `--skip-dirs` | Directory/file discovery |
| `--skip-harvest` | URL harvesting (gau, waybackurls, katana) |
| `--skip-secrets` | JavaScript secret scanning |
| `--skip-cloud` | Cloud bucket enumeration |
| `--skip-screenshots` | Visual screenshot capture (gowitness) |
| `--skip-waf` | WAF detection & evasion |

---

## What It Does

**Recon & surface mapping (passive / non-intrusive):**
- Subdomain enumeration — `subfinder`, `amass`, `crt.sh`, with `dnsx` bulk resolution and `subzy` takeover checks
- HTTP probing, port scanning, tech/WAF fingerprinting — `httpx`, `nmap`/`naabu`, `whatweb`, `wafw00f`
- URL harvesting — `gau`, `waybackurls`, `katana`
- JS secret mining, cloud bucket recon, screenshots — `SecretFinder`, `s3scanner`, `gowitness`

**Vulnerability scanning:**
- Full nuclei scan across the **entire** community template set (severity `info` → `critical`), with only genuinely dangerous tags excluded (`dos`, `fuzz`, `brute-force`, `intrusive`, `destructive`, `exploit`). Detection templates for `rce`/`sqli`/`lfi`/`ssrf`/`xss` are **kept** — they detect, they don't exploit.

**Deep bug detection (Phase 2.7):** each scanner runs in isolation, so one tool failing never aborts the rest.
- **DAST parameter fuzzing** — `nuclei -dast` against parameterized URLs harvested from gau/waybackurls/katana (reflected XSS, SQLi, SSTI, LFI/traversal, open redirect, CRLF, SSRF), deduped with `uro`
- **SQLi** — `sqlmap` fed with harvested parameterized URLs + `arjun` discovery
- **XSS** — `dalfox` over parameterized URLs and live hosts
- SSTI, open redirect, SSRF, CORS, path traversal, IDOR, JWT, race conditions, CSRF, WebSocket, OAuth, cache poisoning
- **HTTP request smuggling** (`smuggler`), **client-side prototype pollution** (`ppfuzz`), **403/401 bypass** (`bypass-403`), **hidden parameters** (`x8`), **API schema fuzzing** (`schemathesis`), **mass assignment** (nuclei templates)

**WAF detection & evasion:**
- `wafw00f` detection on all live URLs, then evasion probes (nuclei with bypass headers, `ffuf` with evasion headers, `arjun`) on protected endpoints

**Live progress:** a simultaneous phase dashboard shows each module's status while the scan runs.

---

## Report Structure

Reports are written to `output/reports/` in Markdown and/or HTML. The report is ordered so **all automated findings come first**, followed by a clearly marked final section:

> 🧑‍💻 **HUMAN VALIDATION & TESTING REQUIRED**

Everything that needs a human to confirm, validate, or (with authorization) exploit is consolidated at the very end — authenticated follow-up tasks, manual verification gateways, and a dynamic, finding-specific exploit checklist (request smuggling, prototype pollution, 403 bypass, hidden params, API logic flaws, DAST findings, and more).

---

## Output Structure

```
output/
├── raw/           # Raw tool output
├── parsed/        # Normalized artifacts (incl. dast_urls_*.txt, waf_urls_*.txt)
├── reports/       # Markdown + HTML reports
└── screenshots/   # gowitness captures
logs/
└── framework.log  # Full execution trace
```

---

## Installation Details

### Full install (Kali / Ubuntu / Debian)

```bash
sudo ./install.sh
```

This installs:
- **apt packages** — nmap, ffuf, amass, whatweb, wafw00f, sqlmap, golang
- **Go tools** — subfinder, httpx, nuclei, dnsx, katana, naabu, gau, waybackurls, httprobe, subzy, gowitness, ffuf, dalfox
- **pipx tools** — s3scanner, uro, xnlinkfinder, wafw00f, arjun, jwt_tool, tplmap, **schemathesis**
- **Rust/cargo tools** — **ppfuzz**, **x8** (installs Rust via rustup if missing)
- **git-wrapped tools** — **smuggler**, **bypass-403**, SecretFinder, dirsearch
- nuclei templates (incl. DAST/fuzzing templates) and registers `/usr/local/bin/bountymind`

> Note: `ppfuzz` drives a headless browser, so it needs Chrome/Chromium installed at runtime (Kali usually has it; on a minimal host add `chromium`).

### Manual install

```bash
pip3 install -e .
bountymind --bootstrap        # same toolset via pipx/go/cargo/git
bountymind --check-env
```

Advanced scanners (`smuggler`, `ppfuzz`, `x8`, `schemathesis`, `bypass-403`) are **optional** — `--check-env` will not fail if they are missing, and each scanner skips gracefully when its tool isn't present.

---

## Configuration

Config is auto-created from the example on first run; you can also copy it manually:

```bash
cp config/config.example.yaml config/config.yaml
```

Notable settings (under `scanning:`):
- `included_tags: []` — empty means **maximum** nuclei coverage (whole template set minus excluded tags)
- `dast_enabled: true` / `dast_max_urls: 1500` — control the DAST parameter-fuzzing phase

Optional API keys (Shodan, VirusTotal, SecurityTrails, etc.) enhance discovery but are not required.

---

## Safety & Legal

- Non-destructive by default — DoS, brute-force, and exploit-class templates/tags are excluded
- High-value bugs are **detected**, not auto-exploited; weaponization is left to the analyst
- WAF evasion uses detection-only techniques with rate limiting
- All manual follow-up steps require analyst authorization

---

## License

Internal security engineering tool. Use only with proper authorization.
