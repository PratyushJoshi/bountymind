# BountyMind

**Automated Reconnaissance, Vulnerability Assessment & WAF Evasion Framework**

> **AUTHORIZED USE ONLY** — Run only against systems you own or have explicit written permission to test.

---

## Quick Start (Linux)

```bash
git clone https://github.com/PratyushJoshi/bountymind.git
cd bountymind
sudo ./install.sh          # full system install (recommended)
```

Or install manually and let BountyMind bootstrap missing tools on first scan:

```bash
pip3 install -e .
bountymind --bootstrap       # install pip/go tools only
bountymind --check-env       # verify everything is available
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

# Environment check
bountymind --check-env

# Full help
bountymind --help
```

### Common Options

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Scan a single domain |
| `-l FILE` | Scan domains listed in a file (one per line) |
| `-f FILE` | Alias for `-l` |
| `-v` | Verbose console output |
| `--bootstrap` | Auto-install missing pip/go tools |
| `--update-tools` | Update tools and nuclei templates |
| `--skip-waf` | Skip WAF detection & evasion phase |
| `--format markdown,html` | Report formats |
| `--output-dir DIR` | Custom output directory |

---

## What It Does

**Automated phases (unauthenticated, non-intrusive):**
- Subdomain enumeration (subfinder, amass, crt.sh)
- HTTP probing, port scanning, tech/WAF fingerprinting
- URL harvesting (gau, waybackurls, katana)
- Nuclei vulnerability scanning (safe templates only)
- JS secret mining, cloud bucket recon, screenshots
- **WAF detection (wafw00f) & evasion scans (nuclei waf-bypass, ffuf, arjun)**

**Live progress:** A simultaneous phase dashboard shows each module's status while the scan runs. Reports are written to `output/reports/` when complete.

---

## WAF Detection & Evasion

When live endpoints are protected by a WAF, BountyMind:

1. **Detects** the firewall with `wafw00f` on all live URLs
2. **Runs evasion probes** on protected endpoints:
   - Nuclei `waf-bypass` profile
   - FFUF with evasion headers and rate limiting
   - Arjun passive parameter discovery

Results appear in the report under **WAF Detection** and **WAF Evasion Discoveries**, plus summary metrics.

---

## Output Structure

```
output/
├── raw/           # Raw tool output
├── parsed/        # Normalized artifacts (incl. waf_urls_*.txt)
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

This installs apt packages, Go tools, pip tools (wafw00f, arjun, cloud_enum), clones SecretFinder/dirsearch, updates nuclei templates, and registers `/usr/local/bin/bountymind`.

### Manual pip install

```bash
pip3 install -e .
bountymind --bootstrap
```

---

## Configuration

Copy and edit the config on first run (auto-created from example if missing):

```bash
cp config/config.example.yaml config/config.yaml
```

Optional API keys (Shodan, VirusTotal, etc.) enhance discovery but are not required.

---

## Safety & Legal

- Non-destructive by default — DoS, brute-force, and exploit templates are excluded
- WAF evasion uses detection-only techniques with rate limiting
- All manual follow-up steps require analyst authorization

See the full legacy documentation in this repository for architecture, troubleshooting, and tool inventory details.

---

## License

Internal security engineering tool. Use only with proper authorization.
