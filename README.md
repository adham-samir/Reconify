# Reconify

Personal bug bounty recon toolkit. Automates the full subdomain & asset reconnaissance pipeline from passive enumeration to live host filtering, with clean per-run outputs and markdown reports.

## Features

- **16 passive sources** — subfinder, assetfinder, findomain, amass, crt.sh, dnsdumpster, tls.bufferover.run, riddler.io, CommonCrawl, Wayback, SecurityTrails, VirusTotal, URLScan.io, Shodan, github-subdomains, HackerTarget
- **Parallel execution** — all sources run concurrently via asyncio
- **Active discovery** (opt-in) — FFUF brute-force, alterx permutations, amass active enum
- **Wildcard detection** — identifies and removes wildcard DNS entries
- **Scope filtering** — regex-based scope file support
- **CDN filtering** — removes Cloudflare/Akamai/Fastly IPs before probing
- **Port probing** — naabu for fast port discovery
- **Live host detection** — httpx for HTTP probing with status/title/server
- **IP & ASN mapping** — dnsx resolve, asnmap, amass intel, API harvest
- **Markdown reports** — per-source stats, durations, file listings
- **API key manager** — interactive CLI menu, keys stored in gitignored `.env` file
- **Tool installer** — checks dependencies, installs missing binaries on demand
- **Resumable output** — each run creates a timestamped directory under `outputs/`

## Requirements

- **Python 3.10+**
- **Go** (for `go install`-based tools)
- External tools: subfinder, assetfinder, findomain, amass, httpx, dnsx, asnmap, naabu, cdncheck, ffuf, alterx, github-subdomains

Use `recon --check-tools` to install missing ones automatically.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/reconify.git
cd reconify

# Create virtual environment (required on most modern systems)
python3 -m venv .venv
source .venv/bin/activate    # bash/zsh
# source .venv/bin/activate.fish  # fish shell

# Install
pip install -e .
```

## Quick Start

```bash
# 1. Install missing tools
recon --check-tools

# 2. Configure API keys
recon --keys

# 3. Run passive recon
recon --target example.com --all

# 4. Include active discovery (opt-in)
recon --target example.com --all --active

# 5. Run specific stages
recon --target example.com --stage 1,5

# 6. Filter by scope
recon --target example.com --all --scope scope.txt
```

## API Keys

| Key | Source |
|-----|--------|
| `SHODAN_API_KEY` | Shodan |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `GITHUB_TOKEN` | GitHub Subdomains |
| `SECURITYTRAILS_API_KEY` | SecurityTrails |
| `OTX_API_KEY` | AlienVault OTX |
| `URLSCAN_API_KEY` | URLScan.io |

Configured via `recon --keys` and stored in `config.env` (gitignored).

## Project Structure

```
.
├── recon.py              # CLI entry point
├── config.json           # saved defaults
├── config.env            # API keys (gitignored)
├── pyproject.toml         # packaging
├── requirements.txt       # pip deps
└── modules/
    ├── api_keys.py        # key manager
    ├── installer.py       # tool install flow
    ├── passive.py         # Stage 1
    ├── active.py          # Stage 2 (opt-in)
    ├── merge.py           # Stage 3
    ├── ip_asn.py          # Stage 4
    ├── livehosts.py       # Stage 5
    └── reporter.py        # markdown report
```

## Output Structure

```
outputs/
└── example.com_2026-06-11_143022/
    ├── subfinder.txt
    ├── assetfinder.txt
    ├── ...
    ├── final_subdomains.txt
    ├── resolved_ips.txt
    ├── asn_ranges.txt
    ├── subdomains_alive.txt
    └── recon_example.com_2026-06-11.md
```

## Staging

| Stage | Description | Default |
|-------|-------------|---------|
| 1 | Passive subdomain enumeration | Included in `--all` |
| 2 | Active discovery (FFUF, alterx, amass) | Only with `--active` |
| 3 | Merge & deduplicate | Included in `--all` |
| 4 | IP & ASN mapping | Included in `--all` |
| 5 | Live host filtering | Included in `--all` |

## Disclaimer

This tool is for authorized security testing and bug bounty hunting only.
