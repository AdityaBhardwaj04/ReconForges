# ReconForges

A modular, Python-based security automation tool designed for penetration testers and security researchers to systematically perform the reconnaissance phase of a security assessment.

The framework orchestrates industry-standard open-source tools — **Subfinder**, **Amass**, **httpx**, **Katana**, **Nmap**, **WhatWeb**, and **Nuclei** — into a structured pipeline that discovers subdomains, detects live hosts, crawls web applications, scans ports, fingerprints technology stacks, and identifies vulnerabilities.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Web Crawler](#web-crawler)
- [Parallel Scanning](#parallel-scanning)
- [Scope Controls](#scope-controls)
- [Reports and Visualisation](#reports-and-visualisation)
- [Configuration](#configuration)
- [Extending the Framework](#extending-the-framework)
- [Example Run](#example-run)
- [Disclaimer](#disclaimer)

---

## Features

- **Full recon pipeline** — from domain input to vulnerability report in a single command
- **Modular design** — each stage is an independent Python module; add or remove stages freely
- **Web crawler stage** — Katana-primary crawler with a Python-BFS fallback; extracts URLs, parameters, JS endpoints, and HTML form actions; enriched URLs are fed directly into Nuclei as targets
- **Parallel scanning** — port scanning and technology detection use `ThreadPoolExecutor` for per-host concurrency; configure worker count in `config.py` or via `--threads`
- **Graceful degradation** — if a tool is not installed, that stage is skipped without crashing the pipeline
- **Structured output** — every stage writes to its own dedicated file inside `output/`
- **HTML report** — self-contained `output/report.html` with a stage summary table and collapsible result sections; no CDN or JavaScript required (`--html-report`)
- **JSON export** — machine-readable `output/recon_results.json` aggregating all stage data; always written automatically
- **Recon graph** — PNG network graph of domain → subdomains → ports/technologies/vulnerabilities using `networkx` + `matplotlib` (`--graph`)
- **Scope controls** — `--rate-limit`, `--max-hosts`, and `--exclude` for safe, constrained testing
- **Coloured logging** — real-time console feedback with thread names in the rotating log file for parallel traceability
- **Configurable** — all tool paths, timeouts, ports, and flags are controlled from a single `config.py`
- **Zero mandatory Python dependencies** — core pipeline runs on any Python 3.8+ without a virtual environment
- **Proper CLI command** — installable via `pip install .`; run as `ReconForges -u target.com` like any professional security tool

---

## Architecture

```
ReconForges/
├── pyproject.toml                # Package definition + ReconForges entry point
└── recon_framework/
    ├── __init__.py
    ├── main.py                   # CLI entry point + ReconPipeline orchestrator
    ├── config.py                 # Tool paths, timeouts, and stage settings
    ├── logger.py                 # Coloured console + rotating file logger
    ├── modules/
    │   ├── subdomain_enum.py     # Stage 1 — Subfinder + Amass
    │   ├── host_discovery.py     # Stage 2 — httpx (TCP fallback)
    │   ├── web_crawler.py        # Stage 3 — Katana (Python-BFS fallback)
    │   ├── port_scan.py          # Stage 4 — Nmap (parallel per-host)
    │   ├── tech_detection.py     # Stage 5 — WhatWeb (parallel per-host)
    │   ├── vuln_scan.py          # Stage 6 — Nuclei
    │   ├── report_gen.py         # Post-pipeline — HTML + JSON reports
    │   └── graph_gen.py          # Post-pipeline — recon asset graph (networkx)
    └── utils/
        ├── command_runner.py     # subprocess wrapper → CommandResult dataclass
        └── file_utils.py         # write_lines, read_lines, write_report_section
```

### Pipeline Data Flow

```
Target Domain
     │
     ▼
[1] Subdomain Enumeration   ──► output/subdomains.txt
     │  (Subfinder + Amass)
     ▼
[2] Live Host Detection     ──► output/live_hosts.txt
     │  (httpx / TCP probe)
     ▼
[3] Web Crawling            ──► output/crawler_urls.txt
     │  (Katana / Python BFS)    output/crawler_parameters.txt
     │                           output/crawler_js_files.txt
     │                           output/crawler_endpoints.txt
     ▼
[4] Port & Service Scan     ──► output/port_scan_results.txt
     │  (Nmap)
     ▼
[5] Technology Detection    ──► output/tech_detection.txt
     │  (WhatWeb)
     ▼
[6] Vulnerability Scanning  ──► output/vulnerability_report.txt
       (Nuclei — targets: crawler URLs if available, else live hosts)
```

> The web crawler feeds enriched endpoints (full scheme + host + path) into Nuclei, giving it far more precise targets than bare hostnames alone.

---

## Prerequisites

### Python
- Python 3.8 or higher

### External Tools

| Tool | Purpose | Install |
|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [Amass](https://github.com/owasp-amass/amass) | Active/passive subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@master` |
| [httpx](https://github.com/projectdiscovery/httpx) | Live host probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [Katana](https://github.com/projectdiscovery/katana) | Web crawling (JS-aware) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [Nmap](https://nmap.org) | Port and service scanning | `sudo apt install nmap` |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Technology fingerprinting | `sudo apt install whatweb` |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |

> The framework runs with whichever tools are installed. Missing tools produce a warning and that stage is skipped — the rest of the pipeline continues. If Katana is not installed, the web crawler falls back to a built-in Python BFS crawler automatically.

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/AdityaBhardwaj04/ReconForges.git
cd ReconForges
```

### Step 2 — Install external tools

#### Option A — Automated (recommended)

Run the included setup script. It installs all tools, updates Nuclei templates, and installs optional Python packages for graph generation:

```bash
bash install.sh
```

Flags:

```bash
bash install.sh --no-go-tools    # skip Subfinder, httpx, Katana, Nuclei, Amass
bash install.sh --no-apt         # skip nmap and whatweb
bash install.sh --no-python-pkgs # skip networkx + matplotlib
```

#### Option B — Manual

```bash
# Nmap and WhatWeb via apt (Kali Linux / Debian)
sudo apt update && sudo apt install nmap whatweb -y

# ProjectDiscovery tools via Go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@master

# Add Go binaries to your PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Update Nuclei templates
nuclei -update-templates
```

### Step 3 — Install the ReconForges CLI command

```bash
pip install .
```

This registers the `ReconForges` command globally so you can run it from anywhere:

```bash
ReconForges -u example.com
```

For development (changes to source take effect immediately without reinstalling):

```bash
pip install -e .
```

To use a virtual environment (cleanest option, avoids system-package conflicts):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Step 4 — (Optional) Install Python packages for graph generation

```bash
pip install networkx matplotlib
# or via the declared optional extra:
pip install ".[reporting]"
```

### Step 5 — Verify tools are accessible

```bash
subfinder -version && amass -version && httpx -version
katana -version && nmap --version && whatweb --version && nuclei -version
ReconForges --list-stages
```

---

## Usage

### Basic — full pipeline

```bash
ReconForges -u example.com
```

### Set crawler depth and thread count

```bash
ReconForges -u example.com --depth 3 --threads 10
```

### Custom output directory

```bash
ReconForges -u example.com -o ~/engagements/client_name
```

### Run specific stages only

```bash
ReconForges -u example.com --stages subdomain_enum host_discovery web_crawler
```

### Skip a stage

```bash
ReconForges -u example.com --skip vuln_scan
```

### List all available stages

```bash
ReconForges --list-stages
```

### Full options reference

```
usage: ReconForges [-h] [-u TARGET] [--stages STAGE [STAGE ...]]
                   [--skip STAGE [STAGE ...]] [-o DIR]
                   [--list-stages] [--no-banner]
                   [--threads N] [--depth N]
                   [--rate-limit N] [--max-hosts N]
                   [--exclude PATTERN ...] [--json] [--html-report] [--graph]

Target:
  -u, -d, --url, --domain TARGET
                        Target domain or IP address (e.g. example.com)

Stage control:
  --stages STAGE ...    Run only these stages (space-separated)
  --skip STAGE ...      Skip these stages
  --list-stages         List available stages and exit

Output:
  -o, --output DIR      Custom output directory (default: ./output)
  --no-banner           Suppress ASCII banner
  --json                Print JSON report path after pipeline (always written)
  --html-report         Generate output/report.html
  --graph               Generate output/recon_graph.png
                        (requires: pip install networkx matplotlib)

Parallelism / crawler:
  --threads N           Worker threads for port_scan and tech_detection
                        (default: 5)
  --depth N             Web crawler link-hop depth (default: 3)

Scope controls:
  --rate-limit N        Requests/sec cap forwarded to Nuclei (default: 150)
  --max-hosts N         Scan at most N live hosts
  --exclude PATTERN ... Exclude subdomains containing any of these strings
```

---

## Output

All results are saved to the `output/` directory (or your custom `-o` path):

```
output/
├── subdomains.txt            # All discovered subdomains (deduplicated)
├── live_hosts.txt            # Reachable hosts confirmed by httpx/TCP probe
├── crawler_urls.txt          # All URLs crawled across live hosts
├── crawler_parameters.txt    # Unique query parameters discovered during crawl
├── crawler_js_files.txt      # JavaScript file URLs found during crawl
├── crawler_endpoints.txt     # Endpoints extracted from JS files / form actions
├── port_scan_results.txt     # Nmap results per host (ports, services, versions)
├── tech_detection.txt        # Technology stack per host
├── vulnerability_report.txt  # Nuclei findings (CVEs, misconfigs, exposures)
├── recon_results.json        # Machine-readable aggregate of all stage data
├── report.html               # Self-contained HTML report (--html-report)
└── recon_graph.png           # Recon asset network graph (--graph)
```

Logs are written to `logs/recon.log` with full DEBUG output including per-thread names for parallel stages. The console displays INFO and above.

---

## Web Crawler

The `web_crawler` stage runs after live host detection and before port scanning. It crawls every live host and builds a rich set of application-layer targets for Nuclei.

### How it works

1. **Katana** (primary) — a fast, JS-aware crawler from ProjectDiscovery. Extracts URLs, parameters, JS file endpoints, and HTML form actions. Supports headless Chromium for SPA targets.
2. **Python BFS fallback** — if Katana is not installed, a built-in breadth-first crawler takes over using Python's `urllib` (no third-party deps).

### Why it matters

Without crawling, Nuclei only receives bare hostnames like `https://app.example.com`. With crawler output it receives fully-qualified paths like `https://app.example.com/api/v1/users?id=1`, dramatically increasing template match coverage.

### Crawler configuration (`config.py`)

```python
CRAWLER = {
    "depth":              3,     # link-hop depth from the start URL
    "concurrency":        10,    # simultaneous requests per host
    "rate_limit":         150,   # max requests/sec per host
    "timeout":            15,    # per-request timeout (seconds)
    "crawl_timeout":      300,   # max wall-clock time per host (seconds)
    "js_crawl":           True,  # extract endpoints from JS files
    "form_extraction":    True,  # extract HTML form action URLs
    "headless":           False, # Chromium headless rendering (SPAs only)
    "max_urls_per_host":  5000,  # hard cap on URLs per host; 0 = unlimited
    "workers":            3,     # hosts crawled in parallel
}
```

Override depth at runtime:

```bash
ReconForges -u example.com --depth 5
```

Skip the crawler entirely:

```bash
ReconForges -u example.com --skip web_crawler
```

---

## Parallel Scanning

Port scanning and technology detection run each host in its own thread using `ThreadPoolExecutor`.

**Default:** 5 workers. Override at runtime:

```bash
ReconForges -u example.com --threads 10
```

Or set permanently in `config.py`:

```python
PARALLEL["workers"]       = 10   # global default
PORT_SCAN["workers"]      = 8    # port_scan specifically
TECH_DETECTION["workers"] = 6    # tech_detection specifically
```

Results are always written in the **original host order** regardless of which worker finishes first, ensuring deterministic, diff-friendly reports.

Worker names (e.g. `nmap_0`, `tech_2`) appear in `logs/recon.log` at DEBUG level so you can trace per-host timing.

---

## Scope Controls

Four flags help you stay within the authorised scope of an engagement:

| Flag | Effect |
|---|---|
| `--max-hosts N` | Truncate the live hosts list to at most *N* before port/tech/vuln scanning |
| `--exclude PATTERN ...` | Remove any subdomain whose FQDN contains one of the patterns |
| `--rate-limit N` | Cap Nuclei requests to *N* per second (overrides `VULN_SCAN["rate_limit"]`) |
| `--depth N` | Limit web crawler link-hop depth (overrides `CRAWLER["depth"]`) |

Examples:

```bash
# Only scan the first 5 live hosts
ReconForges -u example.com --max-hosts 5

# Exclude staging and dev subdomains
ReconForges -u example.com --exclude staging dev internal

# Throttle Nuclei to 30 req/s
ReconForges -u example.com --rate-limit 30

# Shallow crawl only (1 hop from the start URL)
ReconForges -u example.com --depth 1
```

---

## Reports and Visualisation

### JSON export

`output/recon_results.json` is written after every run automatically. It contains:
- `domain`, `total_elapsed`, `generated_at`
- `stages` — status, elapsed time, and item count per stage
- `raw_files` — full content of every output text file

```bash
ReconForges -u example.com --json   # also prints the path to console
```

### HTML report

A self-contained HTML file with:
- Pipeline summary table with colour-coded status badges
- Collapsible section for each output file (no JS, no external resources)

```bash
ReconForges -u example.com --html-report
# Opens cleanly in any browser: firefox output/report.html
```

### Recon graph

A directed PNG graph: `domain → subdomains → open ports / technologies / vulnerabilities`.

```bash
pip install networkx matplotlib        # one-time install
ReconForges -u example.com --graph
```

Graph is skipped gracefully with a warning if the packages are not installed.

---

## Configuration

All settings are in [`recon_framework/config.py`](recon_framework/config.py). No flags required for most adjustments — just edit the file.

### Tool paths

Tool binaries are resolved from your `PATH` by default. Override any path via environment variables:

```bash
export NUCLEI_PATH=/opt/nuclei
export SUBFINDER_PATH=/usr/local/bin/subfinder
export KATANA_PATH=~/go/bin/katana
ReconForges -u example.com
```

### Key settings

```python
# How many threads httpx uses for host probing
HOST_DISCOVERY["threads"] = 50

# Nmap port range (change to "1-65535" for a full scan)
PORT_SCAN["ports"] = "--top-ports 1000"

# Nuclei severity filter
VULN_SCAN["severity"] = "low,medium,high,critical"

# Amass timeout in minutes
SUBDOMAIN_ENUM["amass_timeout"] = 10

# Web crawler depth and concurrency
CRAWLER["depth"]       = 3
CRAWLER["concurrency"] = 10
CRAWLER["headless"]    = False   # set True for JS-heavy SPAs (requires Chromium)
```

---

## Extending the Framework

Adding a new recon stage takes four steps.

### Step 1 — Create the module

```python
# recon_framework/modules/dns_brute.py

import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_FILES
from logger import get_logger
from utils.command_runner import run_command
from utils.file_utils import write_lines

log = get_logger("modules.dns_brute")

def run(domain: str) -> list:
    log.info("Starting DNS brute force for: %s", domain)
    # ... call your tool via run_command() ...
    results = ["sub1.example.com", "sub2.example.com"]
    write_lines(OUTPUT_FILES["dns_brute"], results)
    return results
```

### Step 2 — Register the stage in `main.py`

```python
STAGE_MAP = {
    ...
    "dns_brute": "modules.dns_brute",   # add this
}

STAGE_ORDER = [
    "subdomain_enum",
    "dns_brute",          # insert at the right position
    "host_discovery",
    ...
]
```

### Step 3 — Add a pipeline call in `ReconPipeline.run()`

```python
elif stage_name == "dns_brute":
    data = module.run(self.domain)
```

### Step 4 — Add the output path in `config.py`

```python
OUTPUT_FILES = {
    ...
    "dns_brute": os.path.join(OUTPUT_DIR, "dns_brute.txt"),
}
```

---

## Example Run

```
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝██╔════╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ███████╗
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ╚════██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗███████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝

      ReconForges — Automated Reconnaissance & Attack Surface Discovery Framework

  Started : 2026-03-17 21:44:06
  Target  : demo.owasp-juice.shop

[21:44:06] [INFO] STAGE: Subdomain Enumeration — target: demo.owasp-juice.shop
[21:44:06] [INFO] [subfinder] Found 38 subdomains.
[21:44:30] [INFO] [amass] Found 12 subdomains.
[21:44:30] [INFO] Subdomain enumeration complete: 44 unique subdomains

[21:44:30] [INFO] STAGE: Live Host Detection — 44 candidates
[21:44:35] [INFO] 21 live hosts detected.

[21:44:35] [INFO] STAGE: Web Crawling — 21 live hosts
[21:44:35] [INFO] [katana] Crawling https://demo.owasp-juice.shop (depth=3)
[21:45:10] [INFO] Web crawling complete: 1,842 URLs across 21 hosts

[21:45:10] [INFO] STAGE: Port & Service Scanning — 21 live hosts
[21:46:45] [INFO] Port scan complete: 21 hosts scanned

[21:46:45] [INFO] STAGE: Technology Detection — 21 hosts
[21:47:05] [INFO] Technology detection complete: 21 hosts analysed

[21:47:05] [INFO] STAGE: Vulnerability Scanning — 1,842 crawler endpoints
[21:47:50] [INFO] Vulnerability scanning complete: 7 finding(s)

============================================================
RECONFORGES — SCAN COMPLETE  |  SUMMARY
============================================================
  subdomain_enum          [COMPLETED]   30.2s  (44 items)
  host_discovery          [COMPLETED]    5.1s  (21 items)
  web_crawler             [COMPLETED]   35.4s  (1842 items)
  port_scan               [COMPLETED]   95.3s  (21 items)
  tech_detection          [COMPLETED]   19.8s  (21 hosts)
  vuln_scan               [COMPLETED]   45.2s   (7 items)
============================================================
```

---

## Disclaimer

> This tool is intended for **authorized security assessments only**.
>
> Only run this framework against systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, or equivalent laws in your jurisdiction.
>
> The authors accept no liability for misuse of this tool.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
