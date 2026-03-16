"""
config.py - Central configuration for the Automated Reconnaissance Framework.

All tool paths, timeouts, and pipeline defaults are defined here.
Override any value by editing this file or by passing CLI flags.
"""

import os
import shutil

# ---------------------------------------------------------------------------
# Base paths
# ---------------------------------------------------------------------------

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR  = os.path.join(BASE_DIR, "output")
LOG_DIR     = os.path.join(BASE_DIR, "logs")

# ---------------------------------------------------------------------------
# Tool resolver
# ---------------------------------------------------------------------------

def _resolve_tool(env_var: str, name: str, prefer_gobin: bool = False) -> str:
    """
    Return the best path for an external tool binary.

    Resolution order:
      1. Environment variable override (e.g. SUBFINDER_PATH)
      2. ~/go/bin/<name>  — if prefer_gobin=True (Go tools that may conflict
         with system packages, e.g. httpx conflicts with Python's httpx)
      3. Tool already on PATH (shutil.which)
      4. ~/go/bin/<name>  — Go's default install location (last resort)
      5. Fall back to bare name (will fail gracefully at runtime)
    """
    if env_var in os.environ:
        return os.environ[env_var]
    go_bin = os.path.join(os.path.expanduser("~"), "go", "bin", name)
    if prefer_gobin and os.path.isfile(go_bin):
        return go_bin
    if shutil.which(name):
        return name
    if os.path.isfile(go_bin):
        return go_bin
    return name

# ---------------------------------------------------------------------------
# Output file names
# ---------------------------------------------------------------------------

OUTPUT_FILES = {
    "subdomains":           os.path.join(OUTPUT_DIR, "subdomains.txt"),
    "live_hosts":           os.path.join(OUTPUT_DIR, "live_hosts.txt"),
    # Web crawler outputs (produced by the web_crawler stage)
    "crawler_urls":         os.path.join(OUTPUT_DIR, "crawler_urls.txt"),
    "crawler_parameters":   os.path.join(OUTPUT_DIR, "crawler_parameters.txt"),
    "crawler_js_files":     os.path.join(OUTPUT_DIR, "crawler_js_files.txt"),
    "crawler_endpoints":    os.path.join(OUTPUT_DIR, "crawler_endpoints.txt"),
    "port_scan":            os.path.join(OUTPUT_DIR, "port_scan_results.txt"),
    "tech_detection":       os.path.join(OUTPUT_DIR, "tech_detection.txt"),
    "vulnerabilities":      os.path.join(OUTPUT_DIR, "vulnerability_report.txt"),
    # Post-pipeline report outputs
    "report_html":          os.path.join(OUTPUT_DIR, "report.html"),
    "report_json":          os.path.join(OUTPUT_DIR, "recon_results.json"),
    "report_graph":         os.path.join(OUTPUT_DIR, "recon_graph.png"),
}

# ---------------------------------------------------------------------------
# External tool binary paths
# Kali Linux defaults are used; change if your tools live elsewhere.
# ---------------------------------------------------------------------------

TOOL_PATHS = {
    # Go-based ProjectDiscovery tools: prefer ~/go/bin/ over system PATH
    # because Kali ships conflicting packages (e.g. Python's httpx client).
    "subfinder":  _resolve_tool("SUBFINDER_PATH", "subfinder", prefer_gobin=True),
    "amass":      _resolve_tool("AMASS_PATH",      "amass",     prefer_gobin=True),
    "nuclei":     _resolve_tool("NUCLEI_PATH",     "nuclei",    prefer_gobin=True),
    "httpx":      _resolve_tool("HTTPX_PATH",      "httpx",     prefer_gobin=True),
    "katana":     _resolve_tool("KATANA_PATH",     "katana",    prefer_gobin=True),
    # System tools: standard PATH resolution is fine
    "nmap":       _resolve_tool("NMAP_PATH",       "nmap"),
    "whatweb":    _resolve_tool("WHATWEB_PATH",    "whatweb"),
}

# ---------------------------------------------------------------------------
# Per-module settings
# ---------------------------------------------------------------------------

SUBDOMAIN_ENUM = {
    # Run both tools and merge; set False to skip one
    "use_subfinder": True,
    "use_amass":     True,
    # amass timeout in minutes
    "amass_timeout": 10,
}

HOST_DISCOVERY = {
    # httpx concurrency
    "threads":  50,
    # per-host timeout in seconds
    "timeout":  10,
    # also probe HTTPS (in addition to HTTP)
    "probe_https": True,
}

PORT_SCAN = {
    # nmap timing template (0-5; 4 = aggressive, safe for local use)
    "timing":        "T4",
    # port range; use "--top-ports 1000" syntax or explicit "1-65535"
    "ports":         "--top-ports 1000",
    # extra nmap flags appended verbatim
    "extra_flags":   "-sV --open",
    # per-host nmap timeout in seconds
    "timeout":       300,
    # parallel worker threads (overridden at runtime by --threads)
    "workers":       5,
}

TECH_DETECTION = {
    # WhatWeb aggression level (1-4)
    "aggression":  1,
    # per-host timeout in seconds
    "timeout":     30,
    # parallel worker threads (overridden at runtime by --threads)
    "workers":     5,
}

CRAWLER = {
    # Number of link-hops to follow from the start URL (depth 0)
    "depth":              3,
    # Simultaneous HTTP requests per host (Katana -c / Python BFS workers)
    "concurrency":        10,
    # Max requests per second per host  (Katana -rl / Python BFS rate-limit)
    "rate_limit":         150,
    # Per-request HTTP timeout in seconds
    "timeout":            15,
    # Maximum wall-clock crawl time per host in seconds (Katana -ct)
    "crawl_timeout":      300,
    # User-Agent sent with every request
    "user_agent":         (
        "Mozilla/5.0 (compatible; ReconForges/1.0; "
        "+https://github.com/AdityaBhardwaj04/ReconForges)"
    ),
    # Passive JS crawling: extract endpoints from downloaded .js files (Katana -jc)
    "js_crawl":           True,
    # Extract HTML form action URLs (Katana -form-extraction)
    "form_extraction":    True,
    # Headless JS rendering via Chromium — much slower, requires Chromium installed
    # Set True only when targets use heavy client-side rendering (SPAs)
    "headless":           False,
    # Hard cap on URLs crawled per host; 0 = unlimited
    "max_urls_per_host":  5000,
    # Number of hosts crawled in parallel (outer ThreadPoolExecutor)
    "workers":            3,
    # HTTP retry count on transient errors (Python BFS only)
    "retry":              2,
    # File extensions to skip entirely (images, fonts, media, archives)
    "exclude_extensions": [
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
        "css", "woff", "woff2", "ttf", "eot", "otf",
        "mp4", "mp3", "mpeg", "ogg", "wav", "webm", "avi", "mov",
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "zip", "tar", "gz", "rar", "7z",
    ],
}

VULN_SCAN = {
    # nuclei template severity filter  (info,low,medium,high,critical)
    "severity":       "low,medium,high,critical",
    # parallel template runners (-c); raise to 100 on high-core machines
    "concurrency":    50,
    # hosts processed per template batch (-bs)
    "bulk_size":      50,
    # requests per second hard cap (-rl); raise cautiously on fast networks
    "rate_limit":     500,
    # per-request timeout in seconds (-timeout); lower = fail faster
    "timeout":        5,
    # retry count on transient failures (-retries); 0 = no retries for speed
    "retries":        0,
    # scanning strategy (-ss): "template-spray" is faster when target count > 1
    # use "host-spray" if you need per-host result ordering
    "scan_strategy":  "template-spray",
    # comma-separated template tags to exclude (-etags)
    # "headless" skips browser-based templates that spin up Chromium (very slow)
    "exclude_tags":   "headless",
    # pull latest templates before each scan; set False to skip on repeat runs
    "update_templates": True,
}

# ---------------------------------------------------------------------------
# Parallel execution settings
# ---------------------------------------------------------------------------

PARALLEL = {
    # Default ThreadPoolExecutor workers for port_scan and tech_detection.
    # Overridden at runtime by --threads CLI flag.
    "workers": 5,
}

# ---------------------------------------------------------------------------
# Scope and rate-limit controls
# ---------------------------------------------------------------------------

SCOPE = {
    # Hard cap on live hosts passed downstream; 0 = unlimited
    "max_hosts":  0,
    # Subdomains whose FQDN contains any of these strings are removed
    "exclude":    [],
    # Global requests-per-second cap forwarded to Nuclei; 0 = use module default
    "rate_limit": 0,
}

# ---------------------------------------------------------------------------
# Global pipeline settings
# ---------------------------------------------------------------------------

PIPELINE = {
    # stages to run in order; pass --skip web_crawler to omit it
    "stages": [
        "subdomain_enum",
        "host_discovery",
        "web_crawler",      # ← crawls live hosts, feeds enriched targets to vuln_scan
        "port_scan",
        "tech_detection",
        "vuln_scan",
    ],
    # stop the pipeline if a stage produces 0 results
    "stop_on_empty": False,
}
