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
    "subdomains":        os.path.join(OUTPUT_DIR, "subdomains.txt"),
    "live_hosts":        os.path.join(OUTPUT_DIR, "live_hosts.txt"),
    "port_scan":         os.path.join(OUTPUT_DIR, "port_scan_results.txt"),
    "tech_detection":    os.path.join(OUTPUT_DIR, "tech_detection.txt"),
    "vulnerabilities":   os.path.join(OUTPUT_DIR, "vulnerability_report.txt"),
    # Post-pipeline report outputs
    "report_html":       os.path.join(OUTPUT_DIR, "report.html"),
    "report_json":       os.path.join(OUTPUT_DIR, "recon_results.json"),
    "report_graph":      os.path.join(OUTPUT_DIR, "recon_graph.png"),
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

VULN_SCAN = {
    # nuclei template severity filter  (info,low,medium,high,critical)
    "severity":     "low,medium,high,critical",
    # nuclei concurrency
    "concurrency":  25,
    # nuclei rate limit (req/sec)
    "rate_limit":   150,
    # nuclei timeout per template
    "timeout":      10,
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
    # stages to run; remove a key to skip that stage
    "stages": [
        "subdomain_enum",
        "host_discovery",
        "port_scan",
        "tech_detection",
        "vuln_scan",
    ],
    # stop the pipeline if a stage produces 0 results
    "stop_on_empty": False,
}
