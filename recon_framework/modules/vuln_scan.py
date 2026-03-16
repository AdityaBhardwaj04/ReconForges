"""
vuln_scan.py - Vulnerability scanning using Nuclei.

Pipeline stage 5.
Runs Nuclei against all live hosts with configurable severity filters.
Writes findings to output/vulnerability_report.txt.
"""

import os
import sys
import tempfile
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as _root_cfg
from config import OUTPUT_FILES, TOOL_PATHS, VULN_SCAN
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import ensure_dir, read_lines, write_lines

log = get_logger("modules.vuln_scan")


# ---------------------------------------------------------------------------
# Nuclei runner
# ---------------------------------------------------------------------------

def _update_nuclei_templates() -> None:
    """Pull the latest Nuclei template database (best-effort, skippable via config)."""
    if not VULN_SCAN.get("update_templates", True):
        log.debug("[nuclei] Template update skipped (update_templates=False).")
        return
    if not tool_available(TOOL_PATHS["nuclei"]):
        return

    log.info("[nuclei] Updating templates …")
    result = run_command(
        [TOOL_PATHS["nuclei"], "-update-templates", "-silent", "-duc"],
        timeout=120,
    )
    if result.success:
        log.info("[nuclei] Templates updated.")
    else:
        log.warning("[nuclei] Template update failed (using existing templates): %s", result.stderr[:200])


def _run_nuclei(hosts_file: str, output_file: str) -> List[str]:
    """
    Execute Nuclei against the host list in *hosts_file*.

    Speed flags used
    ----------------
    -c   concurrency    — parallel template runners (default: 50)
    -bs  bulk_size      — hosts per template batch  (default: 50)
    -rl  rate_limit     — requests/sec hard cap     (default: 500)
    -timeout            — per-request timeout        (default: 5s)
    -retries 0          — no retries on failure (biggest single speedup)
    -ss template-spray  — scan all hosts per template before moving on
    -etags headless     — skip Chromium-based templates (very slow)
    -nh                 — skip httpx probe (host_discovery already ran it)
    -duc                — disable update check at scan time

    Returns the raw finding lines written to *output_file*.
    """
    cfg         = VULN_SCAN
    severity    = cfg.get("severity",      "low,medium,high,critical")
    concurrency = cfg.get("concurrency",   50)
    bulk_size   = cfg.get("bulk_size",     50)
    rate_limit  = cfg.get("rate_limit",    500)
    timeout     = cfg.get("timeout",       5)
    retries     = cfg.get("retries",       0)
    strategy    = cfg.get("scan_strategy", "template-spray")
    excl_tags   = cfg.get("exclude_tags",  "headless")

    # Allow --rate-limit CLI flag to override the module default
    scope_rl = _root_cfg.SCOPE.get("rate_limit", 0)
    if scope_rl > 0:
        rate_limit = scope_rl
        log.debug("[nuclei] Rate limit overridden by SCOPE: %d req/s", rate_limit)

    cmd = [
        TOOL_PATHS["nuclei"],
        "-l",        hosts_file,
        "-o",        output_file,
        "-s",        severity,           # severity filter
        "-c",        str(concurrency),   # parallel template runners
        "-bs",       str(bulk_size),     # hosts per template batch
        "-rl",       str(rate_limit),    # requests/sec cap
        "-timeout",  str(timeout),       # per-request timeout
        "-retries",  str(retries),       # 0 = fail fast, no retry
        "-ss",       strategy,           # template-spray is faster for multi-target
        "-etags",    excl_tags,          # skip headless (Chromium) templates
        "-nh",                           # skip httpx probe (already done upstream)
        "-duc",                          # disable update check at scan time
        "-silent",
        "-no-color",
    ]

    # Conservative scan timeout: proportional to concurrency × timeout, floored at 1 hour
    scan_timeout = max(concurrency * timeout * 30, 3600)
    log.info(
        "[nuclei] Scan started — severity=%s  concurrency=%d  rate=%d/s  timeout=%ds  strategy=%s",
        severity, concurrency, rate_limit, timeout, strategy,
    )

    result = run_command(cmd, timeout=scan_timeout)

    if result.timed_out:
        log.warning("[nuclei] Scan timed out — partial results may be available.")
    elif not result.success:
        log.error("[nuclei] Scan failed: %s", result.error or result.stderr[:300])
        return []

    findings = read_lines(output_file)
    return findings


# ---------------------------------------------------------------------------
# Public stage entry point
# ---------------------------------------------------------------------------

def run(live_hosts: List[str]) -> List[str]:
    """
    Run Nuclei vulnerability scanning against *live_hosts*.

    Writes all findings to ``output/vulnerability_report.txt`` and returns
    the list of finding lines.

    Returns
    -------
    list[str]
        Raw Nuclei finding lines (one per finding).
    """
    log.info("=" * 60)
    log.info("STAGE: Vulnerability Scanning — %d hosts", len(live_hosts))
    log.info("=" * 60)

    if not live_hosts:
        log.warning("No live hosts — skipping vulnerability scanning.")
        return []

    if not tool_available(TOOL_PATHS["nuclei"]):
        log.error("nuclei not found — vulnerability scanning aborted.")
        return []

    # Best-effort template refresh
    _update_nuclei_templates()

    output_path = OUTPUT_FILES["vulnerabilities"]
    ensure_dir(os.path.dirname(output_path))

    findings: List[str] = []

    with tempfile.TemporaryDirectory(prefix="recon_nuclei_") as tmpdir:
        hosts_file  = os.path.join(tmpdir, "targets.txt")
        nuclei_out  = os.path.join(tmpdir, "nuclei_raw.txt")

        with open(hosts_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(live_hosts))

        findings = _run_nuclei(hosts_file, nuclei_out)

    if not findings:
        log.info("[nuclei] No findings — target may be well-hardened or templates matched nothing.")
        findings = ["[INFO] No vulnerabilities detected with configured template set."]

    count = write_lines(output_path, findings, deduplicate=False)
    log.info(
        "Vulnerability scanning complete: %d finding(s) → %s",
        count, output_path,
    )
    return findings
