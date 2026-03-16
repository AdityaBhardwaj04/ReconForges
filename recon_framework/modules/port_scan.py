"""
port_scan.py - Port and service scanning using Nmap.

Pipeline stage 3.
Runs nmap against every live host, captures open ports, service banners,
and version information, then writes output/port_scan_results.txt.
"""

import os
import re
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_FILES, PARALLEL, PORT_SCAN, TOOL_PATHS
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import ensure_dir, write_report_section

log = get_logger("modules.port_scan")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_scheme(host: str) -> str:
    """Remove http:// or https:// prefix so nmap receives a clean hostname."""
    return re.sub(r"^https?://", "", host).rstrip("/").split("/")[0]


def _nmap_scan(host: str, output_base: str) -> str:
    """
    Scan *host* with nmap and return the grepable output as a string.

    Uses -oN (normal), -oG (grepable), and -oX (XML) all at once so the
    report file gets human-readable output while callers can later parse
    the grepable/XML formats if needed.
    """
    cfg     = PORT_SCAN
    timing  = cfg.get("timing", "T4")
    ports   = cfg.get("ports", "--top-ports 1000")
    extras  = cfg.get("extra_flags", "-sV --open")
    timeout = cfg.get("timeout", 300)

    normal_out = f"{output_base}.nmap"
    grep_out   = f"{output_base}.gnmap"
    xml_out    = f"{output_base}.xml"

    # Build the command list; split string flags safely
    cmd = [
        TOOL_PATHS["nmap"],
        f"-{timing}",
    ]

    # Ports can be "--top-ports 1000" (two tokens) or "80,443" (one token)
    cmd.extend(ports.split())
    cmd.extend(extras.split())
    cmd.extend([
        "-oN", normal_out,
        "-oG", grep_out,
        "-oX", xml_out,
        host,
    ])

    log.info("[nmap] Scanning %s …", host)
    result = run_command(cmd, timeout=timeout)

    if not result.success:
        msg = result.error or result.stderr[:300]
        log.error("[nmap] Scan of %s failed: %s", host, msg)
        return f"[ERROR] nmap scan failed for {host}: {msg}\n"

    # Prefer the normal output for the report
    if os.path.isfile(normal_out):
        with open(normal_out, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()

    return result.stdout


# ---------------------------------------------------------------------------
# Parallel worker
# ---------------------------------------------------------------------------

def _scan_host_worker(host: str, tmpdir: str) -> tuple:
    """
    ThreadPoolExecutor worker: run nmap for one host.

    Returns (clean_host, scan_output) so the main thread can write results
    in the original host order without any file-write races.
    """
    thread_name = threading.current_thread().name
    clean_host  = _strip_scheme(host)
    safe_name   = re.sub(r"[^\w.-]", "_", clean_host)
    output_base = os.path.join(tmpdir, safe_name)

    log.debug("[%s] Starting nmap for %s", thread_name, clean_host)
    t_start = time.monotonic()

    scan_output = _nmap_scan(clean_host, output_base)

    elapsed = time.monotonic() - t_start
    log.debug("[%s] Finished %s in %.1fs", thread_name, clean_host, elapsed)
    return clean_host, scan_output


# ---------------------------------------------------------------------------
# Public stage entry point
# ---------------------------------------------------------------------------

def run(live_hosts: List[str]) -> List[str]:
    """
    Scan every host in *live_hosts* with nmap.

    Writes consolidated results to ``output/port_scan_results.txt`` and
    returns the list of hosts that had at least one open port.

    Returns
    -------
    list[str]
        Hosts for which nmap found open ports (clean hostname format).
    """
    log.info("=" * 60)
    log.info("STAGE: Port & Service Scanning — %d live hosts", len(live_hosts))
    log.info("=" * 60)

    if not live_hosts:
        log.warning("No live hosts to scan — skipping port scan.")
        return []

    if not tool_available(TOOL_PATHS["nmap"]):
        log.error("nmap not found — port scanning aborted.")
        return []

    output_path = OUTPUT_FILES["port_scan"]
    ensure_dir(os.path.dirname(output_path))

    # Clear (or create) the output file before writing sections
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("AUTOMATED RECON FRAMEWORK — PORT SCAN RESULTS\n")
        fh.write("=" * 60 + "\n\n")

    workers       = PORT_SCAN.get("workers", PARALLEL.get("workers", 5))
    scanned_hosts: List[str] = []

    with tempfile.TemporaryDirectory(prefix="recon_nmap_") as tmpdir:
        results_map: Dict[str, str] = {}

        log.info("[nmap] Spawning up to %d parallel workers …", workers)
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="nmap") as executor:
            future_to_host = {
                executor.submit(_scan_host_worker, host, tmpdir): host
                for host in live_hosts
            }
            for future in as_completed(future_to_host):
                original_host = future_to_host[future]
                try:
                    clean_host, scan_output = future.result()
                    results_map[clean_host] = scan_output
                except Exception as exc:                   # noqa: BLE001
                    clean_host = _strip_scheme(original_host)
                    log.error("[nmap] Worker failed for %s: %s", clean_host, exc)
                    results_map[clean_host] = f"[ERROR] Worker exception for {clean_host}: {exc}\n"

        # Write sections in original host order for deterministic output
        for host in live_hosts:
            clean_host  = _strip_scheme(host)
            scan_output = results_map.get(clean_host, f"[ERROR] No result for {clean_host}\n")
            write_report_section(output_path, f"Host: {clean_host}", scan_output)
            if "[ERROR]" not in scan_output:
                scanned_hosts.append(clean_host)

    log.info("Port scan complete: %d hosts scanned → %s", len(scanned_hosts), output_path)
    return scanned_hosts
