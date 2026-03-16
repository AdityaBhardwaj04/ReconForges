"""
host_discovery.py - Live host detection using httpx.

Pipeline stage 2.
Probes each subdomain over HTTP and HTTPS to filter out dead hosts.
Writes output/live_hosts.txt with only the reachable targets.
"""

import os
import sys
import tempfile
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import HOST_DISCOVERY, OUTPUT_FILES, TOOL_PATHS
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import read_lines, write_lines

log = get_logger("modules.host_discovery")


# ---------------------------------------------------------------------------
# httpx-based probing
# ---------------------------------------------------------------------------

def _is_projectdiscovery_httpx() -> bool:
    """
    Return True only if the httpx binary is ProjectDiscovery's recon tool.

    Kali also ships a Python 'httpx' HTTP client with completely different
    flags.  ProjectDiscovery's httpx prints 'projectdiscovery' in its version
    output; the Python client does not.

    Uses a raw subprocess call (not run_command) so no warning is logged when
    the Python httpx fails the version flag — that failure is expected and
    handled here silently.
    """
    import subprocess
    try:
        proc = subprocess.run(
            [TOOL_PATHS["httpx"], "-version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            text=True,
        )
        return "projectdiscovery" in (proc.stdout + proc.stderr).lower()
    except Exception:
        return False


def _probe_with_httpx(hosts_file: str, output_file: str) -> List[str]:
    """
    Run ProjectDiscovery httpx against the host list and return live URLs.

    Reads results from stdout (not -o file) to avoid a known hang when httpx
    writes to a file in certain sandbox environments.
    httpx prints one ``scheme://host [status] [title]`` per line.
    """
    if not tool_available(TOOL_PATHS["httpx"]):
        log.warning("httpx not found — falling back to basic TCP check.")
        return []

    if not _is_projectdiscovery_httpx():
        log.warning(
            "httpx on PATH is not ProjectDiscovery's tool — skipping "
            "(TCP fallback will be used)."
        )
        return []

    cfg     = HOST_DISCOVERY
    threads = cfg.get("threads", 50)
    timeout = cfg.get("timeout", 10)

    cmd = [
        TOOL_PATHS["httpx"],
        "-l",       hosts_file,
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-silent",
        "-status-code",
        "-title",
        "-follow-redirects",
        "-no-color",
    ]

    log.info("[httpx] Probing hosts (threads=%d, timeout=%ds) …", threads, timeout)
    result = run_command(cmd, timeout=threads * timeout * 2)

    if not result.success:
        log.error("[httpx] Failed: %s", result.error or result.stderr[:200])
        return []

    # Extract only the first token from each line (the URL/hostname).
    # httpx appends status-code and title after whitespace; keeping the full
    # line (with possible ANSI codes) caused nmap to receive garbage hostnames.
    lines = []
    for l in result.stdout.splitlines():
        l = l.strip()
        if not l:
            continue
        lines.append(l.split()[0])
    if lines:
        with open(output_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")

    return lines


def _fallback_tcp_check(hosts: List[str], timeout: int = 5) -> List[str]:
    """
    TCP connect fallback when httpx is unavailable.

    Tries port 80 and 443 for each host.
    """
    import socket

    live: List[str] = []
    for host in hosts:
        for port in (80, 443):
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    live.append(host)
                    break
            except (OSError, socket.timeout):
                continue
    return live


# ---------------------------------------------------------------------------
# Public stage entry point
# ---------------------------------------------------------------------------

def run(subdomains: List[str]) -> List[str]:
    """
    Probe *subdomains* for liveness.

    Reads from the provided list (populated by stage 1), writes reachable
    hosts to ``output/live_hosts.txt``, and returns that list.

    Returns
    -------
    list[str]
        Live host entries as returned by httpx (e.g. ``https://sub.example.com``).
    """
    log.info("=" * 60)
    log.info("STAGE: Live Host Detection — %d candidates", len(subdomains))
    log.info("=" * 60)

    if not subdomains:
        log.warning("No subdomains provided — skipping host discovery.")
        return []

    live_hosts: List[str] = []

    with tempfile.TemporaryDirectory(prefix="recon_") as tmpdir:
        # Write candidate list to a temp file for httpx
        hosts_tmp  = os.path.join(tmpdir, "candidates.txt")
        httpx_out  = os.path.join(tmpdir, "httpx_out.txt")

        with open(hosts_tmp, "w") as fh:
            fh.write("\n".join(subdomains))

        live_hosts = _probe_with_httpx(hosts_tmp, httpx_out)

        if not live_hosts:
            log.warning("httpx returned nothing — trying TCP fallback …")
            live_hosts = _fallback_tcp_check(subdomains, timeout=HOST_DISCOVERY.get("timeout", 10))

    if not live_hosts:
        log.warning("No live hosts detected.")
    else:
        log.info("%d live hosts detected.", len(live_hosts))

    output_path = OUTPUT_FILES["live_hosts"]
    count = write_lines(output_path, live_hosts)
    log.info("Live host detection complete: %d hosts → %s", count, output_path)

    return read_lines(output_path)
