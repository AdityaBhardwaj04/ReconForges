"""
subdomain_enum.py - Subdomain enumeration using Subfinder and Amass.

Pipeline stage 1.
Runs both tools concurrently, merges results, deduplicates, and writes
output/subdomains.txt.
"""

import json
import os
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_FILES, SUBDOMAIN_ENUM, TOOL_PATHS
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import read_lines, write_lines

log = get_logger("modules.subdomain_enum")


# ---------------------------------------------------------------------------
# Individual tool runners
# ---------------------------------------------------------------------------

def _run_subfinder(domain: str, output_file: str) -> List[str]:
    """Run subfinder and return discovered subdomains."""
    if not tool_available(TOOL_PATHS["subfinder"]):
        log.warning("subfinder not found — skipping.")
        return []

    log.info("[subfinder] Starting enumeration for: %s", domain)

    result = run_command(
        [
            TOOL_PATHS["subfinder"],
            "-d", domain,
            "-o", output_file,
            "-silent",
        ],
        timeout=300,
    )

    if not result.success:
        log.error("[subfinder] Failed: %s", result.error or result.stderr[:200])
        return []

    subdomains = read_lines(output_file)
    log.info("[subfinder] Found %d subdomains.", len(subdomains))
    return subdomains


def _run_amass(domain: str, output_file: str) -> List[str]:
    """Run amass enum and return discovered subdomains."""
    if not tool_available(TOOL_PATHS["amass"]):
        log.warning("amass not found — skipping.")
        return []

    timeout_min = SUBDOMAIN_ENUM.get("amass_timeout", 10)
    log.info("[amass] Starting enumeration for: %s (timeout %dmin)", domain, timeout_min)

    result = run_command(
        [
            TOOL_PATHS["amass"],
            "enum",
            "-passive",
            "-d", domain,
            "-o", output_file,
            "-timeout", str(timeout_min),
        ],
        timeout=timeout_min * 60 + 30,   # allow slight overrun
    )

    if not result.success:
        log.error("[amass] Failed: %s", result.error or result.stderr[:200])
        return []

    subdomains = read_lines(output_file)
    if not subdomains:
        # amass v5 may not create the -o file when passive mode finds nothing;
        # results go to stdout instead — parse them as a fallback.
        log.debug("[amass] Output file empty — parsing stdout as fallback.")
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or " " in line or line.startswith("[") or "." not in line or "\x1b" in line:
                continue
            subdomains.append(line)
        if subdomains:
            log.debug("[amass] Recovered %d subdomains from stdout.", len(subdomains))
    log.info("[amass] Found %d subdomains.", len(subdomains))
    return subdomains


# ---------------------------------------------------------------------------
# crt.sh passive fallback
# ---------------------------------------------------------------------------

def _run_crtsh(domain: str) -> List[str]:
    """
    Query crt.sh certificate transparency logs for *domain*.

    Pure-Python fallback using stdlib urllib.request only.
    Returns a deduplicated list of discovered subdomains.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    log.info("[crt.sh] Querying certificate transparency logs for: %s", domain)

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (recon-framework/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        log.warning("[crt.sh] HTTP error %d — skipping.", exc.code)
        return []
    except urllib.error.URLError as exc:
        log.warning("[crt.sh] Network error: %s — skipping.", exc.reason)
        return []
    except Exception as exc:
        log.warning("[crt.sh] Unexpected error: %s — skipping.", exc)
        return []

    try:
        entries = json.loads(raw)
    except json.JSONDecodeError:
        log.warning("[crt.sh] Malformed JSON response — skipping.")
        return []

    if not isinstance(entries, list):
        log.warning("[crt.sh] Unexpected response format — skipping.")
        return []

    seen: set = set()
    subdomains: List[str] = []
    suffix = f".{domain}"

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lower()
            if not name:
                continue
            if name.startswith("*."):
                name = name[2:]
            if name != domain and not name.endswith(suffix):
                continue
            if "*" in name or " " in name:
                continue
            if name not in seen:
                seen.add(name)
                subdomains.append(name)

    log.info("[crt.sh] Found %d unique subdomains.", len(subdomains))
    return subdomains


# ---------------------------------------------------------------------------
# Public stage entry point
# ---------------------------------------------------------------------------

def run(domain: str) -> List[str]:
    """
    Execute subdomain enumeration for *domain*.

    Runs subfinder and/or amass (controlled by config.SUBDOMAIN_ENUM),
    merges results, and writes ``output/subdomains.txt``.

    Returns
    -------
    list[str]
        Deduplicated list of discovered subdomains.
    """
    log.info("=" * 60)
    log.info("STAGE: Subdomain Enumeration — target: %s", domain)
    log.info("=" * 60)

    all_subdomains: List[str] = []

    # Use a temp directory for raw tool outputs
    with tempfile.TemporaryDirectory(prefix="recon_") as tmpdir:
        sf_out   = os.path.join(tmpdir, "subfinder.txt")
        amass_out = os.path.join(tmpdir, "amass.txt")

        if SUBDOMAIN_ENUM.get("use_subfinder", True):
            all_subdomains.extend(_run_subfinder(domain, sf_out))

        if SUBDOMAIN_ENUM.get("use_amass", True):
            all_subdomains.extend(_run_amass(domain, amass_out))

    if not all_subdomains:
        log.warning("No results from subfinder/amass — attempting crt.sh passive lookup.")
        all_subdomains = _run_crtsh(domain)

    if not all_subdomains:
        log.warning("No subdomains discovered — check tool availability and target.")
        # Always include the root domain so later stages have something to work with
        all_subdomains = [domain]

    output_path = OUTPUT_FILES["subdomains"]
    count = write_lines(output_path, all_subdomains)

    log.info("Subdomain enumeration complete: %d unique subdomains → %s", count, output_path)
    return read_lines(output_path)
