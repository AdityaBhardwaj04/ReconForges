"""
tech_detection.py - Technology stack fingerprinting using WhatWeb.

Pipeline stage 4.
Identifies web frameworks, CMS platforms, web servers, programming
languages, and third-party libraries in use by the target.
Results are written to output/tech_detection.txt.
"""

import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import OUTPUT_FILES, PARALLEL, TECH_DETECTION, TOOL_PATHS
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import ensure_dir, write_report_section

log = get_logger("modules.tech_detection")


# ---------------------------------------------------------------------------
# WhatWeb runner
# ---------------------------------------------------------------------------

def _run_whatweb(host: str, aggression: int = 1, timeout: int = 30) -> str:
    """
    Run WhatWeb against *host* and return its text output.

    Aggression levels
    -----------------
    1 - Passive, single request per target (default, safe)
    3 - Aggressive, follows redirects and makes extra requests
    4 - Heavy aggressive (noisy, may trigger WAF)
    """
    cmd = [
        TOOL_PATHS["whatweb"],
        host,
        f"--aggression={aggression}",
        "--color=never",         # plain text for file output
        "--log-brief=-",         # brief output to stdout
        f"--open-timeout={timeout}",
        f"--read-timeout={timeout}",
    ]

    result = run_command(cmd, timeout=timeout + 10)

    if not result.success:
        log.warning("[whatweb] Failed for %s: %s", host, result.error or result.stderr[:200])
        return f"[ERROR] WhatWeb failed for {host}\n"

    return result.stdout.strip() or f"[INFO] No technologies detected for {host}"


def _run_httpx_tech(host: str, timeout: int = 15) -> str:
    """
    Fallback: use httpx --tech-detect if WhatWeb is unavailable.
    Returns a summary string.
    """
    cmd = [
        TOOL_PATHS["httpx"],
        "-u", host,
        "-tech-detect",
        "-status-code",
        "-title",
        "-server",
        "-silent",
        f"-timeout", str(timeout),
    ]

    result = run_command(cmd, timeout=timeout + 5)

    if not result.success:
        return f"[ERROR] httpx tech-detect failed for {host}\n"

    return result.stdout.strip() or f"[INFO] No data returned for {host}"


# ---------------------------------------------------------------------------
# Parallel worker
# ---------------------------------------------------------------------------

def _detect_host_worker(
    host: str,
    use_whatweb: bool,
    aggression: int,
    timeout: int,
) -> tuple:
    """
    ThreadPoolExecutor worker: fingerprint technologies for one host.

    Returns (host, output_string) so the main thread can write results in
    the original host order without file-write races.
    """
    thread_name = threading.current_thread().name
    log.debug("[%s] Starting tech detection for %s", thread_name, host)
    t_start = time.monotonic()

    if use_whatweb:
        output = _run_whatweb(host, aggression=aggression, timeout=timeout)
    else:
        output = _run_httpx_tech(host, timeout=timeout)

    elapsed = time.monotonic() - t_start
    log.debug("[%s] Finished %s in %.1fs", thread_name, host, elapsed)
    return host, output


# ---------------------------------------------------------------------------
# Public stage entry point
# ---------------------------------------------------------------------------

def run(live_hosts: List[str]) -> Dict[str, str]:
    """
    Fingerprint technologies for every host in *live_hosts*.

    Prefers WhatWeb; falls back to httpx ``--tech-detect`` if WhatWeb is
    absent.  Results are written to ``output/tech_detection.txt``.

    Returns
    -------
    dict[str, str]
        Mapping of hostname → raw detection output.
    """
    log.info("=" * 60)
    log.info("STAGE: Technology Detection — %d hosts", len(live_hosts))
    log.info("=" * 60)

    if not live_hosts:
        log.warning("No live hosts — skipping technology detection.")
        return {}

    use_whatweb = tool_available(TOOL_PATHS["whatweb"])
    use_httpx   = tool_available(TOOL_PATHS["httpx"])

    if not use_whatweb and not use_httpx:
        log.error("Neither whatweb nor httpx found — technology detection aborted.")
        return {}

    aggression = TECH_DETECTION.get("aggression", 1)
    timeout    = TECH_DETECTION.get("timeout", 30)

    output_path = OUTPUT_FILES["tech_detection"]
    ensure_dir(os.path.dirname(output_path))

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("AUTOMATED RECON FRAMEWORK — TECHNOLOGY DETECTION\n")
        fh.write("=" * 60 + "\n\n")

    workers = TECH_DETECTION.get("workers", PARALLEL.get("workers", 5))
    results: Dict[str, str] = {}

    log.info("[tech] Spawning up to %d parallel workers …", workers)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tech") as executor:
        future_to_host = {
            executor.submit(
                _detect_host_worker, host, use_whatweb, aggression, timeout
            ): host
            for host in live_hosts
        }
        for future in as_completed(future_to_host):
            original_host = future_to_host[future]
            try:
                host, output = future.result()
                results[host] = output
            except Exception as exc:                       # noqa: BLE001
                log.error("[tech] Worker failed for %s: %s", original_host, exc)
                results[original_host] = f"[ERROR] Worker exception for {original_host}: {exc}\n"

    # Write sections in original host order for deterministic output
    for host in live_hosts:
        output = results.get(host, f"[ERROR] No result for {host}\n")
        write_report_section(output_path, f"Host: {host}", output)

    log.info("Technology detection complete: %d hosts analysed → %s", len(results), output_path)
    return results
