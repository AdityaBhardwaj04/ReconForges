"""
main.py - CLI entry point and pipeline orchestrator for ReconForges.

Usage
-----
    ReconForges -u example.com
    ReconForges -u example.com --depth 3 --threads 10
    ReconForges -u example.com -o results/
    ReconForges -u example.com --stages subdomain_enum host_discovery
    ReconForges -u example.com --output /tmp/recon_out --skip vuln_scan
    ReconForges --list-stages
"""

import argparse
import importlib
import os
import sys
import time
from datetime import datetime
from typing import List, Optional

# Ensure the recon_framework package root is on sys.path so that all
# sibling modules (config, logger, modules.*, utils.*) resolve correctly.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config as cfg
from logger import get_logger
from utils.file_utils import ensure_dir

log = get_logger("main")


# ---------------------------------------------------------------------------
# Available pipeline stages (order matters)
# ---------------------------------------------------------------------------

STAGE_MAP = {
    "subdomain_enum":  "modules.subdomain_enum",
    "host_discovery":  "modules.host_discovery",
    "web_crawler":     "modules.web_crawler",    # after host_discovery; before port_scan
    "port_scan":       "modules.port_scan",
    "tech_detection":  "modules.tech_detection",
    "vuln_scan":       "modules.vuln_scan",
}

STAGE_ORDER = list(STAGE_MAP.keys())


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝██╔════╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ███████╗
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ╚════██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗███████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══════╝

      ReconForges — Automated Reconnaissance & Attack Surface Discovery Framework
"""


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

class ReconPipeline:
    """Drives the ordered execution of recon stages."""

    def __init__(
        self,
        domain: str,
        stages: List[str],
        output_dir: Optional[str] = None,
    ) -> None:
        self.domain = domain
        self.stages = stages

        if output_dir:
            # Override paths in config so all modules write to this directory
            cfg.OUTPUT_DIR = output_dir
            for key in cfg.OUTPUT_FILES:
                filename = os.path.basename(cfg.OUTPUT_FILES[key])
                cfg.OUTPUT_FILES[key] = os.path.join(output_dir, filename)

        ensure_dir(cfg.OUTPUT_DIR)
        ensure_dir(cfg.LOG_DIR)

    # ------------------------------------------------------------------ #

    def _load_stage(self, name: str):
        """Dynamically import a stage module."""
        module_path = STAGE_MAP[name]
        return importlib.import_module(module_path)

    # ------------------------------------------------------------------ #

    def run(self) -> dict:
        """
        Execute each enabled stage in order, threading results between them.

        Stage data-flow
        ---------------
        subdomain_enum  → list[str] subdomains
        host_discovery  → list[str] live hosts
        port_scan       → list[str] scanned hosts
        tech_detection  → dict[str, str] host → tech info
        vuln_scan       → list[str] finding lines
        """
        log.info("Target      : %s", self.domain)
        log.info("Stages      : %s", ", ".join(self.stages))
        log.info("Output dir  : %s", cfg.OUTPUT_DIR)

        pipeline_start = time.monotonic()
        results: dict  = {"domain": self.domain, "stages": {}}

        # Accumulate inter-stage data
        subdomains:    List[str] = []
        live_hosts:    List[str] = []
        crawler_urls:  List[str] = []   # populated by web_crawler; fed into vuln_scan

        for stage_name in STAGE_ORDER:
            if stage_name not in self.stages:
                log.info("Stage '%s' is disabled — skipping.", stage_name)
                continue

            stage_start = time.monotonic()
            log.info("")
            log.info(">>> Starting stage: %s", stage_name.upper())

            try:
                module = self._load_stage(stage_name)

                # ---- call each stage with the right arguments ---- #
                if stage_name == "subdomain_enum":
                    data = module.run(self.domain)
                    # Apply --exclude scope filter
                    exclude_patterns = cfg.SCOPE.get("exclude", [])
                    if exclude_patterns:
                        before = len(data)
                        data = [
                            s for s in data
                            if not any(pat in s for pat in exclude_patterns)
                        ]
                        removed = before - len(data)
                        if removed:
                            log.info(
                                "Scope: removed %d subdomain(s) matching --exclude patterns.",
                                removed,
                            )
                    subdomains = data

                elif stage_name == "host_discovery":
                    data = module.run(subdomains)
                    # Apply --max-hosts scope cap
                    max_hosts = cfg.SCOPE.get("max_hosts", 0)
                    if max_hosts > 0 and len(data) > max_hosts:
                        log.info(
                            "Scope: truncating live hosts from %d → %d (--max-hosts).",
                            len(data), max_hosts,
                        )
                        data = data[:max_hosts]
                    live_hosts = data

                elif stage_name == "web_crawler":
                    data = module.run(live_hosts)
                    crawler_urls = data

                elif stage_name == "port_scan":
                    data = module.run(live_hosts)

                elif stage_name == "tech_detection":
                    data = module.run(live_hosts)

                elif stage_name == "vuln_scan":
                    # Prefer crawler-discovered endpoints over bare live hosts:
                    # crawler_urls are full URLs (scheme+host+path) which give
                    # Nuclei much more precise targets than hostnames alone.
                    targets = crawler_urls if crawler_urls else live_hosts
                    if crawler_urls:
                        log.info(
                            "vuln_scan: using %d crawler-discovered endpoints "
                            "as Nuclei targets (instead of %d bare live hosts).",
                            len(crawler_urls), len(live_hosts),
                        )
                    data = module.run(targets)

                else:
                    log.warning("Unknown stage '%s' — skipped.", stage_name)
                    continue

                elapsed = time.monotonic() - stage_start
                results["stages"][stage_name] = {
                    "status":  "completed",
                    "elapsed": round(elapsed, 2),
                    "data":    data,
                }
                log.info("<<< Stage '%s' completed in %.1fs.", stage_name, elapsed)

            except Exception as exc:                       # noqa: BLE001
                elapsed = time.monotonic() - stage_start
                log.exception("Stage '%s' raised an unexpected error: %s", stage_name, exc)
                results["stages"][stage_name] = {
                    "status":  "error",
                    "elapsed": round(elapsed, 2),
                    "error":   str(exc),
                }

                if cfg.PIPELINE.get("stop_on_empty") and not data:
                    log.warning("stop_on_empty is set — aborting pipeline.")
                    break

        total = time.monotonic() - pipeline_start
        results["total_elapsed"] = round(total, 2)

        self._print_summary(results)
        return results

    # ------------------------------------------------------------------ #

    def _print_summary(self, results: dict) -> None:
        """Print a clean end-of-run summary table."""
        log.info("")
        log.info("=" * 60)
        log.info("RECONFORGES — SCAN COMPLETE  |  SUMMARY")
        log.info("=" * 60)
        log.info("Target  : %s", results["domain"])
        log.info("Runtime : %.1fs", results["total_elapsed"])
        log.info("")

        for stage, info in results["stages"].items():
            status  = info["status"].upper()
            elapsed = info["elapsed"]
            data    = info.get("data", [])

            count_str = ""
            if isinstance(data, list):
                count_str = f"  ({len(data)} items)"
            elif isinstance(data, dict):
                count_str = f"  ({len(data)} hosts)"

            log.info("  %-22s  [%s]  %.1fs%s", stage, status, elapsed, count_str)

        log.info("")
        log.info("Output files:")
        for key, path in cfg.OUTPUT_FILES.items():
            if os.path.isfile(path):
                size = os.path.getsize(path)
                log.info("  %-22s  %s  (%d bytes)", key, path, size)
        log.info("=" * 60)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ReconForges",
        description="ReconForges — Automated Reconnaissance & Attack Surface Discovery Framework. "
                    "Orchestrates Subfinder, Amass, Nmap, WhatWeb, and Nuclei.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ReconForges -u example.com
  ReconForges -u example.com --depth 3 --threads 10
  ReconForges -u example.com -o results/
  ReconForges -u example.com --stages subdomain_enum host_discovery port_scan
  ReconForges -u example.com --skip vuln_scan
  ReconForges -u example.com --output /tmp/pentest_results
  ReconForges --list-stages
  ReconForges --no-banner -u example.com
        """,
    )

    parser.add_argument(
        "-u", "-d", "--url", "--domain",
        metavar="TARGET",
        dest="domain",
        help="Target domain or IP address (e.g. example.com)",
    )
    parser.add_argument(
        "--stages",
        nargs="+",
        metavar="STAGE",
        choices=STAGE_ORDER,
        default=None,
        help="Run only these stages (space-separated). "
             f"Choices: {', '.join(STAGE_ORDER)}",
    )
    parser.add_argument(
        "--skip",
        nargs="+",
        metavar="STAGE",
        choices=STAGE_ORDER,
        default=[],
        help="Skip these stages.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="DIR",
        default=None,
        help="Override the output directory (default: ./output)",
    )
    parser.add_argument(
        "--list-stages",
        action="store_true",
        help="List available pipeline stages and exit.",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the ASCII banner.",
    )

    # -- Parallelism / crawler controls --------------------------------------
    parser.add_argument(
        "--threads",
        metavar="N",
        type=int,
        default=None,
        help="Parallel worker count for port_scan and tech_detection (default: 5).",
    )
    parser.add_argument(
        "--depth",
        metavar="N",
        type=int,
        default=None,
        help="Web crawler link-hop depth (default: 3).",
    )

    # -- Scope controls ------------------------------------------------------
    parser.add_argument(
        "--rate-limit",
        metavar="N",
        type=int,
        default=None,
        dest="rate_limit",
        help="Requests-per-second cap forwarded to Nuclei (default: 150).",
    )
    parser.add_argument(
        "--max-hosts",
        metavar="N",
        type=int,
        default=None,
        dest="max_hosts",
        help="Scan at most N live hosts (truncates list before port/tech/vuln stages).",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        metavar="PATTERN",
        default=[],
        help="Exclude subdomains whose FQDN contains any of these strings.",
    )

    # -- Output formats ------------------------------------------------------
    parser.add_argument(
        "--json",
        action="store_true",
        dest="output_json",
        help="Write JSON results to output/recon_results.json (always written; "
             "this flag prints the path at INFO level).",
    )
    parser.add_argument(
        "--html-report",
        action="store_true",
        dest="html_report",
        help="Generate a self-contained HTML report at output/report.html.",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        dest="graph",
        help="Generate a recon asset graph PNG at output/recon_graph.png "
             "(requires: pip install networkx matplotlib).",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    if args.list_stages:
        print("Available pipeline stages (in execution order):")
        for i, name in enumerate(STAGE_ORDER, 1):
            print(f"  {i}. {name}")
        return 0

    if not args.domain:
        parser.error("the -d/--domain argument is required.")

    # -- Apply runtime overrides to config singletons BEFORE pipeline build --
    if args.threads is not None:
        cfg.PARALLEL["workers"]          = args.threads
        cfg.PORT_SCAN["workers"]         = args.threads
        cfg.TECH_DETECTION["workers"]    = args.threads

    if args.depth is not None:
        cfg.CRAWLER["depth"] = args.depth

    if args.rate_limit is not None:
        cfg.SCOPE["rate_limit"] = args.rate_limit

    if args.max_hosts is not None:
        cfg.SCOPE["max_hosts"] = args.max_hosts

    if args.exclude:
        cfg.SCOPE["exclude"] = args.exclude

    if not args.no_banner:
        print(BANNER)

    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Target  : {args.domain}")
    print()
    log.info("[ReconForges] Starting reconnaissance pipeline...")

    # Determine which stages to run
    if args.stages:
        stages = [s for s in STAGE_ORDER if s in args.stages]
    else:
        stages = list(STAGE_ORDER)

    if args.skip:
        stages = [s for s in stages if s not in args.skip]

    if not stages:
        log.error("No stages selected after applying --stages / --skip filters.")
        return 1

    pipeline = ReconPipeline(
        domain=args.domain,
        stages=stages,
        output_dir=args.output,
    )

    results = pipeline.run()

    # -- Post-pipeline: JSON (always written; --json just makes it verbose) --
    try:
        from modules.report_gen import write_json
        json_path = write_json(results)
        if args.output_json:
            log.info("JSON report: %s", json_path)
    except Exception as exc:
        log.warning("JSON report generation failed: %s", exc)

    # -- Post-pipeline: HTML report ------------------------------------------
    if args.html_report:
        try:
            from modules.report_gen import write_html
            html_path = write_html(results)
            log.info("HTML report: %s", html_path)
        except Exception as exc:
            log.warning("HTML report generation failed: %s", exc)

    # -- Post-pipeline: graph (optional dep, graceful fallback) --------------
    if args.graph:
        try:
            from modules.graph_gen import write_graph
            graph_path = write_graph(results)
            log.info("Recon graph: %s", graph_path)
        except ImportError as exc:
            log.warning(
                "Graph generation skipped — install dependencies first: "
                "pip install networkx matplotlib\n  (%s)", exc
            )
        except Exception as exc:
            log.warning("Graph generation failed: %s", exc)

    return 0


if __name__ == "__main__":
    sys.exit(main())
