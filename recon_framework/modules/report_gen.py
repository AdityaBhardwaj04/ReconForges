"""
report_gen.py - Post-pipeline report generator.

Produces two output artefacts after the pipeline finishes:

  output/recon_results.json   — machine-readable aggregated results
  output/report.html          — self-contained HTML summary (no JS, no CDN)

Both consume the results dict returned by ReconPipeline.run().
Zero mandatory third-party dependencies — stdlib only.
"""

import json
import os
import sys
import time
from typing import Any, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as cfg
from logger import get_logger
from utils.file_utils import ensure_dir, read_lines

log = get_logger("modules.report_gen")


# ---------------------------------------------------------------------------
# JSON export
# ---------------------------------------------------------------------------

def write_json(results: dict) -> str:
    """
    Serialise the pipeline results dict to JSON.

    The output includes the raw content of every stage output file so the
    JSON artefact is fully self-contained.

    Parameters
    ----------
    results : dict
        The dict returned by ``ReconPipeline.run()``.

    Returns
    -------
    str
        Absolute path of the written file.
    """
    output_path = cfg.OUTPUT_FILES.get(
        "report_json", os.path.join(cfg.OUTPUT_DIR, "recon_results.json")
    )
    ensure_dir(os.path.dirname(output_path))

    payload: Dict[str, Any] = {
        "generated_at":  time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "domain":        results.get("domain"),
        "total_elapsed": results.get("total_elapsed"),
        "stages":        results.get("stages", {}),
        "raw_files":     {},
    }

    # Attach raw text content of every pipeline output file that exists.
    for key, path in cfg.OUTPUT_FILES.items():
        if key.startswith("report_"):
            continue          # skip the report outputs themselves
        if os.path.isfile(path):
            payload["raw_files"][key] = read_lines(path)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)

    log.info("JSON report written: %s (%d bytes)", output_path, os.path.getsize(output_path))
    return output_path


# ---------------------------------------------------------------------------
# HTML report — embedded template (no Jinja2 required)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report &mdash; {domain}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body   {{ font-family: 'Courier New', monospace; background: #1e1e2e;
            color: #cdd6f4; margin: 0; padding: 2rem; line-height: 1.5; }}
  a      {{ color: #89b4fa; }}
  h1     {{ color: #89b4fa; margin-bottom: .25rem; font-size: 1.6rem; }}
  h2     {{ color: #94e2d5; border-bottom: 1px solid #313244;
            padding-bottom: .3rem; margin-top: 2rem; font-size: 1.15rem; }}
  .meta  {{ color: #6c7086; font-size: .85rem; margin-bottom: 1.5rem; }}
  table  {{ border-collapse: collapse; width: 100%; margin-bottom: 1.5rem;
            font-size: .9rem; }}
  th, td {{ border: 1px solid #45475a; padding: .4rem .8rem; text-align: left; }}
  th     {{ background: #313244; color: #89b4fa; }}
  tr:nth-child(even) {{ background: #181825; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: .8rem;
            font-weight: bold; }}
  .ok    {{ background: #a6e3a1; color: #1e1e2e; }}
  .err   {{ background: #f38ba8; color: #1e1e2e; }}
  details {{ margin: .5rem 0; }}
  summary {{ cursor: pointer; color: #89dceb; font-weight: bold;
             padding: .3rem 0; list-style: none; }}
  summary::before {{ content: "▶ "; font-size: .8rem; }}
  details[open] summary::before {{ content: "▼ "; }}
  pre    {{ background: #181825; padding: 1rem; overflow-x: auto;
            border-radius: 4px; font-size: .8em; white-space: pre-wrap;
            word-break: break-all; margin: 0; border: 1px solid #313244; }}
  .empty {{ color: #6c7086; font-style: italic; padding: .5rem 0; }}
</style>
</head>
<body>

<h1>Recon Report</h1>
<p class="meta">
  <strong>Target:</strong> {domain} &nbsp;&bull;&nbsp;
  <strong>Generated:</strong> {generated_at} &nbsp;&bull;&nbsp;
  <strong>Total elapsed:</strong> {total_elapsed}s
</p>

<h2>Pipeline Summary</h2>
<table>
  <thead>
    <tr><th>Stage</th><th>Status</th><th>Elapsed (s)</th><th>Items</th></tr>
  </thead>
  <tbody>
    {summary_rows}
  </tbody>
</table>

<h2>Stage Results</h2>
{file_sections}

</body>
</html>
"""


def _escape(text: str) -> str:
    """Minimal HTML escaping — only the characters that break raw <pre> blocks."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _stage_row(name: str, info: dict) -> str:
    status  = info.get("status", "unknown")
    elapsed = info.get("elapsed", 0)
    data    = info.get("data", [])
    badge   = "ok" if status == "completed" else "err"
    count   = len(data) if isinstance(data, (list, dict)) else "-"
    return (
        f'    <tr><td>{name}</td>'
        f'<td><span class="badge {badge}">{status.upper()}</span></td>'
        f'<td>{elapsed}</td><td>{count}</td></tr>'
    )


def _file_section(label: str, path: str) -> str:
    if not os.path.isfile(path):
        return (
            f'<details><summary>{label}</summary>'
            f'<p class="empty">File not generated.</p></details>\n'
        )
    size = os.path.getsize(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    safe = _escape(content)
    return (
        f'<details><summary>{label} '
        f'<span style="color:#6c7086;font-size:.8em">({size:,} bytes)</span>'
        f'</summary>\n<pre>{safe}</pre></details>\n'
    )


def write_html(results: dict) -> str:
    """
    Render a self-contained HTML report from pipeline results.

    Parameters
    ----------
    results : dict
        The dict returned by ``ReconPipeline.run()``.

    Returns
    -------
    str
        Absolute path of the written file.
    """
    output_path = cfg.OUTPUT_FILES.get(
        "report_html", os.path.join(cfg.OUTPUT_DIR, "report.html")
    )
    ensure_dir(os.path.dirname(output_path))

    summary_rows = "\n".join(
        _stage_row(name, info)
        for name, info in results.get("stages", {}).items()
    )

    file_sections = ""
    for key, path in cfg.OUTPUT_FILES.items():
        if key.startswith("report_"):
            continue
        label = key.replace("_", " ").title()
        file_sections += _file_section(label, path)

    html = _HTML_TEMPLATE.format(
        domain        = results.get("domain", "unknown"),
        generated_at  = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        total_elapsed = results.get("total_elapsed", 0),
        summary_rows  = summary_rows,
        file_sections = file_sections,
    )

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html)

    log.info("HTML report written: %s (%d bytes)", output_path, os.path.getsize(output_path))
    return output_path
