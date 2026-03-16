"""
graph_gen.py - Recon asset graph visualizer (optional post-pipeline stage).

Generates a directed PNG graph of the reconnaissance findings:

  domain → subdomains → open ports / detected technologies / vulnerabilities

Output: output/recon_graph.png

Dependencies (optional — not required for the core pipeline):
  pip install networkx matplotlib

If either package is missing the module raises ImportError which main.py
catches and converts to a warning, keeping the pipeline running cleanly.
"""

import os
import re
import sys
from typing import Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config as cfg
from logger import get_logger
from utils.file_utils import ensure_dir, read_lines

log = get_logger("modules.graph_gen")

# ---------------------------------------------------------------------------
# Optional dependency guard — import once at module level so the ImportError
# propagates to the caller immediately rather than at draw time.
# ---------------------------------------------------------------------------

try:
    import networkx as nx
    import matplotlib
    matplotlib.use("Agg")          # non-interactive backend — no display required
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch
    _DEPS_OK = True
except ImportError as _import_err:
    _DEPS_OK     = False
    _IMPORT_ERR  = str(_import_err)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Color palette (Catppuccin Mocha — matches the HTML report theme)
_COLOR = {
    "domain":    "#89b4fa",   # blue
    "subdomain": "#a6e3a1",   # green
    "port":      "#fab387",   # peach / orange
    "tech":      "#cba6f7",   # mauve / purple
    "vuln":      "#f38ba8",   # red
}

_BG_DARK   = "#1e1e2e"
_BG_PANEL  = "#313244"
_FG        = "#cdd6f4"
_EDGE_COL  = "#45475a"


def _parse_open_ports(report_path: str) -> Dict[str, List[str]]:
    """
    Extract open-port lines from the consolidated nmap report file.

    Returns {hostname: [port_str, ...]} where port_str is e.g.
    ``"80/tcp  http"`` (port + service name, truncated for graph legibility).
    """
    if not os.path.isfile(report_path):
        return {}

    result: Dict[str, List[str]] = {}
    current_host: str = ""
    host_re = re.compile(r"Host:\s*(\S+)")
    port_re = re.compile(r"^\s*(\d+/\w+)\s+open\s+(\S+)")

    for line in read_lines(report_path):
        host_match = host_re.search(line)
        if host_match:
            current_host = host_match.group(1)
            result.setdefault(current_host, [])
            continue
        if current_host and port_re.match(line):
            m = port_re.match(line)
            result[current_host].append(f"{m.group(1)} {m.group(2)}")

    return result


def _build_graph(results: dict) -> "nx.DiGraph":
    """Construct the directed graph from pipeline results."""
    domain = results.get("domain", "unknown")
    stages = results.get("stages", {})

    G = nx.DiGraph()
    node_attrs: Dict[str, dict] = {}

    def add(node: str, layer: str) -> None:
        G.add_node(node)
        node_attrs[node] = {"layer": layer, "color": _COLOR.get(layer, _FG)}

    add(domain, "domain")

    # -- Subdomains ----------------------------------------------------------
    subdomains: List[str] = stages.get("subdomain_enum", {}).get("data", [])
    if not subdomains:
        subdomains = read_lines(cfg.OUTPUT_FILES.get("subdomains", ""))

    for sub in subdomains:
        add(sub, "subdomain")
        G.add_edge(domain, sub)

    # -- Open ports ----------------------------------------------------------
    port_scan_path = cfg.OUTPUT_FILES.get("port_scan", "")
    port_map = _parse_open_ports(port_scan_path)

    for host, ports in port_map.items():
        # Connect to subdomain node if present, else directly to domain
        parent = host if G.has_node(host) else domain
        for port_str in ports[:6]:          # cap at 6 port nodes per host
            node = f"{host}\n{port_str}"
            add(node, "port")
            G.add_edge(parent, node)

    # -- Technologies --------------------------------------------------------
    tech_data: Dict[str, str] = stages.get("tech_detection", {}).get("data", {})
    for host, tech_str in tech_data.items():
        parent = host if G.has_node(host) else domain
        techs  = re.findall(r"\[([^\]]{1,30})\]", tech_str)
        seen   = set()
        for tech in techs:
            if tech in seen:
                continue
            seen.add(tech)
            node = f"{host}\n[{tech}]"
            add(node, "tech")
            G.add_edge(parent, node)
            if len(seen) >= 4:              # cap at 4 tech nodes per host
                break

    # -- Vulnerabilities -----------------------------------------------------
    vuln_lines: List[str] = stages.get("vuln_scan", {}).get("data", [])
    for vuln_line in vuln_lines[:25]:       # cap total vuln nodes at 25
        if vuln_line.startswith("[INFO]"):
            continue
        node = vuln_line[:55]               # truncate long lines for legibility
        add(node, "vuln")
        G.add_edge(domain, node)

    # Attach color attribute back to nodes
    nx.set_node_attributes(G, {n: d["color"] for n, d in node_attrs.items()}, "color")
    return G


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def write_graph(results: dict) -> str:
    """
    Build and save a directed PNG graph of the recon findings.

    Parameters
    ----------
    results : dict
        The dict returned by ``ReconPipeline.run()``.

    Returns
    -------
    str
        Absolute path of the written PNG.

    Raises
    ------
    ImportError
        If ``networkx`` or ``matplotlib`` are not installed.
    """
    if not _DEPS_OK:
        raise ImportError(
            f"graph_gen requires networkx and matplotlib. "
            f"Install them with: pip install networkx matplotlib\n"
            f"Original error: {_IMPORT_ERR}"
        )

    output_path = cfg.OUTPUT_FILES.get(
        "report_graph", os.path.join(cfg.OUTPUT_DIR, "recon_graph.png")
    )
    ensure_dir(os.path.dirname(output_path))

    domain = results.get("domain", "unknown")
    G = _build_graph(results)

    log.info(
        "[graph_gen] Graph: %d nodes, %d edges — rendering …",
        G.number_of_nodes(), G.number_of_edges(),
    )

    # Layout — spring for small graphs, shell for larger ones (faster)
    try:
        if G.number_of_nodes() <= 60:
            pos = nx.spring_layout(G, seed=42, k=2.5)
        else:
            pos = nx.kamada_kawai_layout(G)
    except Exception:
        pos = nx.random_layout(G, seed=42)

    node_colors = [G.nodes[n].get("color", _FG) for n in G.nodes()]

    # Scale figure to graph size
    node_count = G.number_of_nodes()
    fig_w = max(18, min(node_count * 0.8, 40))
    fig_h = max(12, min(node_count * 0.55, 28))

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    ax.set_facecolor(_BG_DARK)
    fig.patch.set_facecolor(_BG_DARK)

    nx.draw_networkx_nodes(
        G, pos, ax=ax,
        node_color=node_colors,
        node_size=350,
        alpha=0.92,
    )
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color=_EDGE_COL,
        arrows=True,
        arrowstyle="-|>",
        arrowsize=14,
        alpha=0.65,
        connectionstyle="arc3,rad=0.05",
    )
    nx.draw_networkx_labels(
        G, pos, ax=ax,
        font_size=6,
        font_color=_FG,
        font_family="monospace",
    )

    ax.set_title(
        f"Recon Graph — {domain}",
        color=_COLOR["domain"],
        fontsize=14,
        pad=18,
        fontfamily="monospace",
    )
    ax.axis("off")

    legend_handles = [
        Patch(facecolor=_COLOR["domain"],    label="Domain"),
        Patch(facecolor=_COLOR["subdomain"], label="Subdomains"),
        Patch(facecolor=_COLOR["port"],      label="Ports / Services"),
        Patch(facecolor=_COLOR["tech"],      label="Technologies"),
        Patch(facecolor=_COLOR["vuln"],      label="Vulnerabilities"),
    ]
    ax.legend(
        handles=legend_handles,
        loc="upper left",
        facecolor=_BG_PANEL,
        labelcolor=_FG,
        fontsize=8,
        edgecolor=_EDGE_COL,
    )

    plt.tight_layout()
    plt.savefig(
        output_path,
        dpi=150,
        bbox_inches="tight",
        facecolor=fig.get_facecolor(),
    )
    plt.close(fig)

    log.info("Graph written: %s (%d bytes)", output_path, os.path.getsize(output_path))
    return output_path
