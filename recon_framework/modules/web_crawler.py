"""
web_crawler.py - Web Crawling and Endpoint Discovery for ReconForges.

Strategy
--------
Primary  : Katana (ProjectDiscovery) — Go-based, JS-aware, high-performance crawler.
           Same tool ecosystem as nuclei / httpx / subfinder already in the pipeline.
Fallback : Pure-Python BFS crawler built on urllib + html.parser (zero extra deps).

Discovers
---------
  • Full URLs and endpoint paths
  • Query parameters and their keys
  • JavaScript file URLs
  • Form action endpoints
  • API-style routes (/api/, /v1/, /graphql, etc.)
  • Endpoints embedded inside JS files (regex extraction)
  • robots.txt paths and sitemap.xml URLs
  • Internal links and hidden paths

Loop-prevention / Deduplication
---------------------------------
  • Every URL is normalised before insertion into the seen-set:
      – lowercase scheme + host
      – query params sorted alphabetically
      – fragment stripped
      – trailing slash removed (except root "/")
  • BFS depth cap enforced per-host (configurable, default: 3)
  • Domain-scope guard: only same-apex-domain URLs are followed
  • Binary / media extension filter blocks non-HTML assets before enqueue
  • Katana enforces dedup internally; the Python fallback mirrors the same rules
"""

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree

import config as cfg
from logger import get_logger
from utils.command_runner import run_command, tool_available
from utils.file_utils import ensure_dir, write_lines

log = get_logger("web_crawler")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BINARY_EXTENSIONS: frozenset = frozenset([
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp", "tiff",
    "css", "woff", "woff2", "ttf", "eot", "otf",
    "mp4", "mp3", "mpeg", "ogg", "wav", "webm", "avi", "mov",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "zip", "tar", "gz", "rar", "7z", "bz2",
    "exe", "bin", "dll", "so", "apk", "dmg", "msi",
    "map",  # .js.map source-map files
])

# Regex patterns for extracting API endpoints from JavaScript source
_JS_ENDPOINT_PATTERNS: List[re.Pattern] = [
    # Quoted relative API paths: '/api/v1/users', "/graphql"
    re.compile(
        r"""(?:['"`])(\/(?:api|v\d+|graphql|rest|internal|admin|auth|user|users|"""
        r"""data|search|endpoint|service|query|mutation)[a-zA-Z0-9_\-./]*"""
        r"""(?:\?[^'"`\s]*)?)(?:['"`])"""
    ),
    # fetch() and axios calls: fetch('/api/...'), axios.get('/...')
    re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|"""
        r"""XMLHttpRequest\.open|\.ajax)\s*\(\s*['"`]([^'"`\s]{3,300})['"`]"""
    ),
    # URL/endpoint string assignments: baseURL = '...', apiURL: '/...'
    re.compile(
        r"""(?:baseURL|apiURL|API_URL|BASE_URL|endpoint|apiBase|serverURL)"""
        r"""\s*[:=]\s*['"`]([^'"`\s]{3,300})['"`]"""
    ),
    # Express/router route definitions: router.get('/path'), app.post('/endpoint')
    re.compile(
        r"""(?:router|app|express)\s*\.\s*(?:get|post|put|delete|patch|use|all)"""
        r"""\s*\(\s*['"`]([^'"`\s]{2,200})['"`]"""
    ),
    # Any quoted path starting with /  (catch-all, stricter length bounds)
    re.compile(r"""(?:['"`])(\/[a-zA-Z0-9_\-]{2,}(?:\/[a-zA-Z0-9_\-./]{0,100})?)(?:['"`])"""),
]


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------

def _apex_domain(netloc: str) -> str:
    """
    Return the apex (eTLD+1) domain from a netloc string.
    Handles IPv4 addresses and bare hostnames gracefully.

    Examples
    --------
    "sub.example.com" → "example.com"
    "example.com"     → "example.com"
    "192.168.1.1"     → "192.168.1.1"
    """
    host = netloc.lower().split(":")[0]  # strip port
    parts = host.split(".")
    if len(parts) >= 2 and not parts[-1].isdigit():
        return ".".join(parts[-2:])
    return host


def _normalize_url(url: str) -> str:
    """
    Canonicalize a URL for reliable deduplication.

    Transformations applied:
    - Lowercase scheme and host
    - Strip URL fragment (#section)
    - Sort query parameters alphabetically
    - Remove trailing slash from path (except bare root "/")
    """
    try:
        p = urllib.parse.urlparse(url.strip())
        scheme = p.scheme.lower()
        host   = p.netloc.lower()
        path   = p.path.rstrip("/") or "/"
        query  = urllib.parse.urlencode(
            sorted(urllib.parse.parse_qsl(p.query, keep_blank_values=True))
        )
        return urllib.parse.urlunparse((scheme, host, path, "", query, ""))
    except Exception:
        return url


def _is_same_domain(url: str, apex: str) -> bool:
    """Return True when *url* belongs to the same apex domain as *apex*."""
    try:
        netloc = urllib.parse.urlparse(url).netloc
        return _apex_domain(netloc) == apex
    except Exception:
        return False


def _has_binary_extension(url: str) -> bool:
    """Return True if the URL path ends with a non-crawlable file extension."""
    path = urllib.parse.urlparse(url).path.lower()
    ext  = path.rsplit(".", 1)[-1].split("?")[0] if "." in path else ""
    return ext in _BINARY_EXTENSIONS


def _resolve_url(href: str, base: str) -> Optional[str]:
    """
    Resolve *href* (possibly relative) against *base*.
    Returns None for non-HTTP schemes or unparseable inputs.
    """
    try:
        full   = urllib.parse.urljoin(base, href.strip())
        parsed = urllib.parse.urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        return full
    except Exception:
        return None


# ---------------------------------------------------------------------------
# HTML link extractor
# ---------------------------------------------------------------------------

class _LinkExtractor(HTMLParser):
    """
    Streaming HTML parser that collects:
      links    — href / src / data-url values (raw, not yet resolved)
      js_files — <script src="..."> references
      forms    — <form action="..."> values
    """

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links:    List[str] = []
        self.js_files: List[str] = []
        self.forms:    List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:  # noqa: C901
        d = dict(attrs)

        if tag in ("a", "link", "area", "base"):
            href = d.get("href", "")
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                self.links.append(href)

        elif tag == "script":
            src = d.get("src", "")
            if src:
                self.js_files.append(src)

        elif tag in ("img", "iframe", "frame", "embed", "source", "track", "video", "audio"):
            for attr in ("src", "data-src"):
                val = d.get(attr, "")
                if val:
                    self.links.append(val)
            # srcset may contain multiple space-separated URL+descriptor pairs
            srcset = d.get("srcset", "")
            if srcset:
                for part in srcset.split(","):
                    url_part = part.strip().split()[0]
                    if url_part:
                        self.links.append(url_part)

        elif tag == "form":
            action = d.get("action", "")
            if action and not action.startswith(("javascript:", "#")):
                self.forms.append(action)

        # data-* attributes that carry URL-like values
        for attr_name, attr_val in attrs:
            if attr_name in ("data-url", "data-href", "data-src", "data-action", "data-endpoint"):
                if attr_val and (attr_val.startswith("/") or attr_val.startswith("http")):
                    self.links.append(attr_val)


# ---------------------------------------------------------------------------
# HTTP fetch helper
# ---------------------------------------------------------------------------

def _fetch(
    url:        str,
    timeout:    int   = 15,
    retries:    int   = 2,
    user_agent: str   = "Mozilla/5.0 (compatible; ReconForges/1.0)",
    delay:      float = 1.0,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Fetch *url* with retry logic.

    Returns
    -------
    (body: str, content_type: str, final_url: str)
    All three are None on persistent failure.
    """
    headers = {
        "User-Agent":      user_agent,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "identity",       # avoid gzip so we can read as-is
        "Connection":      "keep-alive",
    }

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content_type = resp.headers.get("Content-Type", "")
                final_url    = resp.geturl()
                body         = resp.read(5 * 1024 * 1024)  # cap at 5 MB
                return body.decode("utf-8", errors="replace"), content_type, final_url
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 401, 403, 404, 410, 429):
                return None, None, None      # no point retrying client errors
            if attempt < retries:
                time.sleep(delay)
        except (urllib.error.URLError, OSError, TimeoutError):
            if attempt < retries:
                time.sleep(delay)

    return None, None, None


# ---------------------------------------------------------------------------
# robots.txt and sitemap.xml discovery
# ---------------------------------------------------------------------------

def _crawl_robots_sitemap(
    base_url:   str,
    user_agent: str,
    timeout:    int,
) -> List[str]:
    """
    Fetch and parse robots.txt and sitemap.xml for a given base URL.

    Handles:
    - robots.txt Allow/Disallow paths
    - Sitemap: directives in robots.txt
    - <loc> entries in sitemap.xml and sitemap_index.xml (one level deep)

    Returns a flat list of discovered absolute URLs.
    """
    found:           List[str] = []
    sitemap_queue:   List[str] = []
    processed_sms:   Set[str]  = set()
    apex = _apex_domain(urllib.parse.urlparse(base_url).netloc)

    # --- robots.txt ---
    robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
    body, _, _ = _fetch(robots_url, timeout=timeout, retries=1, user_agent=user_agent)
    if body:
        for raw_line in body.splitlines():
            line = raw_line.strip()
            lower = line.lower()
            if lower.startswith(("allow:", "disallow:")):
                path = line.split(":", 1)[1].strip()
                if path and path not in ("/", "*"):
                    resolved = urllib.parse.urljoin(base_url, path.split("*")[0])
                    if _is_same_domain(resolved, apex):
                        found.append(resolved)
            elif lower.startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemap_queue.append(sm)

    # Default sitemap locations
    for default_sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        sitemap_queue.append(urllib.parse.urljoin(base_url, default_sm))

    # --- sitemaps ---
    for sm_url in sitemap_queue:
        if sm_url in processed_sms:
            continue
        processed_sms.add(sm_url)

        sm_body, _, _ = _fetch(sm_url, timeout=timeout, retries=1, user_agent=user_agent)
        if not sm_body:
            continue

        try:
            root = ElementTree.fromstring(sm_body)
        except ElementTree.ParseError:
            continue

        # Handle both namespaced and bare XML
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        for loc in (*root.findall(".//sm:url/sm:loc", ns), *root.findall(".//url/loc")):
            if loc.text:
                found.append(loc.text.strip())

        # Sitemap index — follow sub-sitemaps (one level only)
        for loc in (*root.findall(".//sm:sitemap/sm:loc", ns), *root.findall(".//sitemap/loc")):
            if loc.text and loc.text.strip() not in processed_sms:
                # Only add if we haven't exceeded a reasonable limit
                if len(processed_sms) < 20:
                    sitemap_queue.append(loc.text.strip())

    return found


# ---------------------------------------------------------------------------
# JavaScript endpoint extraction
# ---------------------------------------------------------------------------

def _extract_js_endpoints(
    js_url:     str,
    base_url:   str,
    user_agent: str,
    timeout:    int,
) -> List[str]:
    """
    Fetch *js_url* and extract candidate endpoint paths via regex.

    Applies multiple patterns targeting:
    - fetch() / axios / XMLHttpRequest calls
    - URL/endpoint variable assignments
    - Express-style route definitions
    - Quoted relative paths matching common API conventions

    Returns resolved absolute URLs (same-apex-domain only).
    """
    body, _, _ = _fetch(js_url, timeout=timeout, retries=1, user_agent=user_agent)
    if not body:
        return []

    apex  = _apex_domain(urllib.parse.urlparse(base_url).netloc)
    found: Set[str] = set()

    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(body):
            candidate = match.group(1).strip()
            if not candidate or len(candidate) > 500:
                continue
            # Skip anything with whitespace or template literals
            if any(c in candidate for c in (" ", "\n", "\t", "`", "${", "\\n")):
                continue
            # Skip obviously non-URL strings
            if candidate.startswith(("//", "/*", "#")):
                continue

            resolved = _resolve_url(candidate, base_url)
            if resolved and _is_same_domain(resolved, apex):
                found.add(resolved)

    return list(found)


# ---------------------------------------------------------------------------
# Python stdlib BFS crawler (Katana fallback)
# ---------------------------------------------------------------------------

def _python_bfs_crawler(
    start_url:    str,
    extra_seeds:  List[str],
    apex:         str,
    max_depth:    int,
    concurrency:  int,
    timeout:      int,
    user_agent:   str,
    max_urls:     int,
    rate_limit:   float,
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    BFS web crawler implemented with Python stdlib only.

    Deduplication
    -------------
    - ``seen`` set holds normalised URLs; checked before enqueue
    - Depth tracked per-URL via queue tuple (url, depth)
    - Domain scope enforced by ``_is_same_domain``
    - Binary extensions filtered by ``_has_binary_extension``

    Rate Limiting
    -------------
    Each worker sleeps ``concurrency / rate_limit`` seconds between requests,
    which distributes the load so that ``concurrency`` threads together
    produce approximately ``rate_limit`` requests per second.

    Returns
    -------
    (all_urls, param_urls, js_files, form_endpoints)
    """
    seen:       Set[str]  = {_normalize_url(start_url)}
    all_urls:   List[str] = [start_url]
    param_urls: List[str] = []
    js_files:   List[str] = []
    forms:      List[str] = []

    # Seed the queue with start URL and any extra seeds (robots/sitemap)
    queue: deque = deque([(start_url, 0)])
    for seed in extra_seeds:
        norm = _normalize_url(seed)
        if norm not in seen and _is_same_domain(seed, apex):
            seen.add(norm)
            all_urls.append(seed)
            queue.append((seed, 0))

    # Rate-limit delay per worker thread
    per_worker_delay = max(concurrency / max(rate_limit, 1), 0.01)

    def _process(url: str, depth: int) -> Tuple[str, List[str], List[str], List[str]]:
        """
        Fetch one URL, extract links, JS refs, and form actions.
        Returns (effective_url, new_links, js_refs, forms).
        """
        time.sleep(per_worker_delay)
        body, ct, final_url = _fetch(url, timeout=timeout, retries=1, user_agent=user_agent)
        if not body:
            return url, [], [], []

        effective_url  = final_url or url
        content_type   = (ct or "").lower()
        new_links:     List[str] = []
        js_refs:       List[str] = []
        new_forms:     List[str] = []

        if "javascript" in content_type or url.lower().endswith(".js"):
            # For JS files: extract hidden endpoints via regex
            js_endpoints = _extract_js_endpoints(url, start_url, user_agent, timeout)
            return effective_url, js_endpoints, [], []

        if "html" in content_type or not ct:
            extractor = _LinkExtractor(effective_url)
            try:
                extractor.feed(body)
            except Exception:
                pass
            new_links  = extractor.links
            js_refs    = extractor.js_files
            new_forms  = extractor.forms

        return effective_url, new_links, js_refs, new_forms

    # BFS loop — drain one depth level at a time using a thread pool
    while queue and len(all_urls) < max_urls:
        # Collect all items at the current BFS depth into a batch
        batch: List[Tuple[str, int]] = []
        current_depth = queue[0][1]
        while queue and queue[0][1] == current_depth:
            batch.append(queue.popleft())

        if not batch:
            break

        with ThreadPoolExecutor(max_workers=min(concurrency, len(batch))) as pool:
            futures = {
                pool.submit(_process, url, depth): (url, depth)
                for url, depth in batch
            }
            for future in as_completed(futures):
                orig_url, orig_depth = futures[future]
                try:
                    eff_url, new_links, new_js, new_forms = future.result()
                except Exception as exc:
                    log.debug("BFS worker error on %s: %s", orig_url, exc)
                    continue

                # Enqueue discovered links within scope
                for href in new_links:
                    resolved = _resolve_url(href, eff_url)
                    if not resolved:
                        continue
                    if not _is_same_domain(resolved, apex):
                        continue
                    if _has_binary_extension(resolved):
                        continue
                    norm = _normalize_url(resolved)
                    if norm in seen:
                        continue
                    seen.add(norm)
                    all_urls.append(resolved)
                    if urllib.parse.urlparse(resolved).query:
                        param_urls.append(resolved)
                    if orig_depth < max_depth:
                        queue.append((resolved, orig_depth + 1))

                # Enqueue JS files (allow one extra depth beyond max_depth
                # so we still mine endpoints even at the edge)
                for js_href in new_js:
                    resolved = _resolve_url(js_href, eff_url)
                    if not resolved:
                        continue
                    norm = _normalize_url(resolved)
                    if norm in seen:
                        continue
                    seen.add(norm)
                    js_files.append(resolved)
                    all_urls.append(resolved)
                    if orig_depth <= max_depth:
                        queue.append((resolved, orig_depth + 1))

                # Collect form actions
                for action in new_forms:
                    resolved = _resolve_url(action, eff_url)
                    if not resolved:
                        continue
                    norm = _normalize_url(resolved)
                    if norm in seen:
                        continue
                    seen.add(norm)
                    forms.append(resolved)
                    all_urls.append(resolved)

    return all_urls, param_urls, js_files, forms


# ---------------------------------------------------------------------------
# Katana integration
# ---------------------------------------------------------------------------

def _run_katana(
    host:   str,
    tmpdir: str,
) -> Tuple[List[str], List[str], List[str], List[str]]:
    """
    Run Katana against *host* and parse the structured JSONL output.

    Key Katana flags used
    ---------------------
    -jc                  passive JS crawling (extracts endpoints from .js files)
    -kf all              auto-discover robots.txt and sitemap.xml paths
    -form-extraction     extract HTML form action endpoints
    -jsonl               JSONL output for reliable structured parsing
    -ef <ext,...>        skip binary / media file extensions

    Returns
    -------
    (all_urls, param_urls, js_files, form_endpoints)
    """
    crawl_cfg  = cfg.CRAWLER
    katana_bin = cfg.TOOL_PATHS.get("katana", "katana")
    out_file   = os.path.join(tmpdir, "katana_out.jsonl")
    timeout    = crawl_cfg.get("crawl_timeout", 300)

    exclude_ext = ",".join(crawl_cfg.get("exclude_extensions", sorted(_BINARY_EXTENSIONS)))

    cmd: List[str] = [
        katana_bin,
        "-u",        host,
        "-d",        str(crawl_cfg.get("depth",       3)),
        "-c",        str(crawl_cfg.get("concurrency", 10)),
        "-rl",       str(crawl_cfg.get("rate_limit",  150)),
        "-timeout",  str(crawl_cfg.get("timeout",     15)),
        "-o",        out_file,
        "-silent",
        "-no-color",
        "-ef",       exclude_ext,
        "-jsonl",
        "-kf",       "all",              # robots.txt + sitemap.xml auto-discovery
    ]

    if crawl_cfg.get("js_crawl", True):
        cmd.append("-jc")                # passive JS endpoint extraction

    if crawl_cfg.get("form_extraction", True):
        cmd.append("-form-extraction")

    if crawl_cfg.get("headless", False):
        # Headless mode renders JavaScript (requires Chromium)
        cmd.extend(["-headless", "-system-chrome"])

    ua = crawl_cfg.get("user_agent", "")
    if ua:
        cmd.extend(["-H", f"User-Agent: {ua}"])

    log.debug(
        "Katana: host=%s  depth=%d  concurrency=%d  rate=%d  timeout=%ds",
        host,
        crawl_cfg.get("depth",       3),
        crawl_cfg.get("concurrency", 10),
        crawl_cfg.get("rate_limit",  150),
        timeout,
    )

    result = run_command(cmd, timeout=timeout + 60)  # +60s grace period

    # ---- Parse output ---- #
    raw_lines: List[str] = []
    if os.path.isfile(out_file):
        with open(out_file, "r", errors="replace") as fh:
            raw_lines.extend(fh.read().splitlines())
    # Katana may also write to stdout (version-dependent)
    if result.stdout:
        raw_lines.extend(result.stdout.splitlines())

    all_urls:   List[str] = []
    param_urls: List[str] = []
    js_files:   List[str] = []
    forms:      List[str] = []
    seen:       Set[str]  = set()

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue

        url        = ""
        source_tag = ""

        if line.startswith("{"):
            # Katana JSONL schema (v1.x):
            # {
            #   "timestamp": "...",
            #   "request": {
            #     "method": "GET",
            #     "endpoint": "https://example.com/api/users",
            #     "tag": "hyperlink",       ← "script", "form", etc.
            #     "attribute": "href",
            #     "source": "https://example.com/"
            #   },
            #   "response": { "status_code": 200, ... }
            # }
            try:
                record = json.loads(line)
                req        = record.get("request", {})
                url        = (req.get("endpoint")
                              or record.get("endpoint")
                              or record.get("url", ""))
                source_tag = req.get("tag", "")
            except (json.JSONDecodeError, AttributeError):
                pass
        elif line.startswith("http"):
            url = line  # plain-URL output (older Katana versions)

        if not url:
            continue

        norm = _normalize_url(url)
        if norm in seen:
            continue
        seen.add(norm)
        all_urls.append(url)

        if urllib.parse.urlparse(url).query:
            param_urls.append(url)

        if url.lower().endswith(".js") or source_tag == "script":
            js_files.append(url)

        if source_tag in ("form", "form-action"):
            forms.append(url)

    if not result.success and not result.timed_out and not all_urls:
        log.warning(
            "Katana returned no results for %s. stderr: %s",
            host, result.stderr[:300],
        )

    log.info("Katana: %d URLs discovered on %s", len(all_urls), host)
    return all_urls, param_urls, js_files, forms


# ---------------------------------------------------------------------------
# Per-host dispatcher
# ---------------------------------------------------------------------------

def _crawl_host(host: str, use_katana: bool) -> Dict[str, List[str]]:
    """
    Orchestrate crawling for a single live host.

    Returns a dict with keys:
      all_urls       — every discovered URL
      param_urls     — URLs that carry query parameters
      js_files       — JavaScript file URLs
      form_endpoints — form action endpoints
      endpoints      — deduplicated base paths (no query string) for Nuclei
    """
    crawl_cfg = cfg.CRAWLER

    # Normalise host: ensure scheme present
    if not host.startswith(("http://", "https://")):
        host = "https://" + host

    apex       = _apex_domain(urllib.parse.urlparse(host).netloc)
    user_agent = crawl_cfg.get(
        "user_agent",
        "Mozilla/5.0 (compatible; ReconForges/1.0)",
    )
    timeout = crawl_cfg.get("timeout", 15)

    log.info("Crawling: %s", host)
    t_start = time.monotonic()

    all_urls:   List[str] = []
    param_urls: List[str] = []
    js_files:   List[str] = []
    forms:      List[str] = []

    if use_katana:
        with tempfile.TemporaryDirectory(prefix="reconforges_katana_") as tmpdir:
            all_urls, param_urls, js_files, forms = _run_katana(host, tmpdir)

        # Safety net: if Katana didn't pick up robots/sitemap, fetch them now
        if not any(("/robots.txt" in u or "sitemap" in u.lower()) for u in all_urls):
            extra = _crawl_robots_sitemap(host, user_agent=user_agent, timeout=timeout)
            seen_set = {_normalize_url(u) for u in all_urls}
            for u in extra:
                norm = _normalize_url(u)
                if norm not in seen_set and _is_same_domain(u, apex):
                    seen_set.add(norm)
                    all_urls.append(u)
    else:
        log.debug("Katana unavailable — using Python BFS crawler for %s", host)

        extra_seeds = _crawl_robots_sitemap(host, user_agent=user_agent, timeout=timeout)

        all_urls, param_urls, js_files, forms = _python_bfs_crawler(
            start_url   = host,
            extra_seeds = extra_seeds,
            apex        = apex,
            max_depth   = crawl_cfg.get("depth",            3),
            concurrency = crawl_cfg.get("concurrency",      10),
            timeout     = timeout,
            user_agent  = user_agent,
            max_urls    = crawl_cfg.get("max_urls_per_host", 5000),
            rate_limit  = crawl_cfg.get("rate_limit",       150),
        )
        log.info("BFS: %d URLs discovered on %s", len(all_urls), host)

    # Derive unique base endpoints (scheme+host+path, no query/fragment)
    # These are what get fed to Nuclei for vulnerability scanning
    endpoint_set: Set[str] = set()
    for url in all_urls:
        try:
            p    = urllib.parse.urlparse(url)
            base = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
            endpoint_set.add(base)
        except Exception:
            pass
    # Include form action endpoints as dedicated targets
    for fa in forms:
        p    = urllib.parse.urlparse(fa)
        base = urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
        endpoint_set.add(base)

    elapsed = time.monotonic() - t_start
    log.info(
        "Crawl done  %-40s  URLs=%-5d  JS=%-4d  Params=%-4d  Forms=%-4d  [%.1fs]",
        host, len(all_urls), len(js_files), len(param_urls), len(forms), elapsed,
    )

    return {
        "all_urls":       all_urls,
        "param_urls":     param_urls,
        "js_files":       js_files,
        "form_endpoints": forms,
        "endpoints":      sorted(endpoint_set),
    }


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(live_hosts: List[str]) -> List[str]:
    """
    Crawl every live host and aggregate all discovered URLs and endpoints.

    Called by ReconPipeline after the host_discovery stage.

    Parameters
    ----------
    live_hosts : list[str]
        Live host URLs/names produced by host_discovery.

    Returns
    -------
    list[str]
        All discovered URLs (passed downstream to vuln_scan as Nuclei targets).
        The full structured output is also written to four output files:
          • output/crawler_urls.txt        — every discovered URL
          • output/crawler_parameters.txt  — URLs that carry query parameters
          • output/crawler_js_files.txt    — JavaScript file URLs
          • output/crawler_endpoints.txt   — deduplicated base paths (for Nuclei)
    """
    if not live_hosts:
        log.warning("web_crawler: no live hosts received — skipping crawl.")
        return []

    crawl_cfg  = cfg.CRAWLER
    use_katana = tool_available(cfg.TOOL_PATHS.get("katana", "katana"))

    if use_katana:
        log.info("Katana detected — using Go-based crawler for maximum performance.")
    else:
        log.warning(
            "Katana not found. Falling back to Python BFS crawler.\n"
            "  Install Katana for JS-aware, high-performance crawling:\n"
            "  go install github.com/projectdiscovery/katana/cmd/katana@latest"
        )

    workers = crawl_cfg.get("workers", 3)
    log.info("Crawling %d live host(s) with %d parallel worker(s).", len(live_hosts), workers)

    # Aggregated results across all hosts
    agg_urls:      List[str] = []
    agg_params:    List[str] = []
    agg_js:        List[str] = []
    agg_endpoints: List[str] = []

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="crawler") as pool:
        futures = {
            pool.submit(_crawl_host, host, use_katana): host
            for host in live_hosts
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                result = future.result()
                agg_urls.extend(result["all_urls"])
                agg_params.extend(result["param_urls"])
                agg_js.extend(result["js_files"])
                agg_endpoints.extend(result["endpoints"])
                agg_endpoints.extend(result["form_endpoints"])
            except Exception as exc:
                log.exception("Crawler worker raised for %s: %s", host, exc)

    # --- Global deduplication (order-preserving) ---
    def _dedup_urls(lst: List[str]) -> List[str]:
        seen_set: Set[str] = set()
        out: List[str] = []
        for item in lst:
            key = _normalize_url(item)
            if key not in seen_set:
                seen_set.add(key)
                out.append(item)
        return out

    agg_urls      = _dedup_urls(agg_urls)
    agg_params    = _dedup_urls(agg_params)
    agg_js        = _dedup_urls(agg_js)
    agg_endpoints = _dedup_urls(agg_endpoints)

    # --- Write structured output files ---
    ensure_dir(cfg.OUTPUT_DIR)

    url_count   = write_lines(cfg.OUTPUT_FILES["crawler_urls"],        agg_urls,      deduplicate=True)
    param_count = write_lines(cfg.OUTPUT_FILES["crawler_parameters"],  agg_params,    deduplicate=True)
    js_count    = write_lines(cfg.OUTPUT_FILES["crawler_js_files"],    agg_js,        deduplicate=True)
    ep_count    = write_lines(cfg.OUTPUT_FILES["crawler_endpoints"],   agg_endpoints, deduplicate=True)

    log.info(
        "Web crawl complete — "
        "Total URLs: %d | Parameters: %d | JS files: %d | Endpoints: %d",
        url_count, param_count, js_count, ep_count,
    )

    # Return all discovered URLs — consumed by vuln_scan as Nuclei targets
    return agg_urls
