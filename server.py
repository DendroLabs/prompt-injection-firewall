#!/usr/bin/env python3
"""PIF MCP Server — Prompt Injection Firewall.

MCP server that provides sanitized web access tools. All web content passes
through the PIF sanitizer before reaching the LLM. Supports urllib (always
available) and Firecrawl (optional, for JS rendering and search).
"""

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from ddgs import DDGS
from mcp.server.fastmcp import FastMCP

# Add parent dir to path for sanitizer import
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sanitizer import sanitize, generate_report

PIF_DIR = Path(os.environ.get("PIF_DIR", Path.home() / ".pif"))
QUARANTINE_DIR = PIF_DIR / "quarantine"
CONFIG_PATH = PIF_DIR / "config.json"

DEFAULT_CONFIG = {
    "firecrawl_url": "http://localhost:3002",
    "strict_mode": False,
    "log_raw": True,
}

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)
FETCH_TIMEOUT = 15
MAX_CONTENT_SIZE = 10 * 1024 * 1024  # 10 MB


def _load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        return {**DEFAULT_CONFIG, **cfg}
    return DEFAULT_CONFIG.copy()


def _ensure_dirs():
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def _file_hash(url):
    ts = str(time.time())
    return hashlib.sha256((url + ts).encode()).hexdigest()[:12]


def _log_quarantine(url, raw_text, clean_text, findings, file_hash, config):
    """Write raw, clean, and report files to quarantine directory."""
    _ensure_dirs()

    if config.get("log_raw", True):
        raw_path = QUARANTINE_DIR / f"raw-{file_hash}.txt"
        raw_path.write_text(raw_text, encoding="utf-8")

    clean_path = QUARANTINE_DIR / f"clean-{file_hash}.txt"
    clean_path.write_text(clean_text, encoding="utf-8")

    report = generate_report(url, raw_text, clean_text, findings)
    report["hash"] = file_hash
    report["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    report_path = QUARANTINE_DIR / f"report-{file_hash}.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Append to activity log
    log_path = QUARANTINE_DIR / "activity.jsonl"
    log_entry = {
        "timestamp": report["timestamp"],
        "hash": file_hash,
        "url": url,
        "findings_count": len(findings),
        "critical_count": report["critical_count"],
        "high_count": report["high_count"],
        "status": "CLEAN" if not findings else f"{len(findings)} issues",
    }
    with open(log_path, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    return report


def _pif_header(findings):
    """Generate the inline PIF status header."""
    if not findings:
        return "[PIF: clean]\n\n"
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    parts = [f"{v} {k}" for k, v in counts.items()]
    return f"[PIF: {', '.join(parts)} sanitized]\n\n"


def _fetch_urllib(url):
    """Fetch a URL using stdlib urllib."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if any(
                content_type.startswith(t)
                for t in ("image/", "audio/", "video/", "application/octet-stream")
            ):
                return None, "binary", content_type
            raw = resp.read(MAX_CONTENT_SIZE)
            charset = resp.headers.get_content_charset() or "utf-8"
            text = raw.decode(charset, errors="replace")
            return text, "text", content_type
    except urllib.error.HTTPError as e:
        return f"HTTP Error {e.code}: {e.reason}", "error", ""
    except urllib.error.URLError as e:
        return f"URL Error: {e.reason}", "error", ""
    except Exception as e:
        return f"Fetch error: {e}", "error", ""


def _check_firecrawl(config):
    """Check if Firecrawl is reachable."""
    url = config.get("firecrawl_url", "http://localhost:3002")
    try:
        req = urllib.request.Request(f"{url}/", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status < 500
    except Exception:
        return False


def _firecrawl_request(endpoint, body, config):
    """Make a request to the Firecrawl REST API."""
    base_url = config.get("firecrawl_url", "http://localhost:3002")
    url = f"{base_url}{endpoint}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"Firecrawl HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"error": f"Firecrawl error: {e}"}


# --- MCP Server ---

mcp = FastMCP(
    "pif",
    instructions=(
        "PIF (Prompt Injection Firewall) provides sanitized web access. "
        "All web content is scanned for prompt injection, suspicious Unicode, "
        "and encoded payloads before being returned. Use pif_fetch for basic "
        "HTTP requests, pif_scrape for JS-rendered pages (requires Firecrawl), "
        "and pif_search for web searches (requires Firecrawl)."
    ),
)


@mcp.tool()
def pif_fetch(url: str) -> str:
    """Fetch a URL via HTTP GET and return sanitized content.

    Always available — uses stdlib urllib. Good for static pages, APIs,
    and any URL that doesn't require JavaScript rendering.
    """
    config = _load_config()
    strict = config.get("strict_mode", False)

    text, kind, content_type = _fetch_urllib(url)

    if kind == "binary":
        return f"[PIF: binary content ({content_type}) — not scannable]"

    if kind == "error":
        return f"[PIF: fetch failed] {text}"

    fh = _file_hash(url)
    clean_text, findings = sanitize(text, strict=strict)
    _log_quarantine(url, text, clean_text, findings, fh, config)

    return _pif_header(findings) + clean_text


@mcp.tool()
def pif_scrape(url: str, wait_for: int = 0) -> str:
    """Scrape a URL with JS rendering and return sanitized markdown.

    Uses Firecrawl for JavaScript-rendered content. Falls back to basic
    HTTP fetch if Firecrawl is not available.

    Args:
        url: The URL to scrape.
        wait_for: Milliseconds to wait for JS to render (0 = default).
    """
    config = _load_config()
    strict = config.get("strict_mode", False)

    if _check_firecrawl(config):
        body = {
            "url": url,
            "formats": ["markdown"],
            "onlyMainContent": True,
        }
        if wait_for > 0:
            body["waitFor"] = wait_for

        result = _firecrawl_request("/v1/scrape", body, config)

        if "error" in result:
            return f"[PIF: Firecrawl error] {result['error']}"

        data = result.get("data", {})
        text = data.get("markdown", data.get("content", ""))
        if not text:
            return "[PIF: Firecrawl returned empty content]"
    else:
        text, kind, content_type = _fetch_urllib(url)
        if kind == "binary":
            return f"[PIF: binary content ({content_type}) — not scannable]"
        if kind == "error":
            return f"[PIF: fetch failed (Firecrawl unavailable, urllib fallback)] {text}"

    fh = _file_hash(url)
    clean_text, findings = sanitize(text, strict=strict)
    _log_quarantine(url, text, clean_text, findings, fh, config)

    return _pif_header(findings) + clean_text


def _search_ddg(query, limit):
    """Search using DuckDuckGo as fallback."""
    try:
        with DDGS() as ddgs:
            return list(ddgs.text(query, max_results=limit))
    except Exception as e:
        return {"error": str(e)}


def _search_firecrawl(query, limit, config):
    """Search using Firecrawl (returns result list with scraped content)."""
    body = {
        "query": query,
        "limit": limit,
        "scrapeOptions": {"formats": ["markdown"], "onlyMainContent": True},
    }
    result = _firecrawl_request("/v1/search", body, config)
    if "error" in result:
        return None
    data = result.get("data", [])
    return data if data else None


@mcp.tool()
def pif_search(query: str, limit: int = 5) -> str:
    """Search the web and return sanitized results.

    Uses Firecrawl search if available and configured, otherwise falls back
    to DuckDuckGo. Individual results are sanitized before returning.

    Args:
        query: The search query.
        limit: Maximum number of results (default 5).
    """
    config = _load_config()
    strict = config.get("strict_mode", False)
    firecrawl_up = _check_firecrawl(config)

    results_data = None
    source = None

    if firecrawl_up:
        results_data = _search_firecrawl(query, limit, config)
        if results_data:
            source = "firecrawl"

    if not results_data:
        ddg_results = _search_ddg(query, limit)
        if isinstance(ddg_results, dict) and "error" in ddg_results:
            return f"[PIF: search error] {ddg_results['error']}"
        if not ddg_results:
            return "[PIF: no search results found]"
        results_data = [
            {
                "title": r.get("title", f"Result"),
                "url": r.get("href", "unknown"),
                "markdown": r.get("body", ""),
            }
            for r in ddg_results
        ]
        source = "duckduckgo"

    all_findings = []
    sections = []
    fh = _file_hash(query)

    for i, item in enumerate(results_data, 1):
        title = item.get("title", item.get("metadata", {}).get("title", f"Result {i}"))
        item_url = item.get("url", "unknown")
        content = item.get("markdown", item.get("content", ""))

        if content:
            clean_content, findings = sanitize(content, strict=strict)
            all_findings.extend(findings)
        else:
            clean_content = "(no content)"
            findings = []

        sections.append(f"## Result {i}: {title}\nURL: {item_url}\n\n{clean_content}")

    combined_clean = "\n\n---\n\n".join(sections)
    combined_raw = json.dumps(results_data, ensure_ascii=False)
    _log_quarantine(f"search:{query}", combined_raw, combined_clean, all_findings, fh, config)

    header = _pif_header(all_findings)
    return f"{header}[Source: {source}]\n\n{combined_clean}"


@mcp.tool()
def pif_status() -> str:
    """Check PIF status: config, Firecrawl availability, recent activity."""
    config = _load_config()
    firecrawl_ok = _check_firecrawl(config)

    lines = [
        "PIF Prompt Injection Firewall",
        f"  Config:     {CONFIG_PATH}",
        f"  Backend:    {'Firecrawl (' + config.get('firecrawl_url', '?') + ') + ' if firecrawl_ok else ''}urllib",
        f"  Strict:     {'on' if config.get('strict_mode') else 'off'}",
        f"  Quarantine: {QUARANTINE_DIR}",
    ]

    log_path = QUARANTINE_DIR / "activity.jsonl"
    if log_path.exists():
        entries = log_path.read_text().strip().split("\n")
        total = len(entries)
        flagged = sum(1 for e in entries if '"CLEAN"' not in e)
        lines.append(f"  Requests:   {total} total, {flagged} flagged")
    else:
        lines.append("  Requests:   0 (no activity yet)")

    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run(transport="stdio")
