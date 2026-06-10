#!/usr/bin/env python3
"""PIF PreToolUse Hook — blocks direct web tool access.

Reads hook input from stdin, checks if the tool is a direct web access tool
(WebFetch, WebSearch, Firecrawl MCP), and denies it with a message directing
the LLM to use PIF tools instead.
"""

import json
import sys
import urllib.parse
from pathlib import Path

BLOCKED_TOOLS = {"WebFetch", "WebSearch"}
BLOCKED_PREFIXES = ("mcp__firecrawl__",)

import re

BASH_WEB_COMMANDS = re.compile(
    r'\b(curl|wget|https?(?!://)|python3?\s+-c\s+.*(?:urllib|requests|httpx|aiohttp))\b'
)
BASH_URL_PATTERN = re.compile(r'https?://')

LOCALHOST_PATTERN = re.compile(
    r'^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(/|$)'
)

CONFIG_PATH = Path.home() / ".pif" / "config.json"


def _load_trusted_domains():
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                return json.load(f).get("trusted_domains", [])
    except Exception:
        pass
    return []


def _is_trusted(url, trusted_domains):
    if not url or url == "(no url)":
        return False
    try:
        host = urllib.parse.urlparse(url).hostname or ""
        return any(
            host == d.strip() or host.endswith("." + d.strip())
            for d in trusted_domains
            if d.strip()
        )
    except Exception:
        return False


def _check_bash_web_access(command):
    """Check if a Bash command is fetching web content."""
    if not command:
        return False
    if not (BASH_WEB_COMMANDS.search(command) and BASH_URL_PATTERN.search(command)):
        return False
    urls = _extract_urls_from_command(command)
    if urls and all(LOCALHOST_PATTERN.match(u) for u in urls):
        return False
    return True


def _extract_urls_from_command(command):
    """Extract URLs from a shell command for trusted domain checking."""
    return re.findall(r'https?://[^\s"\'<>]+', command or "")


def main():
    data = json.load(sys.stdin)
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    is_web_tool = (
        tool_name in BLOCKED_TOOLS
        or any(tool_name.startswith(p) for p in BLOCKED_PREFIXES)
    )

    is_bash_web = (
        tool_name == "Bash"
        and _check_bash_web_access(tool_input.get("command", ""))
    )

    if not is_web_tool and not is_bash_web:
        sys.exit(0)

    trusted_domains = _load_trusted_domains()

    if is_web_tool:
        url = tool_input.get("url", tool_input.get("query", "(no url)"))
        if _is_trusted(url, trusted_domains):
            sys.exit(0)
        attempted = url
    else:
        command = tool_input.get("command", "")
        urls = _extract_urls_from_command(command)
        if urls and all(_is_trusted(u, trusted_domains) for u in urls):
            sys.exit(0)
        attempted = command[:200]

    reason = (
        f"PIF: Direct web access via {tool_name} is blocked. "
        f"Use PIF tools instead:\n"
        f"  - pif_fetch: basic HTTP GET\n"
        f"  - pif_scrape: JS-rendered scrape (needs Firecrawl)\n"
        f"  - pif_search: web search (needs Firecrawl)\n"
        f"Attempted: {attempted}"
    )

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
