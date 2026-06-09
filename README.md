# PIF — Prompt Injection Firewall

MCP server that provides sanitized web access for LLMs. All web content passes through a non-LLM pattern-matching sanitizer before reaching the model's context. Detects and strips prompt injection attacks, suspicious Unicode, homoglyphs, encoded payloads, and data exfiltration attempts.

## Quick Start

```bash
cd ~/Documents/misc/web-quarantine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 cli.py setup
```

The setup wizard detects Firecrawl, configures your MCP client, and runs a test.

## Architecture

```
LLM client (Claude Code, opencode, etc.)
    |
    |  MCP protocol (stdio)
    v
PIF MCP Server (server.py)
    |
    |--- sanitizer.py (always runs on every response)
    |
    |--- Backend:
    |      Firecrawl REST API (if available) — JS rendering, search
    |      urllib (always available) — basic HTTP
    |
    v
Sanitized content returned to LLM
```

## MCP Tools

| Tool | Description | Backend |
|------|-------------|---------|
| pif_fetch | HTTP GET, sanitized text | urllib (always) |
| pif_scrape | JS-rendered scrape | Firecrawl or urllib fallback |
| pif_search | Web search | DuckDuckGo or Firecrawl |
| pif_status | Health check | local |

## CLI

```bash
pif setup           # Interactive setup wizard
pif status          # Health check
pif log             # Recent activity
pif log --watch     # Live tail
pif audit <hash>    # Deep dive on a request
```

## Sanitizer Categories

| Severity | Category | Examples |
|----------|----------|---------|
| CRITICAL | instruction_override | "ignore previous instructions" |
| CRITICAL | role_hijacking | "you are now a", "DAN mode" |
| CRITICAL | delimiter_injection | [INST], <\|im_start\|>, <<SYS>> |
| CRITICAL | system_prompt_extraction | "reveal your system prompt" |
| HIGH | indirect_injection | "[Note to AI:]" |
| HIGH | data_exfiltration | markdown image exfil, sendBeacon |
| MEDIUM | unicode_attack | zero-width chars, RTL overrides |
| MEDIUM | homoglyph | Cyrillic/Greek lookalikes |
| LOW | encoded_payload | Base64-encoded injection |

## Files

```
sanitizer.py          Core non-LLM scanner (stdlib only)
server.py             MCP server (requires mcp + ddgs)
cli.py                CLI: setup, status, log, audit
hook.py               Claude Code PreToolUse hook (blocks web tools + curl/wget in Bash)
config.json           Default config template
tests/
  test_sanitizer.py   82 sanitizer tests
  test_hook.py        18 hook tests
  injection-test-page.html   Test page with embedded attacks
```

## Config

Runtime config at `~/.pif/config.json`:

```json
{
  "firecrawl_url": "http://localhost:3002",
  "strict_mode": false,
  "log_raw": true,
  "trusted_domains": ["localhost", "127.0.0.1"]
}
```

Quarantine logs at `~/.pif/quarantine/` (raw, clean, and JSON report per request).

## Dependencies

- Python 3.10+ (3.13 recommended; 3.14 may have MCP compatibility issues)
- mcp SDK (`pip install mcp`)
- ddgs (`pip install ddgs`) — DuckDuckGo search fallback
- Firecrawl (optional, for JS rendering and better search)

## Testing

```bash
python3 -m pytest tests/ -v
```
