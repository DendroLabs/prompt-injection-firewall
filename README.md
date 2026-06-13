# PIF — Prompt Injection Firewall

MCP server that provides sanitized web access for LLMs. All web content passes through a non-LLM pattern-matching sanitizer before reaching the model's context. Detects and strips prompt injection attacks, suspicious Unicode, homoglyphs, encoded payloads, and data exfiltration attempts.

## Why Not Use an LLM to Filter?

The obvious question: why use regex heuristics instead of asking an LLM to detect prompt injection? The answer is fundamental to the threat model.

**The filter and the target are the same attack surface.** If you use an LLM to scan web content for prompt injection, the injected payload is now inside the filter LLM's context — which is exactly where the attacker wants it. A sufficiently clever injection can compromise the filter itself, causing it to report "clean" on malicious content. You've just added latency and cost without adding security.

This isn't theoretical. Research on LLM-as-judge systems shows they're vulnerable to the same adversarial techniques they're trying to detect: instruction overrides, role hijacking, and context manipulation all work on the judge LLM too. An attacker who can craft a payload that fools GPT-4 can likely craft one that fools GPT-4-as-filter, because the same linguistic patterns that constitute "understanding instructions" also constitute "being vulnerable to instruction injection."

**PIF's approach: deterministic pattern matching outside the LLM.**

The sanitizer runs zero LLM calls. It uses compiled regex patterns, Unicode analysis, and structural heuristics — none of which can be "convinced" by clever wording. A regex either matches or it doesn't. This means:

- **No prompt injection can disable the filter.** The sanitizer doesn't process natural language instructions — it matches byte patterns.
- **No latency or cost per scan.** Regex runs in microseconds, not seconds. No API calls, no token costs.
- **No model dependency.** Works offline, works with any LLM client, works in air-gapped environments.
- **Auditable.** Every pattern is a readable regex with a severity and category. You can review exactly what it catches and why.

The tradeoff is that regex heuristics won't catch novel, never-before-seen injection techniques the way a sufficiently capable LLM might. PIF accepts this tradeoff because a filter that can be defeated by the same attack it's filtering for provides false confidence — worse than no filter at all.

For defense in depth, PIF can be combined with model-level safety features (system prompts, constitutional AI, etc.) that operate at a different layer. PIF handles the content before it enters context; the model's own guardrails handle what happens after.

## Quick Start

```bash
git clone https://github.com/DendroLabs/prompt-injection-firewall.git
cd prompt-injection-firewall
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

## Claude Code Hook

`hook.py` is a PreToolUse hook that closes the paths around PIF: it denies
WebFetch, WebSearch, Firecrawl MCP tools, and Bash commands that fetch web
content (curl, wget, HTTPie, python urllib/requests/httpx/aiohttp), directing
the model to the pif_* tools instead.

Exemptions:

- **Loopback** — URLs targeting `localhost`, `127.0.0.1`, or `[::1]` always
  pass, including ports written as unexpanded shell variables
  (`http://localhost:$port/`, `http://127.0.0.1:${PORT}/`), since the hook
  sees commands before shell expansion.
- **Trusted domains** — hosts listed in `trusted_domains` in
  `~/.pif/config.json` (and their subdomains) pass. For Bash commands, every
  URL in the command must be trusted or the command is blocked.

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
  test_hook.py        26 hook tests
  injection-test-page.html   Test page with embedded attacks
```

## Recommended Claude Code Settings

To get the most out of PIF, configure Claude Code so the model uses PIF tools
by default instead of attempting blocked tools first.

### 1. Deny direct web tools

In `~/.claude/settings.json`, move `WebSearch` and `WebFetch` to the deny list
and allow PIF tools:

```json
{
  "permissions": {
    "allow": [
      "mcp__pif__*"
    ],
    "deny": [
      "WebSearch",
      "WebFetch"
    ]
  }
}
```

This prevents the model from ever attempting the blocked tools, avoiding
wasted calls that hit the hook and get denied.

### 2. Add PIF instructions to CLAUDE.md

Add this to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md`
so all sessions and subagents know to use PIF from the start:

```markdown
## Web Access — PIF Only

All web access must go through PIF (Prompt Injection Firewall) MCP tools.
WebSearch, WebFetch, and curl/wget are blocked by a PreToolUse hook —
do not attempt them.

- **pif_search** — web search (replaces WebSearch)
- **pif_scrape** — JS-rendered page scrape (replaces WebFetch for rich pages)
- **pif_fetch** — basic HTTP GET (replaces WebFetch/curl)

Subagents performing web research MUST use these PIF tools directly.
```

Without these settings, the model will try WebSearch/curl first, get blocked
by the hook, and sometimes give up instead of retrying with PIF tools.

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
