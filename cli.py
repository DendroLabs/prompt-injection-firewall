#!/usr/bin/env python3
"""PIF CLI — Setup wizard, status, log, and audit commands."""

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

PIF_DIR = Path(os.environ.get("PIF_DIR", Path.home() / ".pif"))
QUARANTINE_DIR = PIF_DIR / "quarantine"
CONFIG_PATH = PIF_DIR / "config.json"
SERVER_PATH = Path(__file__).resolve().parent / "server.py"

DEFAULT_CONFIG = {
    "firecrawl_url": "http://localhost:3002",
    "strict_mode": False,
    "log_raw": True,
    "quarantine_dir": str(QUARANTINE_DIR),
    "trusted_domains": [],
}


def _load_config():
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


def _save_config(config):
    PIF_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


def _check_firecrawl(url):
    try:
        req = urllib.request.Request(f"{url}/", method="GET")
        with urllib.request.urlopen(req, timeout=3):
            return True
    except Exception:
        return False


def _input_yn(prompt, default=True):
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def cmd_setup():
    """Interactive first-run setup wizard."""
    print("=" * 50)
    print("  PIF - Prompt Injection Firewall Setup")
    print("=" * 50)
    print()

    config = DEFAULT_CONFIG.copy()

    # --- Backend detection ---
    print("Checking for Firecrawl...")
    fc_url = "http://localhost:3002"
    if _check_firecrawl(fc_url):
        print(f"  Firecrawl detected at {fc_url}")
        if _input_yn("  Use Firecrawl as scraping backend?"):
            config["firecrawl_url"] = fc_url
        else:
            config["firecrawl_url"] = ""
    else:
        print("  Firecrawl not found at localhost:3002")
        custom = input("  Enter Firecrawl URL (or press Enter to skip): ").strip()
        if custom:
            if _check_firecrawl(custom):
                print(f"  Firecrawl confirmed at {custom}")
                config["firecrawl_url"] = custom
            else:
                print(f"  Could not reach {custom} — skipping Firecrawl")
                config["firecrawl_url"] = ""
        else:
            config["firecrawl_url"] = ""
            print("  Firecrawl skipped — PIF will use basic HTTP (urllib)")

    print()

    # --- Preferences ---
    config["strict_mode"] = _input_yn("Enable strict mode? (catches more, higher false positive rate)", default=False)
    config["log_raw"] = _input_yn("Log raw (unsanitized) content for audit?")

    domains = input("Trusted domains (comma-separated, or Enter to skip): ").strip()
    if domains:
        config["trusted_domains"] = [d.strip() for d in domains.split(",") if d.strip()]

    print()

    # --- Client integration ---
    print("MCP Client Integration")
    print("  1. Claude Code")
    print("  2. Other (print config snippet)")
    print("  3. Skip")
    choice = input("  Choose [1/2/3]: ").strip()

    venv_python = Path(__file__).resolve().parent / ".venv" / "bin" / "python3"
    python_cmd = str(venv_python) if venv_python.exists() else "python3"

    mcp_snippet = {
        "pif": {
            "type": "stdio",
            "command": python_cmd,
            "args": [str(SERVER_PATH)],
        }
    }

    if choice == "1":
        _setup_claude_code(mcp_snippet, config)
    elif choice == "2":
        print()
        print("Add this to your MCP client config:")
        print(json.dumps({"mcpServers": mcp_snippet}, indent=2))
    else:
        print("  Skipped client integration")

    print()

    # --- Save config ---
    _save_config(config)
    print(f"Config saved to {CONFIG_PATH}")

    # --- Test ---
    print()
    if _input_yn("Run a test fetch to verify PIF works?"):
        _run_test()

    print()
    print("Setup complete! PIF is ready.")
    print()
    print("Quick reference:")
    print("  pif status    — check PIF health")
    print("  pif log       — view recent activity")
    print("  pif audit <h> — inspect a specific request")


def _setup_claude_code(mcp_snippet, config):
    """Auto-configure Claude Code: MCP server + PreToolUse hook."""
    print()

    # MCP config
    claude_dir = Path.home() / ".claude"
    mcp_config_path = claude_dir / "mcp.json"

    if mcp_config_path.exists():
        with open(mcp_config_path) as f:
            mcp_config = json.load(f)
    else:
        mcp_config = {"mcpServers": {}}

    if "mcpServers" not in mcp_config:
        mcp_config["mcpServers"] = {}

    mcp_config["mcpServers"].update(mcp_snippet)

    if _input_yn("  Add PIF MCP server to Claude Code?"):
        with open(mcp_config_path, "w") as f:
            json.dump(mcp_config, f, indent=2)
        print(f"  Updated {mcp_config_path}")
    else:
        print("  Skipped. Add manually:")
        print(f"  {json.dumps(mcp_snippet, indent=2)}")

    # Hook config
    if _input_yn("  Add PreToolUse hook to block direct web tools?"):
        settings_path = claude_dir / "settings.json"
        if settings_path.exists():
            with open(settings_path) as f:
                settings = json.load(f)
        else:
            settings = {}

        if "hooks" not in settings:
            settings["hooks"] = {}

        hook_script = str(Path(__file__).resolve().parent / "hook.py")
        venv_python = Path(__file__).resolve().parent / ".venv" / "bin" / "python3"
        python_cmd = str(venv_python) if venv_python.exists() else "python3"

        hook_entry = {
            "matcher": "WebFetch|WebSearch|mcp__firecrawl__.*",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{python_cmd} {hook_script}",
                    "timeout": 10,
                }
            ],
        }

        if "PreToolUse" not in settings["hooks"]:
            settings["hooks"]["PreToolUse"] = []

        # Check if hook already exists
        existing = [
            h for h in settings["hooks"]["PreToolUse"]
            if "pif" in str(h.get("hooks", [{}])[0].get("command", "")).lower()
            or "hook.py" in str(h.get("hooks", [{}])[0].get("command", ""))
        ]
        if existing:
            print("  PIF hook already configured")
        else:
            settings["hooks"]["PreToolUse"].append(hook_entry)
            with open(settings_path, "w") as f:
                json.dump(settings, f, indent=2)
            print(f"  Updated {settings_path}")


def _run_test():
    """Run a quick test fetch through PIF."""
    print("  Fetching https://example.com through PIF...")
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from server import pif_fetch
        result = pif_fetch("https://example.com")
        if result.startswith("[PIF: clean]"):
            print("  Test PASSED — content fetched and scanned cleanly")
        elif result.startswith("[PIF:"):
            print(f"  Test PASSED — content fetched, findings detected: {result[:80]}")
        else:
            print(f"  Test result: {result[:100]}")
    except Exception as e:
        print(f"  Test FAILED: {e}")


def cmd_status():
    """Show PIF status."""
    config = _load_config()

    fc_url = config.get("firecrawl_url", "")
    fc_ok = _check_firecrawl(fc_url) if fc_url else False

    backend = "urllib"
    if fc_ok:
        backend = f"Firecrawl ({fc_url}) + urllib"

    print("PIF Prompt Injection Firewall")
    print(f"  Config:     {CONFIG_PATH}")
    print(f"  Backend:    {backend}")
    print(f"  Strict:     {'on' if config.get('strict_mode') else 'off'}")
    print(f"  Quarantine: {QUARANTINE_DIR}")

    log_path = QUARANTINE_DIR / "activity.jsonl"
    if log_path.exists():
        entries = log_path.read_text().strip().split("\n")
        entries = [e for e in entries if e.strip()]
        total = len(entries)
        flagged = sum(1 for e in entries if '"CLEAN"' not in e)
        print(f"  Requests:   {total} total, {flagged} flagged")

        # Disk usage
        try:
            size = sum(f.stat().st_size for f in QUARANTINE_DIR.rglob("*") if f.is_file())
            if size > 1024 * 1024:
                print(f"  Disk:       {size / 1024 / 1024:.1f} MB")
            else:
                print(f"  Disk:       {size / 1024:.1f} KB")
        except Exception:
            pass
    else:
        print("  Requests:   0 (no activity yet)")


def cmd_log(limit=20, watch=False):
    """Show recent activity log."""
    log_path = QUARANTINE_DIR / "activity.jsonl"

    if not log_path.exists():
        print("No activity yet.")
        return

    if watch:
        _watch_log(log_path)
        return

    entries = log_path.read_text().strip().split("\n")
    entries = [e for e in entries if e.strip()]

    for line in entries[-limit:]:
        try:
            entry = json.loads(line)
            ts = entry.get("timestamp", "?")[:19]
            status = entry.get("status", "?")
            url = entry.get("url", "?")
            h = entry.get("hash", "?")

            if status == "CLEAN":
                status_display = "CLEAN    "
            else:
                crit = entry.get("critical_count", 0)
                high = entry.get("high_count", 0)
                if crit:
                    status_display = f"{crit} CRIT   "
                elif high:
                    status_display = f"{high} HIGH   "
                else:
                    status_display = f"{status:9s}"

            # Truncate URL for display
            if len(url) > 60:
                url = url[:57] + "..."

            print(f"{ts}  {status_display}  {h}  {url}")
        except json.JSONDecodeError:
            continue


def _watch_log(log_path):
    """Live tail of the activity log."""
    print("Watching PIF activity (Ctrl+C to stop)...")
    print()

    last_size = log_path.stat().st_size if log_path.exists() else 0
    try:
        while True:
            if log_path.exists():
                current_size = log_path.stat().st_size
                if current_size > last_size:
                    with open(log_path) as f:
                        f.seek(last_size)
                        new_data = f.read()
                    for line in new_data.strip().split("\n"):
                        if line.strip():
                            try:
                                entry = json.loads(line)
                                ts = entry.get("timestamp", "?")[:19]
                                status = entry.get("status", "CLEAN")
                                url = entry.get("url", "?")
                                h = entry.get("hash", "?")
                                print(f"{ts}  {status:9s}  {h}  {url}")
                            except json.JSONDecodeError:
                                continue
                    last_size = current_size
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_audit(file_hash):
    """Deep dive on a specific quarantined request."""
    report_path = QUARANTINE_DIR / f"report-{file_hash}.json"
    raw_path = QUARANTINE_DIR / f"raw-{file_hash}.txt"
    clean_path = QUARANTINE_DIR / f"clean-{file_hash}.txt"

    if not report_path.exists():
        print(f"No report found for hash: {file_hash}")
        print(f"Use 'pif log' to find valid hashes.")
        return

    with open(report_path) as f:
        report = json.load(f)

    print(f"PIF Audit: {file_hash}")
    print(f"  URL:        {report.get('url', '?')}")
    print(f"  Timestamp:  {report.get('timestamp', '?')}")
    print(f"  Raw size:   {report.get('raw_size_bytes', 0):,} bytes")
    print(f"  Clean size: {report.get('clean_size_bytes', 0):,} bytes")
    print(f"  Findings:   {report.get('total_findings', 0)}")
    if report.get("critical_count"):
        print(f"    CRITICAL: {report['critical_count']}")
    if report.get("high_count"):
        print(f"    HIGH:     {report['high_count']}")
    if report.get("medium_count"):
        print(f"    MEDIUM:   {report['medium_count']}")
    if report.get("low_count"):
        print(f"    LOW:      {report['low_count']}")

    findings = report.get("findings", [])
    if findings:
        print()
        print("Findings:")
        for i, f in enumerate(findings, 1):
            print(f"  {i}. [{f['severity']}] {f['category']}")
            print(f"     {f['reason']}")
            if f.get("line"):
                print(f"     Line: {f['line']}")
            if f.get("snippet"):
                print(f"     Context: {f['snippet'][:100]}")
            print()

    print("Files:")
    if raw_path.exists():
        print(f"  Raw:   {raw_path}")
    else:
        print(f"  Raw:   (not logged)")
    print(f"  Clean: {clean_path}")
    print(f"  Report: {report_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: pif <command> [args]")
        print()
        print("Commands:")
        print("  setup           Interactive setup wizard")
        print("  status          Check PIF health")
        print("  log [--limit N] View recent activity")
        print("  log --watch     Live tail of activity")
        print("  audit <hash>    Inspect a specific request")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "setup":
        cmd_setup()
    elif cmd == "status":
        cmd_status()
    elif cmd == "log":
        watch = "--watch" in sys.argv
        limit = 20
        for i, arg in enumerate(sys.argv):
            if arg == "--limit" and i + 1 < len(sys.argv):
                try:
                    limit = int(sys.argv[i + 1])
                except ValueError:
                    pass
        cmd_log(limit=limit, watch=watch)
    elif cmd == "audit":
        if len(sys.argv) < 3:
            print("Usage: pif audit <hash>")
            print("Use 'pif log' to find hashes.")
            sys.exit(1)
        cmd_audit(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        print("Use 'pif --help' or run without args for usage.")
        sys.exit(1)


if __name__ == "__main__":
    main()
