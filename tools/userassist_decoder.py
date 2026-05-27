"""
userassist_decoder.py — Tool 3: ROT13 UserAssist Registry Decoder
──────────────────────────────────────────────────────────────────
Windows records which programs a user has launched via Explorer/Start
in the registry under:

    HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist

The program paths are ROT13-encoded.  This tool decodes them and flags
anything that looks like a cheat client.

Input options:
  A) A .reg export file — created on the suspect machine with:
         reg export "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist" ua.reg
  B) Live registry (Windows only) — reads directly via the winreg module.

Usage (from menu or directly):
    python tools/userassist_decoder.py
"""

import os
import re
import struct
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from tools.shared import rot13, is_suspicious, filetime_to_dt, SEVERITY_STYLE

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# USERASSISTENTRY binary layout (Windows 7+, 72 bytes total)
#   0:  session ID  (4 bytes)
#   4:  run count   (4 bytes)
#   8:  focus count (4 bytes)
#  12:  focus time  (4 bytes, milliseconds)
#  16:  padding     (44 bytes)
#  60:  last run    (8 bytes, FILETIME)
UA_RUN_COUNT_OFF  = 4
UA_LAST_RUN_OFF   = 60
UA_STRUCT_MIN_LEN = 68  # need at least through byte 67 (8-byte FILETIME starts at 60)

# Registry path of interest
UA_REG_PATH = (
    r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
)

# ─────────────────────────────────────────────────────────────────────────────
# Binary value parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ua_value(data: bytes) -> dict:
    """
    Parse USERASSISTENTRY binary data.
    Returns {'run_count': int, 'last_run': datetime | None}.
    """
    result = {"run_count": 0, "last_run": None}

    if len(data) < UA_RUN_COUNT_OFF + 4:
        return result

    run_count = struct.unpack_from("<I", data, UA_RUN_COUNT_OFF)[0]
    # A run_count of 0 or 0xFFFFFFFF means the entry was never tracked / is a placeholder
    if run_count not in (0, 0xFFFF_FFFF):
        result["run_count"] = run_count

    if len(data) >= UA_LAST_RUN_OFF + 8:
        ft_bytes = data[UA_LAST_RUN_OFF: UA_LAST_RUN_OFF + 8]
        result["last_run"] = filetime_to_dt(ft_bytes)

    return result

# ─────────────────────────────────────────────────────────────────────────────
# .reg file parser
# ─────────────────────────────────────────────────────────────────────────────

def _hex_value_to_bytes(hex_str: str) -> bytes:
    """
    Convert a Registry hex: value string (may span multiple lines with \\)
    to raw bytes.
    """
    clean = re.sub(r"\\\s*\r?\n\s*", "", hex_str)  # join continuation lines
    clean = clean.replace(",", "").replace(" ", "")
    try:
        return bytes.fromhex(clean)
    except ValueError:
        return b""


def parse_reg_file(path: str) -> list[dict]:
    """
    Parse a .reg export file and return a list of UserAssist entries:
        {
            "encoded": str,      # original ROT13 key name
            "decoded": str,      # decoded program path
            "run_count": int,
            "last_run": datetime | None,
            "suspicious": bool,
        }
    """
    try:
        # .reg files are UTF-16LE on modern Windows; fall back to UTF-8
        try:
            text = Path(path).read_text(encoding="utf-16")
        except Exception:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        console.print(f"[red]Cannot read file:[/red] {e}")
        return []

    entries: list[dict] = []
    # Match:  "SomeName"=hex:xx,xx,xx,...
    # (value may continue across lines with \)
    pattern = re.compile(
        r'"([^"]+)"=hex(?::[0-9a-fA-F]{2}|(?:,[0-9a-fA-F]{2})+)(?:\\\r?\n[^"=\r\n]+)*',
        re.MULTILINE,
    )

    # Simpler: iterate line by line, collect (name, hex_value) pairs
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        # Match a value line: "EncodedName"=hex:...
        m = re.match(r'^"([^"]+)"=hex:(.*)', line)
        if m:
            name    = m.group(1)
            hex_str = m.group(2)
            # Collect continuation lines (end with backslash)
            while hex_str.rstrip().endswith("\\"):
                hex_str = hex_str.rstrip()[:-1]  # remove trailing backslash
                i += 1
                if i < len(lines):
                    hex_str += lines[i].strip()
            raw_data = _hex_value_to_bytes(hex_str)
            decoded  = rot13(name)
            ua       = _parse_ua_value(raw_data)
            entries.append({
                "encoded":   name,
                "decoded":   decoded,
                "run_count": ua["run_count"],
                "last_run":  ua["last_run"],
                "suspicious": is_suspicious(decoded),
            })
        i += 1

    return entries

# ─────────────────────────────────────────────────────────────────────────────
# Live registry reader  (Windows only)
# ─────────────────────────────────────────────────────────────────────────────

def read_live_registry() -> list[dict]:
    """
    Read UserAssist directly from the running Windows registry.
    Only works on Windows — returns [] on other platforms.
    """
    if sys.platform != "win32":
        console.print(
            "[yellow]Live registry reading is only supported on Windows.[/yellow]\n"
            "On Mac/Linux, export the registry key on the suspect machine and use the .reg file option."
        )
        return []

    import winreg

    entries: list[dict] = []
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UA_REG_PATH)
    except FileNotFoundError:
        console.print("[red]UserAssist registry key not found.[/red]")
        return []

    guid_index = 0
    while True:
        try:
            guid = winreg.EnumKey(ua_key, guid_index)
        except OSError:
            break
        guid_index += 1

        try:
            count_key = winreg.OpenKey(ua_key, f"{guid}\\Count")
        except FileNotFoundError:
            continue

        val_index = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(count_key, val_index)
            except OSError:
                break
            val_index += 1

            if not isinstance(data, bytes):
                continue

            decoded = rot13(name)
            ua      = _parse_ua_value(data)
            entries.append({
                "encoded":    name,
                "decoded":    decoded,
                "run_count":  ua["run_count"],
                "last_run":   ua["last_run"],
                "suspicious": is_suspicious(decoded),
            })

        count_key.Close()
    ua_key.Close()
    return entries

# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def print_entries(entries: list[dict]) -> None:
    if not entries:
        console.print("[yellow]No UserAssist entries found.[/yellow]")
        return

    suspicious = [e for e in entries if e["suspicious"]]

    # ── Summary ──────────────────────────────────────────────────────────────
    colour  = "red" if suspicious else "green"
    verdict = f"⚠  {len(suspicious)} SUSPICIOUS ENTRIES" if suspicious else "✔  All entries look clean"
    console.print(Panel(
        f"[bold]Total entries:[/bold] {len(entries)}\n"
        f"[bold]Suspicious:[/bold]    [{colour}]{len(suspicious)}[/{colour}]\n"
        f"[bold]Verdict:[/bold]       [{colour}]{verdict}[/{colour}]",
        title="[bold]UserAssist Summary[/bold]",
        border_style=colour,
    ))

    # ── Full table ────────────────────────────────────────────────────────────
    table = Table(
        title="Decoded UserAssist Entries (suspicious highlighted)",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("Decoded Path",   min_width=40)
    table.add_column("Runs", width=6,  no_wrap=True)
    table.add_column("Last Run (UTC)", min_width=22)
    table.add_column("Flag",           min_width=14)

    # Show suspicious first, then the rest
    sorted_entries = sorted(entries, key=lambda e: (not e["suspicious"], e["decoded"]))
    for e in sorted_entries:
        style   = SEVERITY_STYLE["suspicious"] if e["suspicious"] else ""
        flag    = "⚠ SUSPICIOUS" if e["suspicious"] else ""
        last_r  = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "—"
        path    = e["decoded"][:80]  # cap for display

        if style:
            table.add_row(
                f"[{style}]{path}[/{style}]",
                str(e["run_count"]),
                last_r,
                f"[{style}]{flag}[/{style}]",
            )
        else:
            table.add_row(path, str(e["run_count"]), last_r, flag)

    console.print(table)

# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

from pathlib import Path


def _auto_find_reg() -> str | None:
    """
    Return the best source for UserAssist data without asking the user.
      • Windows  → live registry (no file needed)
      • Mac/Linux → data/ua.reg  (drop the exported .reg file here)
    Returns 'live' for live registry, a file path for .reg, or None if nothing found.
    """
    if sys.platform == "win32":
        return "live"

    # Mac / Linux: check the standard drop location
    for candidate in [
        os.path.join("data", "ua.reg"),
        os.path.join("data", "userassist.reg"),
    ]:
        if os.path.isfile(candidate):
            return candidate

    return None


def main() -> None:
    console.rule("[bold blue]Tool 3 — UserAssist ROT13 Decoder[/bold blue]")

    entries: list[dict] = []

    # ── Auto-detect source ───────────────────────────────────────────────────
    source = _auto_find_reg()

    if source == "live":
        console.print("[dim]Windows detected — reading live registry…[/dim]\n")
        entries = read_live_registry()

    elif source:
        console.print(f"[dim]Auto-detected registry export:[/dim] [bold]{source}[/bold]\n")
        entries = parse_reg_file(source)

    else:
        console.print(Panel(
            "No registry export found automatically.\n\n"
            "During a screenshare via AnyDesk:\n"
            "  1. On their PC: press [bold]Win+R[/bold], type [bold]regedit[/bold]\n"
            "  2. Navigate to:\n"
            "     [dim]HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist[/dim]\n"
            "  3. Right-click [bold]UserAssist[/bold] → [bold]Export[/bold] → save as [bold]ua.reg[/bold]\n"
            "  4. Transfer [bold]ua.reg[/bold] to [bold]ss-toolkit/data/ua.reg[/bold]\n"
            "  5. Re-open this tool — it will scan automatically.",
            title="[yellow]No Registry Export Found[/yellow]",
            border_style="yellow",
        ))
        return

    print_entries(entries)

    # ── Auto-export suspicious entries to timeline ────────────────────────────
    import json
    suspicious = [e for e in entries if e["suspicious"] and e["last_run"]]
    if suspicious:
        events_path = os.path.join("data", "timeline_events.json")
        existing: list[dict] = []
        if os.path.exists(events_path):
            with open(events_path) as f:
                existing = json.load(f)

        new_events = []
        for e in suspicious:
            new_events.append({
                "timestamp": e["last_run"].isoformat(),
                "label":     os.path.basename(e["decoded"]) or e["decoded"],
                "category":  "registry",
                "severity":  "suspicious",
            })
        os.makedirs("data", exist_ok=True)
        with open(events_path, "w") as f:
            json.dump(existing + new_events, f, indent=2)
        console.print(f"[dim]✔ {len(new_events)} suspicious entries auto-saved to timeline.[/dim]")


if __name__ == "__main__":
    main()
