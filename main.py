#!/usr/bin/env python3
"""
ss-toolkit — Minecraft Screenshare Toolkit
───────────────────────────────────────────
A collection of six tools to help server staff run clean, thorough
screenshares against suspected cheaters.

Run this file to open the interactive menu:
    python main.py
"""

import sys
import os

# Ensure the toolkit root is on the Python path so 'tools' imports work
sys.path.insert(0, os.path.dirname(__file__))

# ── Dependency check ──────────────────────────────────────────────────────────
_MISSING: list[str] = []
for _pkg in ("rich", "colorama"):
    try:
        __import__(_pkg)
    except ImportError:
        _MISSING.append(_pkg)

if _MISSING:
    print(f"[!] Missing required packages: {', '.join(_MISSING)}")
    print("    Run:  pip install -r requirements.txt")
    sys.exit(1)

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  ___  ___     _____         _ _   _ _
 / __\/ __\   /__   \___   _| | | (_) |_
 \__ \\__ \     / /\/ _ \ / _ | | | | __|
 / _// _/      / / | (_) | (_) | |_| | |_
/___/\___/     \/   \___/ \___/ \__,_|\__|
"""

TOOL_TABLE = [
    ("1", "OAC PDF Scanner",        "Parse an Ocean Anti-Cheat PDF and flag suspicious entries"),
    ("2", "Prefetch Analyzer",       "Detect suspicious EXEs and timestamp clustering in .pf files"),
    ("3", "UserAssist Decoder",      "Decode ROT13 registry entries and flag suspicious paths"),
    ("4", "Timeline Builder",        "Build a colour-coded visual timeline with matplotlib"),
    ("5", "Discord Screenshare Bot", "Step-by-step SS guide bot for your Discord server"),
    ("6", "Hash Database",           "SQLite database of known cheat file hashes"),
    ("0", "Exit",                    ""),
]

# ─────────────────────────────────────────────────────────────────────────────
# Menu
# ─────────────────────────────────────────────────────────────────────────────

def print_menu() -> None:
    console.clear()

    # ASCII banner
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        "  [dim]Minecraft Screensharing Toolkit  •  "
        "Use the number keys to launch a tool[/dim]\n"
    )

    table = Table(box=box.ROUNDED, show_header=True, expand=False)
    table.add_column("  #  ", style="bold cyan",  no_wrap=True, width=5)
    table.add_column("Tool",                       min_width=26)
    table.add_column("Description",  style="dim", min_width=48)

    for num, name, desc in TOOL_TABLE:
        if num == "0":
            table.add_row(f"  {num}  ", f"[dim]{name}[/dim]", "")
        else:
            table.add_row(f"  {num}  ", f"[bold]{name}[/bold]", desc)

    console.print(table)
    console.print()


def run_tool(choice: str) -> None:
    """Import and call main() for the selected tool."""

    if choice == "1":
        from tools.pdf_scanner import main
        main()

    elif choice == "2":
        from tools.prefetch_analyzer import main
        main()

    elif choice == "3":
        from tools.userassist_decoder import main
        main()

    elif choice == "4":
        from tools.timeline_builder import main
        main()

    elif choice == "5":
        from tools.discord_bot import main
        main()

    elif choice == "6":
        from tools.hash_database import main
        main()

    else:
        console.print("[red]Invalid choice.  Enter 0-6.[/red]")
        return

    # After a tool finishes, pause so the user can read any output
    try:
        console.input("\n[dim]Press Enter to return to the menu…[/dim]")
    except (KeyboardInterrupt, EOFError):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Quick dependency-check hint shown at startup
# ─────────────────────────────────────────────────────────────────────────────

def _check_optional_deps() -> None:
    optional = {
        "pdfplumber":  "Tool 1 — PDF Scanner",
        "matplotlib":  "Tool 4 — Timeline Builder",
        "discord":     "Tool 5 — Discord Bot",
    }
    missing = []
    for pkg, label in optional.items():
        try:
            __import__(pkg)
        except ImportError:
            missing.append(f"  [yellow]• {pkg}[/yellow]  (needed for {label})")

    if missing:
        console.print(
            Panel(
                "Some optional packages are not installed:\n"
                + "\n".join(missing)
                + "\n\n[dim]Run:  pip install -r requirements.txt[/dim]",
                title="[yellow]Optional Dependencies Missing[/yellow]",
                border_style="yellow",
                expand=False,
            )
        )
        try:
            console.input("[dim]Press Enter to continue…[/dim]")
        except (KeyboardInterrupt, EOFError):
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    _check_optional_deps()

    while True:
        print_menu()
        try:
            choice = console.input("[bold]Select tool (0-6):[/bold] ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Goodbye.[/dim]")
            break

        if choice == "0":
            console.print("[dim]Goodbye.[/dim]")
            break

        try:
            run_tool(choice)
        except KeyboardInterrupt:
            console.print("\n[dim]Tool interrupted.  Returning to menu…[/dim]")
        except Exception as exc:
            console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
            console.print("[dim]Check that all dependencies are installed (pip install -r requirements.txt)[/dim]")
            try:
                console.input("\n[dim]Press Enter to continue…[/dim]")
            except (KeyboardInterrupt, EOFError):
                pass


if __name__ == "__main__":
    main()
