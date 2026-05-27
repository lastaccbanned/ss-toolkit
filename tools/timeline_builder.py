"""
timeline_builder.py — Tool 4: Visual Event Timeline
─────────────────────────────────────────────────────
Reads events stored in  data/timeline_events.json  (populated by
tools 2 and 3) and renders a colour-coded horizontal timeline using
matplotlib.

You can also add events manually from within this tool.

Event schema (one object per entry in the JSON array):
    {
        "timestamp":  "2024-01-15T14:32:00+00:00",   # ISO-8601
        "label":      "wurst.jar",
        "category":   "prefetch" | "registry" | "scan" | "manual",
        "severity":   "critical" | "suspicious" | "info" | "clean",
    }

Usage (from menu or directly):
    python tools/timeline_builder.py
"""

import os
import json
import sys
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── Optional matplotlib import ────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use("Agg")          # non-interactive backend, safe everywhere
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import FancyBboxPatch
    _MPL_AVAILABLE = True
except ImportError:
    _MPL_AVAILABLE = False

EVENTS_PATH = os.path.join("data", "timeline_events.json")

# ── Colour mapping ────────────────────────────────────────────────────────────
SEVERITY_COLOURS = {
    "critical":   "#e74c3c",   # red
    "suspicious": "#f39c12",   # orange
    "info":       "#3498db",   # blue
    "clean":      "#2ecc71",   # green
}

CATEGORY_MARKERS = {
    "prefetch": "o",
    "registry": "s",   # square
    "scan":     "^",   # triangle
    "manual":   "D",   # diamond
}

# ─────────────────────────────────────────────────────────────────────────────
# JSON helpers
# ─────────────────────────────────────────────────────────────────────────────

def load_events() -> list[dict]:
    """Load events from EVENTS_PATH.  Returns [] if file missing."""
    if not os.path.exists(EVENTS_PATH):
        return []
    with open(EVENTS_PATH) as f:
        data = json.load(f)
    # Parse ISO timestamps
    parsed = []
    for e in data:
        try:
            ts = datetime.fromisoformat(e["timestamp"])
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            parsed.append({**e, "timestamp": ts})
        except (KeyError, ValueError):
            pass   # skip malformed entries
    return sorted(parsed, key=lambda x: x["timestamp"])


def save_events(events: list[dict]) -> None:
    """Save events to EVENTS_PATH."""
    os.makedirs("data", exist_ok=True)
    serialisable = [{**e, "timestamp": e["timestamp"].isoformat()} for e in events]
    with open(EVENTS_PATH, "w") as f:
        json.dump(serialisable, f, indent=2)

# ─────────────────────────────────────────────────────────────────────────────
# Timeline renderer
# ─────────────────────────────────────────────────────────────────────────────

def render_timeline(events: list[dict], output_path: str) -> str | None:
    """
    Render *events* as a PNG timeline and save to *output_path*.
    Returns the output path on success, None on failure.
    """
    if not _MPL_AVAILABLE:
        console.print(
            "[red]matplotlib is not installed.[/red]  "
            "Run:  pip install matplotlib Pillow"
        )
        return None

    if not events:
        console.print("[yellow]No events to render.[/yellow]")
        return None

    times  = [e["timestamp"] for e in events]
    labels = [e["label"]     for e in events]
    sevs   = [e.get("severity", "info")  for e in events]
    cats   = [e.get("category", "manual") for e in events]

    colours = [SEVERITY_COLOURS.get(s, "#999") for s in sevs]
    markers = [CATEGORY_MARKERS.get(c, "o")     for c in cats]

    fig_height = max(3.0, len(events) * 0.45 + 2.5)
    fig, ax = plt.subplots(figsize=(16, fig_height))

    # ── Draw the spine ────────────────────────────────────────────────────────
    if len(times) > 1:
        ax.plot([times[0], times[-1]], [0, 0],
                color="#cccccc", linewidth=2, zorder=1)
    else:
        ax.axhline(0, color="#cccccc", linewidth=2, zorder=1)

    # ── Plot each event ───────────────────────────────────────────────────────
    stagger_step = 0.45
    for i, (t, label, col, mk) in enumerate(zip(times, labels, colours, markers)):
        # Alternate labels above/below to reduce overlap
        y_offset = stagger_step * (1 if i % 2 == 0 else -1)

        ax.scatter([t], [0], color=col, marker=mk, s=90, zorder=3)
        ax.annotate(
            label,
            xy=(t, 0),
            xytext=(t, y_offset),
            ha="center",
            fontsize=7.5,
            color=col,
            fontweight="bold",
            arrowprops=dict(arrowstyle="-", color=col, lw=0.8),
        )

    # ── Formatting ────────────────────────────────────────────────────────────
    ax.set_yticks([])
    ax.spines[["left", "top", "right"]].set_visible(False)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate(rotation=30, ha="right")

    ax.set_title("Screenshare Event Timeline", fontsize=14, fontweight="bold", pad=14)

    # ── Legend ────────────────────────────────────────────────────────────────
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], marker="o", color="w", markerfacecolor=v, markersize=9, label=k.capitalize())
        for k, v in SEVERITY_COLOURS.items()
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=8, title="Severity")

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    return output_path

# ─────────────────────────────────────────────────────────────────────────────
# Rich table
# ─────────────────────────────────────────────────────────────────────────────

def print_events_table(events: list[dict]) -> None:
    from tools.shared import SEVERITY_STYLE
    table = Table(
        title=f"Loaded Events  ({len(events)} total)",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("#",          width=4,  no_wrap=True)
    table.add_column("Timestamp",  width=22, no_wrap=True)
    table.add_column("Category",   width=10, no_wrap=True)
    table.add_column("Severity",   width=12, no_wrap=True)
    table.add_column("Label")

    for i, e in enumerate(events, 1):
        sev   = e.get("severity", "info")
        style = SEVERITY_STYLE.get(sev, "")
        ts    = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        cat   = e.get("category", "manual")
        label = e.get("label", "?")

        if style:
            table.add_row(
                str(i),
                ts,
                cat,
                f"[{style}]{sev}[/{style}]",
                f"[{style}]{label}[/{style}]",
            )
        else:
            table.add_row(str(i), ts, cat, sev, label)

    console.print(table)

# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    console.rule("[bold blue]Tool 4 — Visual Timeline Builder[/bold blue]")
    console.print(
        "Builds a colour-coded PNG timeline from events collected by "
        "the prefetch and registry tools.\n"
    )

    events = load_events()

    while True:
        console.print(f"\n[dim]Events loaded:[/dim] {len(events)}\n")
        console.print("  [bold]1.[/bold] View current events")
        console.print("  [bold]2.[/bold] Add a manual event")
        console.print("  [bold]3.[/bold] Delete an event by number")
        console.print("  [bold]4.[/bold] Clear ALL events")
        console.print("  [bold]5.[/bold] [bold green]Render timeline PNG[/bold green]")
        console.print("  [bold]0.[/bold] Back to main menu\n")

        choice = console.input("[bold]Choice:[/bold] ").strip()

        if choice == "0":
            break

        elif choice == "1":
            if not events:
                console.print("[yellow]No events yet.  Use tools 2 & 3 to collect data, or add events manually.[/yellow]")
            else:
                print_events_table(events)

        elif choice == "2":
            # Manual event entry
            console.print("\n[bold]Add a manual event[/bold]")
            label = console.input("  Label (e.g. wurst.jar):  ").strip()
            if not label:
                console.print("[red]Label cannot be empty.[/red]")
                continue

            ts_str = console.input("  Timestamp (YYYY-MM-DD HH:MM or blank = now):  ").strip()
            if ts_str:
                try:
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M").replace(tzinfo=timezone.utc)
                except ValueError:
                    console.print("[red]Invalid format. Use YYYY-MM-DD HH:MM[/red]")
                    continue
            else:
                ts = datetime.now(tz=timezone.utc)

            console.print("  Severity — [1] critical  [2] suspicious  [3] info  [4] clean")
            sev_map = {"1": "critical", "2": "suspicious", "3": "info", "4": "clean"}
            sev     = sev_map.get(console.input("  Choice [1-4]: ").strip(), "info")

            events.append({
                "timestamp": ts,
                "label":     label,
                "category":  "manual",
                "severity":  sev,
            })
            events.sort(key=lambda x: x["timestamp"])
            save_events(events)
            console.print(f"[green]Event added and saved.[/green]")

        elif choice == "3":
            if not events:
                console.print("[yellow]No events to delete.[/yellow]")
                continue
            print_events_table(events)
            num_str = console.input("\nEnter event number to delete (or blank to cancel): ").strip()
            if not num_str:
                continue
            try:
                num = int(num_str)
                if 1 <= num <= len(events):
                    removed = events.pop(num - 1)
                    save_events(events)
                    console.print(f"[green]Removed:[/green] {removed['label']}")
                else:
                    console.print("[red]Number out of range.[/red]")
            except ValueError:
                console.print("[red]Please enter a valid number.[/red]")

        elif choice == "4":
            confirm = console.input("[bold red]Delete ALL events? (yes/N):[/bold red] ").strip().lower()
            if confirm == "yes":
                events.clear()
                save_events(events)
                console.print("[green]All events cleared.[/green]")

        elif choice == "5":
            if not events:
                console.print("[yellow]No events to render.  Add some first.[/yellow]")
                continue

            output_path = console.input(
                "[dim]Output path (blank = data/timeline.png):[/dim] "
            ).strip() or os.path.join("data", "timeline.png")

            console.print(f"[dim]Rendering to {output_path} …[/dim]")
            result = render_timeline(events, output_path)
            if result:
                console.print(f"[bold green]Timeline saved to:[/bold green] {result}")
            else:
                console.print("[red]Rendering failed.  Check that matplotlib is installed.[/red]")

        else:
            console.print("[red]Invalid choice.[/red]")


if __name__ == "__main__":
    main()
