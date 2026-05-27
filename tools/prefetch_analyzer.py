"""
prefetch_analyzer.py — Tool 2: Windows Prefetch File Analyzer
──────────────────────────────────────────────────────────────
Reads one or more .pf files from C:\\Windows\\Prefetch and:
  • Shows the executable name, run count, and last-run timestamps
  • Flags suspicious EXE names (cheat clients, injectors, etc.)
  • Detects "timestamp clustering" — multiple suspicious files run
    within the same short window (a common sign of cheat launching)

Supported prefetch versions:
  v17  — Windows XP
  v23  — Windows Vista / 7
  v26  — Windows 8 / 8.1
  v30  — Windows 10 / 11 (requires 'mam' package for decompression)

Usage (from menu or directly):
    python tools/prefetch_analyzer.py
"""

import os
import sys
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from tools.shared import is_suspicious, filetime_to_dt, SEVERITY_STYLE

console = Console()

# ── Try to import mam for Windows 10 decompression ───────────────────────────
try:
    import mam as _mam
    _MAM_AVAILABLE = True
except ImportError:
    _MAM_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
# Binary parsing
# ─────────────────────────────────────────────────────────────────────────────

PREFETCH_MAGIC = b"SCCA"

# Per-version header field offsets
_LAYOUT = {
    17: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x78, "runs_n": 1, "count_off": 0x90},
    23: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    26: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    30: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    31: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
}


def _decompress_mam(data: bytes) -> bytes | None:
    """
    Win10+ prefetch files are MAM-compressed.
    Returns decompressed bytes, or None if mam package missing.
    """
    if not _MAM_AVAILABLE:
        return None
    try:
        return _mam.decompress(data)
    except Exception:
        return None


def parse_prefetch(path: str) -> dict | None:
    """
    Parse a single .pf file and return:
        {
            "path": str,
            "exe_name": str,
            "version": int,
            "run_count": int,
            "last_runs": [datetime, ...],   # up to 8, newest first
            "compressed": bool,
            "error": str | None,
        }
    Returns None if the file is unreadable or not a prefetch file.
    """
    result = {
        "path":       path,
        "exe_name":   "UNKNOWN",
        "version":    0,
        "run_count":  0,
        "last_runs":  [],
        "compressed": False,
        "error":      None,
    }

    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        result["error"] = str(e)
        return result

    # ── Detect MAM compression (Win10) ──────────────────────────────────────
    data = raw
    if raw[:3] == b"MAM":
        result["compressed"] = True
        data = _decompress_mam(raw)
        if data is None:
            result["error"] = (
                "Win10 MAM-compressed prefetch — install 'mam' to analyse: pip install mam"
            )
            # Still try to grab the exe name from the filename
            fname = os.path.basename(path)  # e.g. WURST.EXE-ABCD1234.pf
            result["exe_name"] = fname.rsplit("-", 1)[0] if "-" in fname else fname
            return result

    # ── Validate signature ───────────────────────────────────────────────────
    if len(data) < 8 or data[4:8] != PREFETCH_MAGIC:
        result["error"] = "Not a valid prefetch file (bad signature)"
        return result

    version = struct.unpack_from("<I", data, 0)[0]
    result["version"] = version

    layout = _LAYOUT.get(version)
    if layout is None:
        result["error"] = f"Unsupported prefetch version: {version}"
        # Still try to grab exe name from the filename
        fname = os.path.basename(path)
        result["exe_name"] = fname.rsplit("-", 1)[0] if "-" in fname else fname
        return result

    # ── Executable name ──────────────────────────────────────────────────────
    exe_off = layout["exe_off"]
    exe_len = layout["exe_len"]
    if len(data) >= exe_off + exe_len:
        raw_name = data[exe_off: exe_off + exe_len]
        exe_name = raw_name.decode("utf-16-le", errors="replace").rstrip("\x00")
        result["exe_name"] = exe_name or os.path.basename(path)
    else:
        result["exe_name"] = os.path.basename(path)

    # ── Run count ────────────────────────────────────────────────────────────
    cnt_off = layout["count_off"]
    if len(data) >= cnt_off + 4:
        result["run_count"] = struct.unpack_from("<I", data, cnt_off)[0]

    # ── Last run times ───────────────────────────────────────────────────────
    runs_off = layout["runs_off"]
    runs_n   = layout["runs_n"]
    runs: list[datetime] = []
    for i in range(runs_n):
        off = runs_off + i * 8
        if len(data) < off + 8:
            break
        ft_bytes = data[off: off + 8]
        dt = filetime_to_dt(ft_bytes)
        if dt:
            runs.append(dt)
    result["last_runs"] = sorted(set(runs), reverse=True)  # newest first

    return result

# ─────────────────────────────────────────────────────────────────────────────
# Clustering detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_clusters(
    entries: list[dict],
    window_seconds: int = 30,
    min_cluster_size: int = 2,
) -> list[list[dict]]:
    """
    Find groups of entries whose *most-recent* run time falls within
    *window_seconds* of each other.

    Returns a list of clusters (each cluster = list of entry dicts).
    Only clusters with ≥ *min_cluster_size* members are returned.
    """
    # Build a flat list of (datetime, entry) only for entries that have times
    timed = []
    for e in entries:
        if e["last_runs"]:
            timed.append((e["last_runs"][0], e))

    if not timed:
        return []

    timed.sort(key=lambda x: x[0])
    window = timedelta(seconds=window_seconds)

    clusters: list[list[dict]] = []
    current: list[tuple] = [timed[0]]

    for i in range(1, len(timed)):
        if timed[i][0] - timed[i - 1][0] <= window:
            current.append(timed[i])
        else:
            if len(current) >= min_cluster_size:
                clusters.append([item[1] for item in current])
            current = [timed[i]]

    if len(current) >= min_cluster_size:
        clusters.append([item[1] for item in current])

    return clusters

# ─────────────────────────────────────────────────────────────────────────────
# Pretty output
# ─────────────────────────────────────────────────────────────────────────────

def print_entries(entries: list[dict]) -> None:
    """Display parsed prefetch entries in a Rich table."""
    table = Table(
        title="Prefetch Entries",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("EXE Name",         min_width=24)
    table.add_column("Ver",  width=5,    no_wrap=True)
    table.add_column("Runs", width=5,    no_wrap=True)
    table.add_column("Last Run (UTC)",   min_width=22)
    table.add_column("Flag",             min_width=12)
    table.add_column("Notes",            min_width=30)

    for e in sorted(entries, key=lambda x: x["last_runs"][0] if x["last_runs"] else datetime.min.replace(tzinfo=timezone.utc), reverse=True):
        suspicious = is_suspicious(e["exe_name"])
        has_error  = bool(e.get("error"))

        if has_error and not suspicious:
            style = "dim"
            flag  = "?"
        elif suspicious:
            style = SEVERITY_STYLE["suspicious"]
            flag  = "⚠ SUSPICIOUS"
        else:
            style = ""
            flag  = "✔ clean"

        last_run = e["last_runs"][0].strftime("%Y-%m-%d %H:%M:%S") if e["last_runs"] else "—"
        notes    = e.get("error") or ""
        if e["compressed"] and not e.get("error"):
            notes = "MAM compressed"

        table.add_row(
            f"[{style}]{e['exe_name']}[/{style}]" if style else e["exe_name"],
            str(e["version"]) if e["version"] else "?",
            str(e["run_count"]),
            last_run,
            f"[{style}]{flag}[/{style}]" if style else flag,
            f"[dim]{notes}[/dim]" if notes else "",
        )

    console.print(table)


def print_clusters(clusters: list[list[dict]]) -> None:
    """Print timestamp cluster warnings."""
    if not clusters:
        console.print("[green]No suspicious timestamp clustering detected.[/green]\n")
        return

    console.print(
        f"\n[bold yellow]⚠  TIMESTAMP CLUSTERING DETECTED "
        f"({len(clusters)} cluster(s))[/bold yellow]\n"
        "Multiple files were run within a very short window — this can indicate "
        "a cheat launcher starting several tools at once.\n"
    )
    for i, cluster in enumerate(clusters, 1):
        names = ", ".join(e["exe_name"] for e in cluster)
        ts    = cluster[0]["last_runs"][0].strftime("%Y-%m-%d %H:%M:%S UTC") if cluster[0]["last_runs"] else "unknown time"
        console.print(
            f"  [bold yellow]Cluster {i}[/bold yellow] — {len(cluster)} files around {ts}\n"
            f"    {names}\n"
        )

# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    console.rule("[bold blue]Tool 2 — Prefetch File Analyzer[/bold blue]")
    console.print(
        "Provide a path to a folder containing [bold].pf[/bold] files "
        "(usually [italic]C:\\\\Windows\\\\Prefetch[/italic]) "
        "or a single .pf file.\n"
    )

    raw_path = console.input("[bold]Enter path:[/bold] ").strip().strip('"').strip("'")

    if not raw_path:
        console.print("[red]No path entered. Returning to menu.[/red]")
        return

    pf_files: list[str] = []

    if os.path.isdir(raw_path):
        pf_files = [
            os.path.join(raw_path, f)
            for f in os.listdir(raw_path)
            if f.lower().endswith(".pf")
        ]
        console.print(f"[dim]Found {len(pf_files)} .pf files in {raw_path}[/dim]\n")
    elif os.path.isfile(raw_path):
        pf_files = [raw_path]
    else:
        console.print(f"[red]Path not found:[/red] {raw_path}")
        return

    if not pf_files:
        console.print("[yellow]No .pf files found at that location.[/yellow]")
        return

    # ── Parse ────────────────────────────────────────────────────────────────
    entries: list[dict] = []
    with console.status("[dim]Parsing prefetch files…[/dim]"):
        for pf in pf_files:
            result = parse_prefetch(pf)
            if result:
                entries.append(result)

    # ── Display ──────────────────────────────────────────────────────────────
    print_entries(entries)

    suspicious_entries = [e for e in entries if is_suspicious(e["exe_name"])]
    clusters = detect_clusters(entries)

    console.print(
        f"\n[bold]Summary:[/bold] {len(entries)} files parsed, "
        f"[yellow]{len(suspicious_entries)} suspicious[/yellow], "
        f"[red]{len(clusters)} cluster(s)[/red]\n"
    )

    print_clusters(clusters)

    # ── Offer to pass data to timeline ───────────────────────────────────────
    save = console.input("[dim]Export events for the timeline? (y/N):[/dim] ").strip().lower()
    if save == "y":
        import json, os as _os
        events_path = _os.path.join("data", "timeline_events.json")
        existing: list[dict] = []
        if _os.path.exists(events_path):
            with open(events_path) as f:
                existing = json.load(f)

        new_events = []
        for e in entries:
            if not e["last_runs"]:
                continue
            sev = "suspicious" if is_suspicious(e["exe_name"]) else "info"
            new_events.append({
                "timestamp": e["last_runs"][0].isoformat(),
                "label":     e["exe_name"],
                "category":  "prefetch",
                "severity":  sev,
            })

        all_events = existing + new_events
        with open(events_path, "w") as f:
            json.dump(all_events, f, indent=2)
        console.print(f"[green]Events appended to:[/green] {events_path}")


if __name__ == "__main__":
    main()
