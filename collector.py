#!/usr/bin/env python3
"""
collector.py — SS Toolkit: Windows Evidence Collector
───────────────────────────────────────────────────────
Drop this EXE on the suspect's PC during a screenshare.
It automatically collects:
  • Prefetch files  (C:\\Windows\\Prefetch)
  • UserAssist registry  (recently run programs)
  • Running processes
  • Suspicious files in common cheat locations
  • .minecraft folder contents
  • Recently modified files on the Desktop / Downloads

Everything is displayed on screen and saved to a report
file on the Desktop:  ss_report_<timestamp>.txt

No installation needed.  Single EXE, runs and exits.
"""

import os
import sys
import struct
import hashlib
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

# ── Rich for coloured output ──────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box
    _RICH = True
except ImportError:
    _RICH = False

# ── winreg for live registry (Windows only) ───────────────────────────────────
if sys.platform == "win32":
    import winreg
    import ctypes

console = Console() if _RICH else None

# ─────────────────────────────────────────────────────────────────────────────
# Shared detection lists (inlined so collector.exe is self-contained)
# ─────────────────────────────────────────────────────────────────────────────

GHOST_CLIENTS = [
    "vape", "vape lite", "vapelite", "vape v4", "drip", "dripx", "drip x",
    "stardust", "atom", "reflex", "flaw", "ember", "starscript", "boze",
    "solis", "fentanyl", "pyro", "azura", "flux", "exhibition", "astolfo",
    "autumn", "vertex", "entropy", "quasar", "gorilla", "prism", "zephyr",
    "tenacity", "hybrid", "eagle", "albedo", "cheeto", "monsoon", "motion",
    "inertia", "novoline", "remix", "rise", "sigma", "raven", "ares",
    "rusherhack", "schildblade", "blackout", "luma", "ambrosia", "horion",
    "weave", "weaveloader", "weave-loader", "ghost client", "ghostclient",
]

BYPASS_INDICATORS = [
    "bypass", "javaagent", "java agent", "premain", "agentmain",
    "agent.jar", "dll inject", "dll injection", "createremotethread",
    "classtransformer", "bytebuddy", "javassist", "recaf",
    "unsigned jar", "bytecode", "memory patch", "hook",
    "watchdog bypass", "grim bypass", "intave bypass", "polar bypass",
    "vulcan bypass", "matrix bypass", "hypixel bypass",
]

DEBUG_TOOLS = [
    "processhacker", "process hacker", "cheatengine", "cheat engine",
    "wireshark", "fiddler", "ollydbg", "x64dbg", "x32dbg", "dnspy",
    "de4dot", "dotpeek", "ilspy", "jadx", "jd-gui", "recaf",
    "procmon", "procexp", "windbg", "ghidra", "ida pro",
]

FREE_CLIENTS = [
    "wurst", "impact", "aristois", "meteor", "future",
    "liquidbounce", "nodus", "enchanted",
]

ALL_CHEATS = GHOST_CLIENTS + BYPASS_INDICATORS + DEBUG_TOOLS + FREE_CLIENTS

def classify(name: str) -> str:
    low = name.lower()
    for kw in GHOST_CLIENTS + BYPASS_INDICATORS:
        if kw in low:
            return "critical"
    for kw in FREE_CLIENTS + DEBUG_TOOLS:
        if kw in low:
            return "suspicious"
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

EPOCH_DIFF = 116_444_736_000_000_000

def filetime_to_dt(ft: int) -> datetime | None:
    if ft == 0:
        return None
    unix_100ns = ft - EPOCH_DIFF
    if unix_100ns < 0:
        return None
    return datetime.fromtimestamp(unix_100ns / 10_000_000, tz=timezone.utc)

def rot13(text: str) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "unreadable"

def cprint(text: str, style: str = "") -> None:
    if _RICH:
        console.print(f"[{style}]{text}[/{style}]" if style else text)
    else:
        print(text)

def rule(title: str) -> None:
    if _RICH:
        console.rule(f"[bold cyan]{title}[/bold cyan]")
    else:
        print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

# ─────────────────────────────────────────────────────────────────────────────
# 1. System info
# ─────────────────────────────────────────────────────────────────────────────

def collect_sysinfo() -> dict:
    info = {
        "hostname":  platform.node(),
        "os":        platform.version(),
        "user":      os.environ.get("USERNAME", "unknown"),
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    return info

# ─────────────────────────────────────────────────────────────────────────────
# 2. Prefetch
# ─────────────────────────────────────────────────────────────────────────────

_PF_LAYOUT = {
    17: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x78, "runs_n": 1, "count_off": 0x90},
    23: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    26: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    30: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
    31: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8, "count_off": 0xD0},
}

def _parse_pf(path: str) -> dict | None:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None

    # MAM compressed (Win10)
    if data[:3] == b"MAM":
        try:
            import mam
            data = mam.decompress(data)
        except Exception:
            fname = os.path.basename(path).rsplit("-", 1)[0]
            return {"exe": fname, "runs": 0, "last_run": None, "compressed": True}

    if len(data) < 8 or data[4:8] != b"SCCA":
        return None

    version = struct.unpack_from("<I", data, 0)[0]
    layout  = _PF_LAYOUT.get(version)
    if not layout:
        return None

    # Exe name
    exe_raw = data[layout["exe_off"]: layout["exe_off"] + layout["exe_len"]]
    exe     = exe_raw.decode("utf-16-le", errors="replace").rstrip("\x00")

    # Run count
    runs = 0
    if len(data) >= layout["count_off"] + 4:
        runs = struct.unpack_from("<I", data, layout["count_off"])[0]

    # Last run time
    last_run = None
    for i in range(layout["runs_n"]):
        off = layout["runs_off"] + i * 8
        if len(data) < off + 8:
            break
        ft = struct.unpack_from("<Q", data, off)[0]
        dt = filetime_to_dt(ft)
        if dt and (last_run is None or dt > last_run):
            last_run = dt

    return {"exe": exe, "runs": runs, "last_run": last_run, "compressed": False}


def collect_prefetch() -> list[dict]:
    pf_dir = r"C:\Windows\Prefetch"
    if not os.path.isdir(pf_dir):
        return []

    results = []
    for fname in os.listdir(pf_dir):
        if not fname.lower().endswith(".pf"):
            continue
        parsed = _parse_pf(os.path.join(pf_dir, fname))
        if parsed:
            sev = classify(parsed["exe"])
            results.append({**parsed, "severity": sev})

    return sorted(
        results,
        key=lambda x: x["last_run"] or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

# ─────────────────────────────────────────────────────────────────────────────
# 3. UserAssist registry
# ─────────────────────────────────────────────────────────────────────────────

UA_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

def collect_userassist() -> list[dict]:
    if sys.platform != "win32":
        return []

    entries = []
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UA_PATH)
    except FileNotFoundError:
        return []

    guid_i = 0
    while True:
        try:
            guid = winreg.EnumKey(ua_key, guid_i)
        except OSError:
            break
        guid_i += 1
        try:
            count_key = winreg.OpenKey(ua_key, f"{guid}\\Count")
        except FileNotFoundError:
            continue

        val_i = 0
        while True:
            try:
                name, data, _ = winreg.EnumValue(count_key, val_i)
            except OSError:
                break
            val_i += 1
            if not isinstance(data, bytes) or len(data) < 8:
                continue
            decoded = rot13(name)
            run_count = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
            last_run  = None
            if len(data) >= 68:
                ft = struct.unpack_from("<Q", data, 60)[0]
                last_run = filetime_to_dt(ft)
            sev = classify(decoded)
            entries.append({
                "decoded":   decoded,
                "run_count": run_count,
                "last_run":  last_run,
                "severity":  sev,
            })
        count_key.Close()
    ua_key.Close()
    return entries

# ─────────────────────────────────────────────────────────────────────────────
# 4. Running processes
# ─────────────────────────────────────────────────────────────────────────────

def collect_processes() -> list[dict]:
    procs = []
    if sys.platform != "win32":
        return procs
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 2:
                continue
            name = parts[0]
            pid  = parts[1]
            sev  = classify(name)
            procs.append({"name": name, "pid": pid, "severity": sev})
    except Exception:
        pass
    return procs

# ─────────────────────────────────────────────────────────────────────────────
# 5. Suspicious files in common locations
# ─────────────────────────────────────────────────────────────────────────────

SCAN_DIRS = [
    os.path.expandvars(r"%APPDATA%\.minecraft\mods"),
    os.path.expandvars(r"%APPDATA%\.minecraft"),
    os.path.expandvars(r"%APPDATA%\Roaming"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
]

SCAN_EXTS = {".jar", ".exe", ".bat", ".vbs", ".ps1"}

def collect_suspicious_files() -> list[dict]:
    found = []
    for scan_dir in SCAN_DIRS:
        if not os.path.isdir(scan_dir):
            continue
        try:
            for fname in os.listdir(scan_dir):
                ext = os.path.splitext(fname)[1].lower()
                if ext not in SCAN_EXTS:
                    continue
                sev = classify(fname)
                if sev:
                    fpath = os.path.join(scan_dir, fname)
                    try:
                        mtime = datetime.fromtimestamp(
                            os.path.getmtime(fpath), tz=timezone.utc
                        ).strftime("%Y-%m-%d %H:%M")
                    except OSError:
                        mtime = "?"
                    found.append({
                        "path":     fpath,
                        "name":     fname,
                        "severity": sev,
                        "modified": mtime,
                        "sha256":   sha256_file(fpath),
                    })
        except PermissionError:
            pass
    return found

# ─────────────────────────────────────────────────────────────────────────────
# 6. .minecraft mod list
# ─────────────────────────────────────────────────────────────────────────────

def collect_mods() -> list[dict]:
    mods_dir = os.path.expandvars(r"%APPDATA%\.minecraft\mods")
    if not os.path.isdir(mods_dir):
        return []
    mods = []
    for fname in os.listdir(mods_dir):
        sev = classify(fname)
        fpath = os.path.join(mods_dir, fname)
        try:
            size = os.path.getsize(fpath)
        except OSError:
            size = 0
        mods.append({"name": fname, "size": size, "severity": sev})
    return sorted(mods, key=lambda x: (x["severity"] != "critical", x["severity"] != "suspicious", x["name"]))

# ─────────────────────────────────────────────────────────────────────────────
# Display helpers
# ─────────────────────────────────────────────────────────────────────────────

_SEV_STYLE = {
    "critical":   "bold red",
    "suspicious": "bold yellow",
    "":           "dim",
}

def _sev_label(sev: str) -> str:
    if sev == "critical":
        return "[bold red]⚠ CRITICAL[/bold red]"
    if sev == "suspicious":
        return "[bold yellow]⚠ SUSPICIOUS[/bold yellow]"
    return "[dim]clean[/dim]"


def display_prefetch(entries: list[dict]) -> None:
    rule("Prefetch — Recently Run Programs")
    flagged = [e for e in entries if e["severity"]]
    cprint(f"Total .pf files: {len(entries)}  |  Flagged: {len(flagged)}\n")

    if not _RICH:
        for e in flagged:
            print(f"  [{e['severity'].upper()}] {e['exe']}  runs={e['runs']}")
        return

    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("EXE Name",       min_width=24)
    table.add_column("Runs", width=6,  no_wrap=True)
    table.add_column("Last Run (UTC)", min_width=22)
    table.add_column("Severity",       min_width=14)

    for e in entries[:60]:   # cap at 60 rows
        sev   = e["severity"]
        style = _SEV_STYLE.get(sev, "")
        lr    = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "—"
        name  = e["exe"]
        if style:
            table.add_row(
                f"[{style}]{name}[/{style}]",
                str(e["runs"]),
                lr,
                _sev_label(sev),
            )
        else:
            table.add_row(name, str(e["runs"]), lr, _sev_label(sev))
    console.print(table)


def display_userassist(entries: list[dict]) -> None:
    rule("UserAssist — Programs Opened via Explorer / Start Menu")
    flagged = [e for e in entries if e["severity"]]
    cprint(f"Total entries: {len(entries)}  |  Flagged: {len(flagged)}\n")

    suspicious_only = [e for e in entries if e["severity"]]
    if not suspicious_only:
        cprint("No suspicious entries found.", "green")
        return

    if not _RICH:
        for e in suspicious_only:
            print(f"  [{e['severity'].upper()}] {e['decoded']}")
        return

    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Decoded Path",   min_width=50)
    table.add_column("Runs", width=6,  no_wrap=True)
    table.add_column("Last Run (UTC)", min_width=22)
    table.add_column("Severity",       min_width=14)

    for e in suspicious_only:
        sev   = e["severity"]
        style = _SEV_STYLE.get(sev, "")
        lr    = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "—"
        path  = e["decoded"][-80:]
        table.add_row(
            f"[{style}]{path}[/{style}]",
            str(e["run_count"]),
            lr,
            _sev_label(sev),
        )
    console.print(table)


def display_processes(procs: list[dict]) -> None:
    rule("Running Processes")
    flagged = [p for p in procs if p["severity"]]
    cprint(f"Total processes: {len(procs)}  |  Flagged: {len(flagged)}\n")

    if not flagged:
        cprint("No suspicious processes running.", "green")
        return

    if not _RICH:
        for p in flagged:
            print(f"  [{p['severity'].upper()}] {p['name']}  PID={p['pid']}")
        return

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Process Name", min_width=30)
    table.add_column("PID",          width=8, no_wrap=True)
    table.add_column("Severity",     min_width=14)

    for p in flagged:
        sev   = p["severity"]
        style = _SEV_STYLE.get(sev, "")
        table.add_row(
            f"[{style}]{p['name']}[/{style}]",
            p["pid"],
            _sev_label(sev),
        )
    console.print(table)


def display_files(files: list[dict]) -> None:
    rule("Suspicious Files in Common Locations")
    if not files:
        cprint("No suspicious files found in scanned locations.", "green")
        return

    if not _RICH:
        for f in files:
            print(f"  [{f['severity'].upper()}] {f['path']}")
        return

    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("File Name",     min_width=24)
    table.add_column("Location",      min_width=30)
    table.add_column("Modified",      width=17, no_wrap=True)
    table.add_column("SHA-256",       min_width=20)
    table.add_column("Severity",      min_width=14)

    for f in files:
        sev   = f["severity"]
        style = _SEV_STYLE.get(sev, "")
        loc   = os.path.dirname(f["path"])
        table.add_row(
            f"[{style}]{f['name']}[/{style}]",
            loc[-40:],
            f["modified"],
            f["sha256"][:20] + "…",
            _sev_label(sev),
        )
    console.print(table)


def display_mods(mods: list[dict]) -> None:
    rule(".minecraft Mods Folder")
    if not mods:
        cprint("Mods folder is empty or not found.", "dim")
        return

    if not _RICH:
        for m in mods:
            flag = f" [{m['severity'].upper()}]" if m["severity"] else ""
            print(f"  {m['name']}{flag}")
        return

    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Mod File",   min_width=30)
    table.add_column("Size (KB)",  width=10, no_wrap=True)
    table.add_column("Severity",   min_width=14)

    for m in mods:
        sev   = m["severity"]
        style = _SEV_STYLE.get(sev, "")
        size  = str(round(m["size"] / 1024, 1))
        table.add_row(
            f"[{style}]{m['name']}[/{style}]",
            size,
            _sev_label(sev),
        )
    console.print(table)

# ─────────────────────────────────────────────────────────────────────────────
# Report export
# ─────────────────────────────────────────────────────────────────────────────

def save_report(sysinfo: dict, pf: list, ua: list, procs: list,
                files: list, mods: list, report_path: str) -> None:
    ts    = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"SS Toolkit — Evidence Report",
        f"Generated: {ts}",
        f"Host: {sysinfo['hostname']}  |  User: {sysinfo['user']}",
        f"OS: {sysinfo['os']}",
        "=" * 70,
        "",
    ]

    # Prefetch
    lines += ["PREFETCH — FLAGGED ENTRIES", "─" * 40]
    flagged_pf = [e for e in pf if e["severity"]]
    if flagged_pf:
        for e in flagged_pf:
            lr = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "unknown"
            lines.append(f"  [{e['severity'].upper()}] {e['exe']}  runs={e['runs']}  last={lr}")
    else:
        lines.append("  None")
    lines.append("")

    # UserAssist
    lines += ["USERASSIST — FLAGGED ENTRIES", "─" * 40]
    flagged_ua = [e for e in ua if e["severity"]]
    if flagged_ua:
        for e in flagged_ua:
            lr = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "unknown"
            lines.append(f"  [{e['severity'].upper()}] {e['decoded']}  runs={e['run_count']}  last={lr}")
    else:
        lines.append("  None")
    lines.append("")

    # Processes
    lines += ["RUNNING PROCESSES — FLAGGED", "─" * 40]
    flagged_pr = [p for p in procs if p["severity"]]
    if flagged_pr:
        for p in flagged_pr:
            lines.append(f"  [{p['severity'].upper()}] {p['name']}  PID={p['pid']}")
    else:
        lines.append("  None")
    lines.append("")

    # Suspicious files
    lines += ["SUSPICIOUS FILES", "─" * 40]
    if files:
        for f in files:
            lines.append(f"  [{f['severity'].upper()}] {f['path']}")
            lines.append(f"    SHA-256: {f['sha256']}")
    else:
        lines.append("  None")
    lines.append("")

    # Mods
    lines += ["MINECRAFT MODS", "─" * 40]
    if mods:
        for m in mods:
            flag = f" [{m['severity'].upper()}]" if m["severity"] else ""
            lines.append(f"  {m['name']}{flag}")
    else:
        lines.append("  None / not installed")
    lines.append("")

    # Summary
    total_flags = len(flagged_pf) + len(flagged_ua) + len(flagged_pr) + len(files)
    lines += [
        "=" * 70,
        f"TOTAL FLAGS: {total_flags}",
        f"  Prefetch:    {len(flagged_pf)}",
        f"  UserAssist:  {len(flagged_ua)}",
        f"  Processes:   {len(flagged_pr)}",
        f"  Files:       {len(files)}",
    ]

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    if _RICH:
        console.print(Panel(
            "[bold cyan]SS Toolkit — Windows Evidence Collector[/bold cyan]\n"
            "[dim]Collecting evidence from this PC…[/dim]",
            border_style="cyan",
        ))
    else:
        print("SS Toolkit — Windows Evidence Collector")
        print("Collecting evidence from this PC…\n")

    if sys.platform != "win32":
        cprint(
            "\n[bold yellow]Warning:[/bold yellow] This collector is designed for Windows.\n"
            "Some sections (Prefetch, UserAssist, Processes) will be empty on Mac/Linux.\n"
        )

    # ── Collect ──────────────────────────────────────────────────────────────
    if _RICH:
        with console.status("[dim]Scanning…[/dim]"):
            sysinfo = collect_sysinfo()
            pf      = collect_prefetch()
            ua      = collect_userassist()
            procs   = collect_processes()
            files   = collect_suspicious_files()
            mods    = collect_mods()
    else:
        print("Scanning…")
        sysinfo = collect_sysinfo()
        pf      = collect_prefetch()
        ua      = collect_userassist()
        procs   = collect_processes()
        files   = collect_suspicious_files()
        mods    = collect_mods()

    # ── Display ──────────────────────────────────────────────────────────────
    if _RICH:
        console.print(Panel(
            f"[bold]Hostname:[/bold]  {sysinfo['hostname']}\n"
            f"[bold]User:[/bold]      {sysinfo['user']}\n"
            f"[bold]OS:[/bold]        {sysinfo['os']}\n"
            f"[bold]Scanned:[/bold]   {sysinfo['timestamp']}",
            title="[bold]System Info[/bold]",
            border_style="dim",
        ))

    display_prefetch(pf)
    display_userassist(ua)
    display_processes(procs)
    display_files(files)
    display_mods(mods)

    # ── Summary ──────────────────────────────────────────────────────────────
    total_flags = (
        len([e for e in pf    if e["severity"]]) +
        len([e for e in ua    if e["severity"]]) +
        len([e for e in procs if e["severity"]]) +
        len(files)
    )
    rule("Summary")
    if total_flags == 0:
        cprint("No suspicious findings detected.", "bold green")
    else:
        cprint(f"Total flags: {total_flags}", "bold red")

    # ── Save report ───────────────────────────────────────────────────────────
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    desktop     = os.path.join(os.path.expandvars("%USERPROFILE%"), "Desktop") \
                  if sys.platform == "win32" else os.path.expanduser("~")
    report_path = os.path.join(desktop, f"ss_report_{ts}.txt")

    save_report(sysinfo, pf, ua, procs, files, mods, report_path)
    cprint(f"\n[bold green]Report saved to:[/bold green] {report_path}")

    input("\nPress Enter to exit…")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print("\n" + "=" * 60)
        print("ERROR — something went wrong:")
        print("=" * 60)
        traceback.print_exc()
        print("=" * 60)
        input("\nPress Enter to exit…")
