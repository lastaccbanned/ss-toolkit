#!/usr/bin/env python3
"""
collector.py — SS Toolkit: Windows Evidence Collector
Drop this EXE on the suspect's PC. It scans automatically and saves
a report to their Desktop. Uses ONLY Python built-in modules so it
will always run without any dependency issues.
"""

# ── All imports are stdlib only — nothing external ────────────────────────────
import os
import sys
import struct
import hashlib
import platform
import subprocess
import traceback
from datetime import datetime, timezone
from pathlib import Path

if sys.platform == "win32":
    import winreg

# ─────────────────────────────────────────────────────────────────────────────
# Console colours (plain ANSI — no rich needed)
# ─────────────────────────────────────────────────────────────────────────────

# Enable ANSI colours on Windows 10+
if sys.platform == "win32":
    os.system("color")

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def cprint(text, colour=""):
    print(f"{colour}{text}{RESET}" if colour else text)

def rule(title):
    width = 60
    print(f"\n{CYAN}{'─' * width}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─' * width}{RESET}\n")

# ─────────────────────────────────────────────────────────────────────────────
# Detection lists
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
    "unsigned jar", "bytecode", "memory patch",
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

def classify(name):
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

def filetime_to_dt(ft):
    if ft == 0:
        return None
    unix_100ns = ft - EPOCH_DIFF
    if unix_100ns < 0:
        return None
    try:
        return datetime.fromtimestamp(unix_100ns / 10_000_000, tz=timezone.utc)
    except Exception:
        return None

def rot13(text):
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)

def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unreadable"

# ─────────────────────────────────────────────────────────────────────────────
# 1. System info
# ─────────────────────────────────────────────────────────────────────────────

def collect_sysinfo():
    return {
        "hostname":  platform.node(),
        "os":        platform.version(),
        "user":      os.environ.get("USERNAME", os.environ.get("USER", "unknown")),
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

# ─────────────────────────────────────────────────────────────────────────────
# 2. Prefetch
# ─────────────────────────────────────────────────────────────────────────────

_PF_LAYOUT = {
    17: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x78, "runs_n": 1,  "count_off": 0x90},
    23: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8,  "count_off": 0xD0},
    26: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8,  "count_off": 0xD0},
    30: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8,  "count_off": 0xD0},
    31: {"exe_off": 0x10, "exe_len": 60, "runs_off": 0x80, "runs_n": 8,  "count_off": 0xD0},
}

def _parse_pf(path):
    try:
        data = Path(path).read_bytes()
    except Exception:
        return None

    if data[:3] == b"MAM":
        fname = os.path.basename(path).rsplit("-", 1)[0]
        return {"exe": fname, "runs": 0, "last_run": None, "compressed": True, "severity": classify(fname)}

    if len(data) < 8 or data[4:8] != b"SCCA":
        return None

    try:
        version = struct.unpack_from("<I", data, 0)[0]
        layout  = _PF_LAYOUT.get(version)
        if not layout:
            fname = os.path.basename(path).rsplit("-", 1)[0]
            return {"exe": fname, "runs": 0, "last_run": None, "compressed": False, "severity": classify(fname)}

        exe_raw = data[layout["exe_off"]: layout["exe_off"] + layout["exe_len"]]
        exe     = exe_raw.decode("utf-16-le", errors="replace").rstrip("\x00") or os.path.basename(path)

        runs = 0
        if len(data) >= layout["count_off"] + 4:
            runs = struct.unpack_from("<I", data, layout["count_off"])[0]

        last_run = None
        for i in range(layout["runs_n"]):
            off = layout["runs_off"] + i * 8
            if len(data) < off + 8:
                break
            ft  = struct.unpack_from("<Q", data, off)[0]
            dt  = filetime_to_dt(ft)
            if dt and (last_run is None or dt > last_run):
                last_run = dt

        return {"exe": exe, "runs": runs, "last_run": last_run, "compressed": False, "severity": classify(exe)}
    except Exception:
        return None


def collect_prefetch():
    pf_dir = r"C:\Windows\Prefetch"
    if not os.path.isdir(pf_dir):
        return []
    results = []
    try:
        for fname in os.listdir(pf_dir):
            if fname.lower().endswith(".pf"):
                parsed = _parse_pf(os.path.join(pf_dir, fname))
                if parsed:
                    results.append(parsed)
    except Exception:
        pass
    return sorted(results, key=lambda x: x["last_run"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# 3. UserAssist
# ─────────────────────────────────────────────────────────────────────────────

UA_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

def collect_userassist():
    if sys.platform != "win32":
        return []
    entries = []
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UA_PATH)
        guid_i = 0
        while True:
            try:
                guid = winreg.EnumKey(ua_key, guid_i)
            except OSError:
                break
            guid_i += 1
            try:
                count_key = winreg.OpenKey(ua_key, f"{guid}\\Count")
            except Exception:
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
                decoded   = rot13(name)
                run_count = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
                last_run  = None
                if len(data) >= 68:
                    ft = struct.unpack_from("<Q", data, 60)[0]
                    last_run = filetime_to_dt(ft)
                entries.append({
                    "decoded":   decoded,
                    "run_count": run_count,
                    "last_run":  last_run,
                    "severity":  classify(decoded),
                })
            count_key.Close()
        ua_key.Close()
    except Exception:
        pass
    return entries

# ─────────────────────────────────────────────────────────────────────────────
# 4. Running processes
# ─────────────────────────────────────────────────────────────────────────────

def collect_processes():
    if sys.platform != "win32":
        return []
    procs = []
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=0x08000000,   # CREATE_NO_WINDOW
        )
        for line in out.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                name = parts[0]
                pid  = parts[1]
                procs.append({"name": name, "pid": pid, "severity": classify(name)})
    except Exception:
        pass
    return procs

# ─────────────────────────────────────────────────────────────────────────────
# 5. Suspicious files
# ─────────────────────────────────────────────────────────────────────────────

SCAN_DIRS = [
    os.path.expandvars(r"%APPDATA%\.minecraft\mods"),
    os.path.expandvars(r"%APPDATA%\.minecraft"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
]
SCAN_EXTS = {".jar", ".exe", ".bat", ".vbs", ".ps1"}

def collect_suspicious_files():
    found = []
    for scan_dir in SCAN_DIRS:
        if not os.path.isdir(scan_dir):
            continue
        try:
            for fname in os.listdir(scan_dir):
                if os.path.splitext(fname)[1].lower() not in SCAN_EXTS:
                    continue
                sev = classify(fname)
                if not sev:
                    continue
                fpath = os.path.join(scan_dir, fname)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
                except Exception:
                    mtime = "?"
                found.append({"path": fpath, "name": fname, "severity": sev, "modified": mtime, "sha256": sha256_file(fpath)})
        except Exception:
            pass
    return found

# ─────────────────────────────────────────────────────────────────────────────
# 6. Minecraft mods
# ─────────────────────────────────────────────────────────────────────────────

def collect_mods():
    mods_dir = os.path.expandvars(r"%APPDATA%\.minecraft\mods")
    if not os.path.isdir(mods_dir):
        return []
    mods = []
    try:
        for fname in os.listdir(mods_dir):
            try:
                size = os.path.getsize(os.path.join(mods_dir, fname))
            except Exception:
                size = 0
            mods.append({"name": fname, "size": size, "severity": classify(fname)})
    except Exception:
        pass
    return sorted(mods, key=lambda x: (x["severity"] != "critical", x["severity"] != "suspicious", x["name"]))

# ─────────────────────────────────────────────────────────────────────────────
# Display
# ─────────────────────────────────────────────────────────────────────────────

def sev_colour(sev):
    if sev == "critical":   return RED + BOLD
    if sev == "suspicious": return YELLOW + BOLD
    return ""

def display_prefetch(entries):
    rule("Prefetch — Recently Run Programs")
    flagged = [e for e in entries if e["severity"]]
    print(f"  Total .pf files: {len(entries)}   Flagged: {len(flagged)}\n")
    if not flagged:
        cprint("  No suspicious entries found.", GREEN)
        return
    print(f"  {'EXE Name':<35} {'Runs':>5}  {'Last Run (UTC)':<22}  Severity")
    print(f"  {'─'*35} {'─'*5}  {'─'*22}  {'─'*12}")
    for e in flagged:
        lr  = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "unknown"
        col = sev_colour(e["severity"])
        print(f"  {col}{e['exe']:<35}{RESET} {e['runs']:>5}  {lr:<22}  {col}{e['severity'].upper()}{RESET}")

def display_userassist(entries):
    rule("UserAssist — Programs Opened via Explorer / Start Menu")
    flagged = [e for e in entries if e["severity"]]
    print(f"  Total entries: {len(entries)}   Flagged: {len(flagged)}\n")
    if not flagged:
        cprint("  No suspicious entries found.", GREEN)
        return
    print(f"  {'Program Path':<60}  {'Runs':>5}  Severity")
    print(f"  {'─'*60}  {'─'*5}  {'─'*12}")
    for e in flagged:
        lr  = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e["last_run"] else "unknown"
        col = sev_colour(e["severity"])
        path = e["decoded"][-60:]
        print(f"  {col}{path:<60}{RESET}  {e['run_count']:>5}  {col}{e['severity'].upper()}{RESET}")

def display_processes(procs):
    rule("Running Processes")
    flagged = [p for p in procs if p["severity"]]
    print(f"  Total processes: {len(procs)}   Flagged: {len(flagged)}\n")
    if not flagged:
        cprint("  No suspicious processes running.", GREEN)
        return
    for p in flagged:
        col = sev_colour(p["severity"])
        print(f"  {col}[{p['severity'].upper()}]{RESET}  {p['name']}  (PID {p['pid']})")

def display_files(files):
    rule("Suspicious Files in Common Locations")
    if not files:
        cprint("  No suspicious files found.", GREEN)
        return
    for f in files:
        col = sev_colour(f["severity"])
        print(f"  {col}[{f['severity'].upper()}]{RESET}  {f['path']}")
        print(f"         SHA-256: {f['sha256']}")
        print(f"         Modified: {f['modified']}\n")

def display_mods(mods):
    rule(".minecraft Mods Folder")
    if not mods:
        cprint("  Mods folder empty or not found.", DIM)
        return
    print(f"  {'Mod File':<45} {'Size (KB)':>10}  Severity")
    print(f"  {'─'*45} {'─'*10}  {'─'*12}")
    for m in mods:
        col  = sev_colour(m["severity"])
        size = str(round(m["size"] / 1024, 1))
        sev  = f"{col}{m['severity'].upper()}{RESET}" if m["severity"] else f"{DIM}clean{RESET}"
        print(f"  {col}{m['name']:<45}{RESET} {size:>10}  {sev}")

# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def save_report(sysinfo, pf, ua, procs, files, mods, path):
    lines = [
        "SS Toolkit — Evidence Report",
        f"Generated : {sysinfo['timestamp']}",
        f"Host      : {sysinfo['hostname']}",
        f"User      : {sysinfo['user']}",
        f"OS        : {sysinfo['os']}",
        "=" * 70, "",
        "PREFETCH — FLAGGED ENTRIES", "─" * 40,
    ]
    flagged_pf = [e for e in pf if e["severity"]]
    lines += [f"  [{e['severity'].upper()}] {e['exe']}  runs={e['runs']}  last={e['last_run'].strftime('%Y-%m-%d %H:%M:%S') if e['last_run'] else '?'}" for e in flagged_pf] or ["  None"]
    lines += ["", "USERASSIST — FLAGGED ENTRIES", "─" * 40]
    flagged_ua = [e for e in ua if e["severity"]]
    lines += [f"  [{e['severity'].upper()}] {e['decoded']}  runs={e['run_count']}" for e in flagged_ua] or ["  None"]
    lines += ["", "RUNNING PROCESSES — FLAGGED", "─" * 40]
    flagged_pr = [p for p in procs if p["severity"]]
    lines += [f"  [{p['severity'].upper()}] {p['name']}  PID={p['pid']}" for p in flagged_pr] or ["  None"]
    lines += ["", "SUSPICIOUS FILES", "─" * 40]
    lines += [f"  [{f['severity'].upper()}] {f['path']}\n    SHA-256: {f['sha256']}" for f in files] or ["  None"]
    lines += ["", "MINECRAFT MODS", "─" * 40]
    lines += [f"  {m['name']}{' [' + m['severity'].upper() + ']' if m['severity'] else ''}" for m in mods] or ["  None / not installed"]
    total = len(flagged_pf) + len(flagged_ua) + len(flagged_pr) + len(files)
    lines += [
        "", "=" * 70,
        f"TOTAL FLAGS : {total}",
        f"  Prefetch   : {len(flagged_pf)}",
        f"  UserAssist : {len(flagged_ua)}",
        f"  Processes  : {len(flagged_pr)}",
        f"  Files      : {len(files)}",
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  SS Toolkit — Windows Evidence Collector{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}\n")
    print("  Scanning... please wait\n")

    sysinfo = collect_sysinfo()
    print(f"  {DIM}Host: {sysinfo['hostname']}  |  User: {sysinfo['user']}{RESET}")
    print(f"  {DIM}OS:   {sysinfo['os']}{RESET}\n")

    print(f"  {DIM}[1/5] Scanning Prefetch...{RESET}")
    pf = collect_prefetch()

    print(f"  {DIM}[2/5] Reading UserAssist registry...{RESET}")
    ua = collect_userassist()

    print(f"  {DIM}[3/5] Checking running processes...{RESET}")
    procs = collect_processes()

    print(f"  {DIM}[4/5] Scanning for suspicious files...{RESET}")
    files = collect_suspicious_files()

    print(f"  {DIM}[5/5] Checking .minecraft mods...{RESET}")
    mods = collect_mods()

    display_prefetch(pf)
    display_userassist(ua)
    display_processes(procs)
    display_files(files)
    display_mods(mods)

    total_flags = (
        len([e for e in pf    if e["severity"]]) +
        len([e for e in ua    if e["severity"]]) +
        len([e for e in procs if e["severity"]]) +
        len(files)
    )

    rule("Summary")
    if total_flags == 0:
        cprint(f"  No suspicious findings detected.", GREEN + BOLD)
    else:
        cprint(f"  Total flags: {total_flags}", RED + BOLD)

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    desktop = os.path.join(os.path.expandvars("%USERPROFILE%"), "Desktop") if sys.platform == "win32" else os.path.expanduser("~")
    report  = os.path.join(desktop, f"ss_report_{ts}.txt")

    save_report(sysinfo, pf, ua, procs, files, mods, report)
    cprint(f"\n  Report saved to: {report}", GREEN + BOLD)

    print(f"\n{CYAN}{'='*60}{RESET}")
    input("\n  Press Enter to exit...")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(f"\n{RED}{BOLD}ERROR — something went wrong:{RESET}")
        traceback.print_exc()
        input("\nPress Enter to exit...")
