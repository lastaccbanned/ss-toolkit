#!/usr/bin/env python3
"""
collector.py — SS Toolkit: Windows Evidence Collector (Professional Edition)
Drop on suspect PC, run as administrator. Saves HTML + JSON report.
Stdlib only — no pip installs needed. PyInstaller-compatible.
"""

import os, sys, re, json, struct, hashlib, glob, ctypes, subprocess, traceback, platform, time, csv, io
from datetime import datetime, timezone, timedelta
from pathlib import Path

if sys.platform == "win32":
    import winreg

if sys.platform == "win32":
    os.system("color")

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

def cprint(text, colour=""):
    print(f"{colour}{text}{RESET}" if colour else text)

def rule(title, icon=""):
    w = 72
    print(f"\n{CYAN}{'─'*w}{RESET}")
    print(f"{CYAN}{BOLD}  {icon}{title}{RESET}")
    print(f"{CYAN}{'─'*w}{RESET}\n")

def sev_col(sev):
    if sev == "critical":   return RED + BOLD
    if sev == "suspicious": return YELLOW
    return ""

# ── Progress ──────────────────────────────────────────────────────────────────
TOTAL_STEPS = 26
_step = 0

def progress(label):
    global _step
    _step += 1
    pct   = int(_step / TOTAL_STEPS * 100)
    filled = int(30 * _step / TOTAL_STEPS)
    bar   = "█" * filled + "░" * (30 - filled)
    col   = GREEN if pct < 50 else (YELLOW if pct < 80 else RED)
    print(f"  {col}[{bar}]{RESET} {_step:2d}/{TOTAL_STEPS}  {DIM}{label}{RESET}")

# ── Global timeline ────────────────────────────────────────────────────────────
TIMELINE: list[dict] = []

def add_event(ts, category, description, severity="info", detail=""):
    if ts:
        TIMELINE.append({"ts": ts, "cat": category, "desc": description,
                         "sev": severity, "detail": detail})

# ── Detection lists ───────────────────────────────────────────────────────────
GHOST_CLIENTS = [
    "vape","vapelite","vape lite","vape v4","drip","dripx","drip x",
    "stardust","atom","reflex","flaw","ember","starscript","boze","solis",
    "fentanyl","pyro","azura","flux","exhibition","astolfo","autumn","vertex",
    "entropy","quasar","gorilla","prism","zephyr","tenacity","hybrid","eagle",
    "albedo","cheeto","monsoon","motion","inertia","novoline","remix","rise",
    "sigma","raven","ares","rusherhack","schildblade","blackout","luma",
    "ambrosia","horion","weave","weaveloader","weave-loader","ghostclient",
    "ghost client","cringeware",
]
BYPASS_INDICATORS = [
    "bypass","javaagent","java agent","premain","agentmain","agent.jar",
    "classtransformer","bytebuddy","javassist","createremotethread",
    "dll inject","dll injection","memory patch","recaf","watchdog bypass",
    "grim bypass","intave bypass","polar bypass","vulcan bypass",
    "matrix bypass","hypixel bypass","badlion bypass","unsigned jar",
    "bytecode","classpath inject","hook detected","inline hook",
]
FREE_CLIENTS = ["wurst","impact","aristois","meteor","future","liquidbounce","nodus","enchanted"]
DEBUG_TOOLS  = [
    "processhacker","process hacker","cheatengine","cheat engine","wireshark",
    "fiddler","ollydbg","x64dbg","x32dbg","dnspy","de4dot","dotpeek","ilspy",
    "jadx","jd-gui","procmon","procexp","windbg","ghidra","ida pro","idapro",
]
CHEAT_FEATURES = [
    "killaura","kill aura","xray","x-ray","aimbot","freecam","noclip",
    "autoclicker","auto clicker","scaffold","crystalaura","crystal aura",
    "bhop","triggerbot","aimassist","aim assist","speedhack","speed hack",
    "flyhack","fly hack","autoblock","fastplace","fastbreak","jesus","waterwalk",
]

def classify(name: str) -> str:
    low = name.lower()
    for kw in GHOST_CLIENTS + BYPASS_INDICATORS:
        if kw in low: return "critical"
    for kw in FREE_CLIENTS + DEBUG_TOOLS + CHEAT_FEATURES:
        if kw in low: return "suspicious"
    return ""

SUSPICIOUS_APPDATA_PATHS = ["\\appdata\\", "\\temp\\", "\\roaming\\", "\\downloads\\", "\\local\\temp"]
def flag_path(path: str) -> bool:
    low = path.lower()
    return any(p in low for p in SUSPICIOUS_APPDATA_PATHS)

TRUSTED_DNS = {
    "microsoft.com","windows.com","windowsupdate.com","microsoftonline.com",
    "live.com","bing.com","azure.com","msftncsi.com","msn.com","office.com",
    "google.com","googleapis.com","gstatic.com","youtube.com","googlevideo.com",
    "cloudflare.com","1.1.1.1","8.8.8.8","amazonaws.com","akamai.com",
    "cdn.net","fastly.com","cloudfront.net","minecraft.net","mojang.com",
    "discord.com","discordapp.com","twitch.tv","github.com","githubusercontent.com",
}

def is_trusted_domain(hostname: str) -> bool:
    h = hostname.lower().rstrip(".")
    for td in TRUSTED_DNS:
        if h == td or h.endswith("." + td): return True
    return False

# ── Binary helpers ─────────────────────────────────────────────────────────────
EPOCH_DIFF = 116_444_736_000_000_000

def filetime_to_dt(data) -> datetime | None:
    try:
        ft = struct.unpack_from("<Q", data)[0] if isinstance(data, (bytes, bytearray)) else int(data)
        if ft == 0: return None
        u = ft - EPOCH_DIFF
        if u < 0: return None
        return datetime.fromtimestamp(u / 10_000_000, tz=timezone.utc)
    except Exception:
        return None

def rot13(text: str) -> str:
    r = []
    for c in text:
        if "a" <= c <= "z": r.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif "A" <= c <= "Z": r.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else: r.append(c)
    return "".join(r)

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "unreadable"

def html_esc(s) -> str:
    return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def run_cmd(*args, timeout=15) -> str:
    try:
        return subprocess.check_output(
            list(args), stderr=subprocess.DEVNULL, text=True,
            timeout=timeout, creationflags=0x08000000
        )
    except Exception:
        return ""

def run_ps(cmd: str, timeout=20) -> str:
    try:
        return subprocess.check_output(
            ["powershell","-NonInteractive","-NoProfile","-Command", cmd],
            stderr=subprocess.DEVNULL, text=True,
            timeout=timeout, creationflags=0x08000000
        )
    except Exception:
        return ""

# ── Win10 prefetch decompression (RtlDecompressBuffer) ────────────────────────
def _decompress_mam(data: bytes) -> bytes | None:
    if sys.platform != "win32" or data[:3] != b"MAM":
        return None
    try:
        ntdll = ctypes.windll.ntdll
        uncomp_size = struct.unpack_from("<I", data, 4)[0]
        comp_data   = (ctypes.c_char * len(data[8:]))(*data[8:])
        out_buf     = ctypes.create_string_buffer(uncomp_size)
        final_size  = ctypes.c_ulong(0)
        ws_size     = ctypes.c_ulong(0)
        frag_size   = ctypes.c_ulong(0)
        ntdll.RtlGetCompressionWorkSpaceSize(4, ctypes.byref(ws_size), ctypes.byref(frag_size))
        workspace   = ctypes.create_string_buffer(ws_size.value or 65536)
        rc = ntdll.RtlDecompressBufferEx(
            4, out_buf, uncomp_size, comp_data, len(data[8:]),
            ctypes.byref(final_size), workspace
        )
        if rc == 0:
            return bytes(out_buf[:final_size.value])
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# 1. System info
# ─────────────────────────────────────────────────────────────────────────────
def collect_sysinfo() -> dict:
    uname = os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
    return {
        "hostname":  platform.node(),
        "os":        platform.version(),
        "user":      uname,
        "timestamp": datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "scan_start": datetime.now(tz=timezone.utc),
    }

# ─────────────────────────────────────────────────────────────────────────────
# 2. Prefetch
# ─────────────────────────────────────────────────────────────────────────────
_PF_LAYOUT = {
    17: {"exe_off":0x10,"exe_len":60,"runs_off":0x78,"runs_n":1, "count_off":0x90},
    23: {"exe_off":0x10,"exe_len":60,"runs_off":0x80,"runs_n":8, "count_off":0xD0},
    26: {"exe_off":0x10,"exe_len":60,"runs_off":0x80,"runs_n":8, "count_off":0xD0},
    30: {"exe_off":0x10,"exe_len":60,"runs_off":0x80,"runs_n":8, "count_off":0xD0},
    31: {"exe_off":0x10,"exe_len":60,"runs_off":0x80,"runs_n":8, "count_off":0xD0},
}

SUSPICIOUS_PREFETCH_PATHS = [r"\temp\\", r"\roaming\\", r"\downloads\\", r"\appdata\\local\\temp"]

def _parse_pf(path: str) -> dict | None:
    try:
        raw = Path(path).read_bytes()
    except Exception:
        return None

    data = raw
    compressed = False
    if raw[:3] == b"MAM":
        compressed = True
        data = _decompress_mam(raw)
        if data is None:
            fname = os.path.basename(path).rsplit("-",1)[0]
            return {"exe":fname,"runs":0,"last_run":None,"all_runs":[],"compressed":True,
                    "severity":classify(fname),"from_suspicious_path":False,"file":path}

    if len(data) < 8 or data[4:8] != b"SCCA":
        return None

    try:
        version = struct.unpack_from("<I", data, 0)[0]
        layout  = _PF_LAYOUT.get(version)
        fname   = os.path.basename(path)

        if not layout:
            exe = fname.rsplit("-",1)[0]
            return {"exe":exe,"runs":0,"last_run":None,"all_runs":[],"compressed":compressed,
                    "severity":classify(exe),"from_suspicious_path":False,"file":path}

        exe_raw = data[layout["exe_off"]:layout["exe_off"]+layout["exe_len"]]
        exe     = exe_raw.decode("utf-16-le",errors="replace").rstrip("\x00") or fname

        runs = 0
        if len(data) >= layout["count_off"] + 4:
            runs = struct.unpack_from("<I", data, layout["count_off"])[0]

        all_runs = []
        for i in range(layout["runs_n"]):
            off = layout["runs_off"] + i*8
            if len(data) < off+8: break
            dt = filetime_to_dt(data[off:off+8])
            if dt: all_runs.append(dt)
        all_runs = sorted(set(all_runs), reverse=True)
        last_run = all_runs[0] if all_runs else None

        # Try to detect if this exe ran from a suspicious path by reading the volume info section
        # (best-effort: check string table in the prefetch file)
        from_susp = False
        try:
            text_blob = data.decode("utf-16-le", errors="ignore").lower()
            from_susp = any(p in text_blob for p in SUSPICIOUS_PREFETCH_PATHS)
        except Exception:
            pass

        sev = classify(exe)
        if from_susp and not sev:
            sev = "suspicious"

        if last_run:
            add_event(last_run, "prefetch", exe, sev or "info")

        return {"exe":exe,"runs":runs,"last_run":last_run,"all_runs":all_runs,
                "compressed":compressed,"severity":sev,
                "from_suspicious_path":from_susp,"file":path}
    except Exception:
        return None

def detect_pf_clusters(entries: list[dict], window_s=60) -> list[list[dict]]:
    timed = [(e["last_run"], e) for e in entries if e["last_run"]]
    timed.sort(key=lambda x: x[0])
    clusters, cur = [], []
    for i, (ts, e) in enumerate(timed):
        if not cur or (ts - cur[-1][0]).total_seconds() <= window_s:
            cur.append((ts, e))
        else:
            if len(cur) >= 3: clusters.append([x[1] for x in cur])
            cur = [(ts, e)]
    if len(cur) >= 3: clusters.append([x[1] for x in cur])
    return clusters

def collect_prefetch() -> dict:
    pf_dir = r"C:\Windows\Prefetch"
    if not os.path.isdir(pf_dir):
        return {"entries":[], "clusters":[], "error":"Prefetch folder not found"}
    entries = []
    try:
        for fname in os.listdir(pf_dir):
            if fname.lower().endswith(".pf"):
                r = _parse_pf(os.path.join(pf_dir, fname))
                if r: entries.append(r)
    except PermissionError:
        return {"entries":[], "clusters":[], "error":"Access denied — run as Administrator"}
    except Exception as e:
        return {"entries":[], "clusters":[], "error":str(e)}
    entries.sort(key=lambda x: x["last_run"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    clusters = detect_pf_clusters(entries)
    return {"entries":entries, "clusters":clusters, "error":None}

# ─────────────────────────────────────────────────────────────────────────────
# 3. UserAssist
# ─────────────────────────────────────────────────────────────────────────────
UA_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

def collect_userassist() -> list[dict]:
    if sys.platform != "win32": return []
    entries = []
    try:
        ua_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, UA_PATH)
        gi = 0
        while True:
            try: guid = winreg.EnumKey(ua_key, gi)
            except OSError: break
            gi += 1
            try: ck = winreg.OpenKey(ua_key, f"{guid}\\Count")
            except Exception: continue
            vi = 0
            while True:
                try: name, data, _ = winreg.EnumValue(ck, vi)
                except OSError: break
                vi += 1
                if not isinstance(data, bytes) or len(data) < 8: continue
                decoded   = rot13(name)
                run_count = struct.unpack_from("<I", data, 4)[0] if len(data) >= 8 else 0
                last_run  = filetime_to_dt(data[60:68]) if len(data) >= 68 else None
                sev = classify(decoded)
                if not sev and flag_path(decoded): sev = "suspicious"
                if last_run: add_event(last_run, "userassist", decoded[:80], sev or "info")
                entries.append({"decoded":decoded,"run_count":run_count,
                                "last_run":last_run,"severity":sev})
            ck.Close()
        ua_key.Close()
    except Exception:
        pass
    return entries

# ─────────────────────────────────────────────────────────────────────────────
# 4. Temp folder
# ─────────────────────────────────────────────────────────────────────────────
def collect_temp_folder() -> list[dict]:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    results = []
    dirs_to_scan = list({
        os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
        os.path.expandvars(r"%TEMP%"),
        os.path.expandvars(r"%TMP%"),
    })
    for base in dirs_to_scan:
        if not os.path.isdir(base): continue
        try:
            for item in os.listdir(base):
                fp = os.path.join(base, item)
                try:
                    ct = datetime.fromtimestamp(os.path.getctime(fp), tz=timezone.utc)
                    mt = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)
                    recent = ct >= cutoff or mt >= cutoff
                    sev = classify(item)
                    if not sev and recent: sev = "suspicious"
                    if recent or sev:
                        results.append({"path":fp,"name":item,"created":ct,
                                        "modified":mt,"severity":sev or "info","recent":recent})
                        if sev: add_event(ct, "temp", fp, sev)
                except Exception:
                    pass
        except Exception:
            pass
    return sorted(results, key=lambda x: x["created"], reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# 5. cscui.dll check
# ─────────────────────────────────────────────────────────────────────────────
def collect_cscui_dll() -> dict:
    path = r"C:\Windows\System32\cscui.dll"
    result = {"path":path,"exists":False,"modified":None,"sig_status":"unknown","severity":"info"}
    if not os.path.isfile(path):
        result["severity"] = "suspicious"
        result["sig_status"] = "FILE MISSING"
        return result
    result["exists"] = True
    try:
        mt = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
        result["modified"] = mt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass
    sig = run_ps(f"(Get-AuthenticodeSignature '{path}').Status", timeout=15).strip()
    result["sig_status"] = sig or "unknown"
    if sig in ("HashMismatch", "NotSigned", "UnknownError"):
        result["severity"] = "critical"
        add_event(datetime.now(tz=timezone.utc), "cscui", f"cscui.dll signature: {sig}", "critical")
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 6. Security configuration
# ─────────────────────────────────────────────────────────────────────────────
def _reg_dword(hive, key_path: str, value_name: str) -> int | None:
    if sys.platform != "win32": return None
    try:
        k = winreg.OpenKey(hive, key_path)
        val, _ = winreg.QueryValueEx(k, value_name)
        k.Close()
        return int(val)
    except Exception:
        return None

def collect_security_config() -> dict:
    cfg = {}

    # Secure Boot
    sb = run_ps("Confirm-SecureBootUEFI", timeout=10).strip().lower()
    if "true" in sb:   cfg["secure_boot"] = True
    elif "false" in sb: cfg["secure_boot"] = False
    else:               cfg["secure_boot"] = None  # BIOS / unknown

    # Memory Integrity (Hypervisor-Protected Code Integrity)
    hpci = _reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled"
    )
    cfg["memory_integrity"] = bool(hpci) if hpci is not None else None

    # Fast Boot
    fb = _reg_dword(
        winreg.HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
        "HiberbootEnabled"
    )
    cfg["fast_boot"] = bool(fb) if fb is not None else None

    return cfg

# ─────────────────────────────────────────────────────────────────────────────
# 7. PowerShell history
# ─────────────────────────────────────────────────────────────────────────────
def collect_ps_history() -> list[str]:
    history_file = os.path.expandvars(
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )
    if not os.path.isfile(history_file):
        return []
    try:
        lines = Path(history_file).read_text(encoding="utf-8", errors="replace").splitlines()
        return [l.strip() for l in lines if l.strip()]
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# 8. DNS cache
# ─────────────────────────────────────────────────────────────────────────────
def collect_dns_cache() -> list[dict]:
    raw = run_cmd("ipconfig", "/displaydns", timeout=20)
    if not raw: return []
    records = []
    current_name = None
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(r"^-+$", line)
        if m: current_name = None; continue
        m = re.match(r"^Record Name[.\s]+:\s+(.+)$", line, re.IGNORECASE)
        if m: current_name = m.group(1).strip(); continue
        m = re.match(r"^A \(Host\) Record[.\s]+:\s+(.+)$", line, re.IGNORECASE)
        if m and current_name:
            ip = m.group(1).strip()
            trusted = is_trusted_domain(current_name)
            records.append({"hostname":current_name,"ip":ip,"trusted":trusted,
                            "severity":"info" if trusted else "suspicious"})
            current_name = None
    # deduplicate by hostname
    seen = set()
    deduped = []
    for r in records:
        if r["hostname"] not in seen:
            seen.add(r["hostname"])
            deduped.append(r)
    return sorted(deduped, key=lambda x: (x["trusted"], x["hostname"]))

# ─────────────────────────────────────────────────────────────────────────────
# 9. Windows Event Logs (4663, 4656, 4658 — file/DLL access)
# ─────────────────────────────────────────────────────────────────────────────
def collect_event_logs() -> list[dict]:
    query = "*[System[(EventID=4663 or EventID=4656 or EventID=4658)]]"
    raw = run_cmd("wevtutil", "qe", "Security",
                  f"/q:{query}", "/c:100", "/f:text", "/rd:true", timeout=30)
    if not raw: return []
    events = []
    cur: dict = {}
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("Event["):
            if cur: events.append(cur)
            cur = {}
        m = re.match(r"^Date:\s+(.+)$", line, re.IGNORECASE)
        if m: cur["timestamp"] = m.group(1).strip()
        m = re.match(r"^Event ID:\s+(\d+)$", line, re.IGNORECASE)
        if m: cur["event_id"] = m.group(1)
        m = re.match(r"^Object Name:\s+(.+)$", line, re.IGNORECASE)
        if m: cur["object"] = m.group(1).strip()
        m = re.match(r"^Process Name:\s+(.+)$", line, re.IGNORECASE)
        if m: cur["process"] = m.group(1).strip()
        m = re.match(r"^Account Name:\s+(.+)$", line, re.IGNORECASE)
        if m and "account" not in cur: cur["account"] = m.group(1).strip()
    if cur: events.append(cur)

    results = []
    for ev in events:
        obj = ev.get("object","")
        if not obj: continue
        sev = "info"
        if ".dll" in obj.lower() or ".exe" in obj.lower():
            sev = "suspicious"
        results.append({**ev, "severity":sev})
    return results[:50]

# ─────────────────────────────────────────────────────────────────────────────
# 10. AppData new folders (last 24 h)
# ─────────────────────────────────────────────────────────────────────────────
def collect_appdata_new_folders() -> list[dict]:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    results = []
    bases = [
        os.path.expandvars(r"%APPDATA%"),
        os.path.expandvars(r"%LOCALAPPDATA%"),
    ]
    for base in bases:
        if not os.path.isdir(base): continue
        try:
            for item in os.listdir(base):
                fp = os.path.join(base, item)
                if not os.path.isdir(fp): continue
                try:
                    ct = datetime.fromtimestamp(os.path.getctime(fp), tz=timezone.utc)
                    if ct >= cutoff:
                        sev = classify(item) or "suspicious"
                        results.append({"path":fp,"name":item,"created":ct,"severity":sev})
                        add_event(ct, "appdata", fp, sev)
                except Exception:
                    pass
        except Exception:
            pass
    return sorted(results, key=lambda x: x["created"], reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# 11. Drive scan — .dll / .exe modified last 24 h (outside System32 / PF)
# ─────────────────────────────────────────────────────────────────────────────
_SKIP_DIR_NAMES = {
    "windows","program files","program files (x86)","$recycle.bin",
    "system volume information","windows.old","programdata",
    "perflogs","intel","amd","nvidia",
}
_SKIP_DIR_FRAGMENTS = ["\\windows\\", "\\program files", "\\system32\\", "\\syswow64\\"]

def collect_drive_scan() -> list[dict]:
    cutoff   = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    deadline = time.time() + 120
    target   = {".dll", ".exe"}
    results  = []

    drives = [f"{l}:\\" for l in "CDEFGHIJKLMNOPQRSTUVWXYZ"
              if sys.platform=="win32" and os.path.exists(f"{l}:\\")]
    if sys.platform == "win32" and os.path.exists("C:\\"):
        drives = ["C:\\"] + [d for d in drives if d != "C:\\"]

    for drive in drives:
        if time.time() > deadline: break
        try:
            for root, dirs, files in os.walk(drive, topdown=True):
                if time.time() > deadline: break
                root_low = root.lower()
                # Prune system directories
                if any(f in root_low for f in _SKIP_DIR_FRAGMENTS):
                    dirs[:] = []
                    continue
                dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIR_NAMES]

                for fname in files:
                    if os.path.splitext(fname)[1].lower() not in target: continue
                    fp = os.path.join(root, fname)
                    try:
                        mt = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)
                        if mt < cutoff: continue
                        sev = classify(fname) or "suspicious"
                        results.append({"path":fp,"name":fname,"modified":mt,"severity":sev})
                        add_event(mt, "drive_scan", fp, sev)
                        if len(results) >= 500: return results
                    except Exception:
                        pass
        except Exception:
            pass
    return sorted(results, key=lambda x: x["modified"], reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# 12. Startup registry keys
# ─────────────────────────────────────────────────────────────────────────────
_RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (winreg.HKEY_LOCAL_MACHINE if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (winreg.HKEY_CURRENT_USER if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (winreg.HKEY_CURRENT_USER if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
]

def collect_startup_keys() -> list[dict]:
    if sys.platform != "win32": return []
    results = []
    for hive, key_path, hive_name in _RUN_KEYS:
        if hive is None: continue
        try:
            k = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try: name, value, _ = winreg.EnumValue(k, i)
                except OSError: break
                i += 1
                sev = classify(name) or classify(str(value))
                if not sev and flag_path(str(value)): sev = "suspicious"
                results.append({"hive":hive_name,"name":name,"value":str(value),"severity":sev or "info"})
                if sev: add_event(datetime.now(tz=timezone.utc), "startup", f"{hive_name}: {name} = {value}", sev)
            k.Close()
        except Exception:
            pass
    return results

# ─────────────────────────────────────────────────────────────────────────────
# 13. Recently installed programs
# ─────────────────────────────────────────────────────────────────────────────
_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE if sys.platform=="win32" else None,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER if sys.platform=="win32" else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]

def collect_recently_installed() -> list[dict]:
    if sys.platform != "win32": return []
    cutoff = (datetime.now() - timedelta(days=7)).strftime("%Y%m%d")
    results = []
    seen = set()
    for hive, key_path in _UNINSTALL_KEYS:
        if hive is None: continue
        try:
            k = winreg.OpenKey(hive, key_path)
            i = 0
            while True:
                try: sub = winreg.EnumKey(k, i)
                except OSError: break
                i += 1
                try:
                    sk = winreg.OpenKey(k, sub)
                    def gv(name, default=""):
                        try: v, _ = winreg.QueryValueEx(sk, name); return str(v)
                        except: return default
                    name       = gv("DisplayName")
                    install_dt = gv("InstallDate")
                    publisher  = gv("Publisher")
                    version    = gv("DisplayVersion")
                    sk.Close()
                    if not name or name in seen: continue
                    seen.add(name)
                    sev = classify(name) or classify(publisher)
                    results.append({"name":name,"install_date":install_dt,
                                    "publisher":publisher,"version":version,"severity":sev or "info"})
                except Exception:
                    pass
            k.Close()
        except Exception:
            pass
    # Sort by install date descending; unknown dates go last
    results.sort(key=lambda x: x["install_date"] or "00000000", reverse=True)
    return results[:50]

# ─────────────────────────────────────────────────────────────────────────────
# 14. Scheduled tasks (created last 24 h)
# ─────────────────────────────────────────────────────────────────────────────
def collect_scheduled_tasks() -> list[dict]:
    raw = run_cmd("schtasks", "/query", "/fo", "csv", "/v", timeout=30)
    if not raw: return []
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    tasks  = []
    lines  = [l for l in raw.splitlines() if l.strip()]
    if not lines: return []
    headers = [h.strip('"').lower() for h in lines[0].split('","')]
    def idx(name):
        for i,h in enumerate(headers):
            if name in h: return i
        return -1
    i_name   = idx("taskname")
    i_status = idx("status")
    i_last   = idx("last run")
    i_next   = idx("next run")
    i_author = idx("author")
    i_cmd    = idx("task to run")
    for line in lines[1:]:
        parts = [p.strip('"') for p in line.split('","')]
        if len(parts) <= max(i_name,0): continue
        def g(i): return parts[i] if 0 <= i < len(parts) else ""
        name   = g(i_name)
        cmd    = g(i_cmd)
        author = g(i_author)
        sev    = classify(name) or classify(cmd)
        tasks.append({"name":name,"command":cmd,"status":g(i_status),
                      "author":author,"severity":sev or "info"})
        if sev: add_event(datetime.now(tz=timezone.utc), "schtask", f"{name}: {cmd}", sev)
    return tasks[:100]

# ─────────────────────────────────────────────────────────────────────────────
# 15. Windows Defender exclusions
# ─────────────────────────────────────────────────────────────────────────────
_DEFENDER_BASE = r"SOFTWARE\Microsoft\Windows Defender\Exclusions"

def collect_defender_exclusions() -> dict:
    if sys.platform != "win32": return {}
    result = {"paths":[], "extensions":[], "processes":[]}
    for sub, key in [("paths","Paths"),("extensions","Extensions"),("processes","Processes")]:
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, f"{_DEFENDER_BASE}\\{key}")
            i = 0
            while True:
                try: name, _, _ = winreg.EnumValue(k, i)
                except OSError: break
                i += 1
                sev = classify(name) or ("suspicious" if flag_path(name) else "info")
                result[sub].append({"value":name,"severity":sev})
                if sev in ("critical","suspicious"):
                    add_event(datetime.now(tz=timezone.utc), "defender", f"Exclusion: {name}", sev)
            k.Close()
        except Exception:
            pass
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 16. Process list with file paths
# ─────────────────────────────────────────────────────────────────────────────
def collect_processes() -> list[dict]:
    if sys.platform != "win32": return []
    raw = run_cmd("wmic","process","get","Name,ProcessId,ExecutablePath","/format:csv", timeout=20)
    if not raw:
        # Fallback to tasklist
        raw2 = run_cmd("tasklist","/fo","csv","/nh", timeout=15)
        procs = []
        for line in raw2.strip().splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 2:
                name,pid = parts[0],parts[1]
                procs.append({"name":name,"pid":pid,"path":"","severity":classify(name) or "info"})
        return procs

    procs = []
    for line in raw.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4 or parts[1].lower() == "executablepath": continue
        exe_path, name, pid = parts[1], parts[2], parts[3]
        sev = classify(name) or classify(exe_path)
        if not sev and flag_path(exe_path): sev = "suspicious"
        procs.append({"name":name,"pid":pid,"path":exe_path,"severity":sev or "info"})
        if sev in ("critical","suspicious"):
            add_event(datetime.now(tz=timezone.utc), "process", f"{name} (PID {pid}) {exe_path}", sev)
    return sorted(procs, key=lambda x: (x["severity"]!="critical", x["severity"]!="suspicious", x["name"].lower()))

# ─────────────────────────────────────────────────────────────────────────────
# 17. Hosts file
# ─────────────────────────────────────────────────────────────────────────────
def collect_hosts_file() -> list[dict]:
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    results = []
    try:
        lines = Path(hosts_path).read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"): continue
            parts = stripped.split()
            if len(parts) < 2: continue
            ip, *hostnames = parts
            for h in hostnames:
                if h.startswith("#"): break
                sev = "info" if is_trusted_domain(h) else "suspicious"
                # localhost entries are normal
                if ip in ("127.0.0.1","::1","0.0.0.0") and h in ("localhost","localhost.localdomain"):
                    continue
                results.append({"ip":ip,"hostname":h,"severity":sev})
                if sev == "suspicious":
                    add_event(datetime.now(tz=timezone.utc), "hosts", f"{ip} -> {h}", sev)
    except Exception:
        pass
    return results

# ─────────────────────────────────────────────────────────────────────────────
# 18. Windows Services
# ─────────────────────────────────────────────────────────────────────────────

# Services that must be running — flag as CRITICAL if stopped or disabled.
# Disabling these is a common tactic to reduce forensic evidence or prevent detection.
_MUST_RUN_SVCS = {
    # ── User-specified critical services ─────────────────────────────────────
    "pcasvc":      "Program Compatibility Assistant — tracks program execution history; disabling removes execution evidence",
    "sysmain":     "SysMain (Superfetch) — maintains prefetch/usage data used in forensics; disabling reduces evidence",
    "dps":         "Diagnostic Policy Service — required for Windows diagnostics and event collection",
    "eventlog":    "Windows Event Log — CRITICAL: disabling this erases all event evidence",
    "dcomlaunch":  "DCOM Server Process Launcher — core Windows infrastructure, rarely disabled legitimately",
    "cdpsvc":      "Connected Devices Platform Service — manages activity timeline and device cache",
    # ── Additional security-critical services ────────────────────────────────
    "windefend":   "Windows Defender Antivirus",
    "wscsvc":      "Windows Security Center",
    "mpssvc":      "Windows Firewall",
    "wuauserv":    "Windows Update",
    "winmgmt":     "Windows Management Instrumentation (WMI)",
    "securityhealthservice": "Windows Security Health Service",
}

# Per-user services: Windows appends a random hex suffix (e.g. CDPUserSvc_1a2b3c).
# Match by prefix so both the template and live instances are caught.
_MUST_RUN_PREFIXES = {
    "cdpusersvc":  "Connected Devices Platform User Service — tracks user device activity and Windows Timeline (ActivitiesCache.db); part of the user-specified 'CDPU_' check",
    "userdatasvc": "User Data Access Service — stores and serves Windows activity/timeline cache (ActivitiesCache.db)",
}

# Services that are suspicious when actively RUNNING
_SUSP_IF_RUNNING_SVCS = {
    "remoteregistry":  "Allows remote registry modification — rarely needed on a gaming PC",
    "tlntsvr":         "Telnet server — insecure legacy service",
    "winrm":           "Windows Remote Management — enables remote code execution",
    "rpclocator":      "Legacy RPC locator — not needed on modern Windows",
    "tapisrv":         "Telephony API — uncommon, sometimes abused",
}

def collect_services() -> list[dict]:
    if sys.platform != "win32": return []
    raw = run_ps(
        "Get-WmiObject Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName | "
        "ConvertTo-Csv -NoTypeInformation",
        timeout=30,
    )
    results = []
    if not raw:
        return results
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("#TYPE")]
    if len(lines) < 2:
        return results
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        name      = (row.get("Name") or "").strip()
        display   = (row.get("DisplayName") or "").strip()
        state     = (row.get("State") or "").strip()
        startmode = (row.get("StartMode") or "").strip()
        path      = (row.get("PathName") or "").strip()
        nlow      = name.lower()

        sev   = "info"
        notes = []

        # Running from a user-writable / suspicious path → critical
        if path and flag_path(path):
            sev = "critical"
            notes.append("runs from suspicious path (AppData/Temp/Roaming/Downloads)")

        # Name matches a known cheat / bypass keyword → flag
        name_sev = classify(name) or classify(display)
        if name_sev and name_sev != "info":
            sev = name_sev
            notes.append(f"flagged keyword: {name_sev}")

        # Critical service stopped or disabled — exact name match
        if nlow in _MUST_RUN_SVCS:
            if state.lower() in ("stopped", "paused", "pause pending") or startmode.lower() == "disabled":
                sev = "critical"
                notes.append(_MUST_RUN_SVCS[nlow])

        # Critical service stopped or disabled — prefix match for per-user instances
        # (e.g. CDPUserSvc_1a2b3c, UserDataSvc_1a2b3c)
        if sev != "critical":
            for prefix, note in _MUST_RUN_PREFIXES.items():
                if nlow.startswith(prefix):
                    if state.lower() in ("stopped", "paused", "pause pending") or startmode.lower() == "disabled":
                        sev = "critical"
                        notes.append(note)
                    break

        # Suspicious service is actively running
        if nlow in _SUSP_IF_RUNNING_SVCS and state.lower() == "running":
            if sev == "info":
                sev = "suspicious"
            notes.append(_SUSP_IF_RUNNING_SVCS[nlow])

        results.append({
            "name":      name,
            "display":   display,
            "state":     state,
            "startmode": startmode,
            "path":      path,
            "notes":     "; ".join(notes),
            "severity":  sev,
        })
        if sev in ("critical", "suspicious"):
            add_event(datetime.now(tz=timezone.utc), "service",
                      f"{name} ({display}) — {state} / {startmode}", sev)

    return sorted(results, key=lambda x: (
        x["severity"] != "critical", x["severity"] != "suspicious", x["name"].lower()
    ))

# ─────────────────────────────────────────────────────────────────────────────
# 19. Drive Filesystems
# ─────────────────────────────────────────────────────────────────────────────

_DRIVE_TYPE_NAMES = {
    0: "Unknown", 1: "No Root Dir", 2: "Removable",
    3: "Local Disk", 4: "Network Drive", 5: "CD/DVD", 6: "RAM Disk",
}

def collect_drives() -> list[dict]:
    if sys.platform != "win32": return []
    raw = run_ps(
        "Get-WmiObject Win32_LogicalDisk | "
        "Select-Object DeviceID,FileSystem,Size,FreeSpace,DriveType,Description,VolumeName | "
        "ConvertTo-Csv -NoTypeInformation",
        timeout=20,
    )
    results = []
    if not raw:
        return results
    lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("#TYPE")]
    if len(lines) < 2:
        return results
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    for row in reader:
        device  = (row.get("DeviceID") or "").strip()
        fs      = (row.get("FileSystem") or "").strip().upper()
        desc    = (row.get("Description") or "").strip()
        volname = (row.get("VolumeName") or "").strip()
        dtype_s = (row.get("DriveType") or "0").strip()
        dtype   = int(dtype_s) if dtype_s.isdigit() else 0
        dtype_n = _DRIVE_TYPE_NAMES.get(dtype, str(dtype))

        try: size_gb = round(int(row.get("Size") or 0) / 1_073_741_824, 2)
        except: size_gb = None
        try: free_gb = round(int(row.get("FreeSpace") or 0) / 1_073_741_824, 2)
        except: free_gb = None

        sev   = "info"
        notes = []

        if dtype == 3:  # Fixed local disk
            if fs == "FAT32":
                sev = "suspicious"
                notes.append("FAT32 on fixed drive — no NTFS journaling, no ACLs, evidence doesn't persist reliably")
            elif fs == "EXFAT":
                sev = "suspicious"
                notes.append("exFAT on fixed drive — no NTFS permissions or journaling")
            elif fs and fs not in ("NTFS", "REFS"):
                sev = "suspicious"
                notes.append(f"Non-standard filesystem on fixed drive: {fs}")
        elif dtype == 2:  # Removable
            if fs in ("FAT32", "EXFAT"):
                notes.append(f"Removable drive ({fs}) — common for USB sticks")

        results.append({
            "device":   device,
            "fs":       fs or "Unknown",
            "type":     dtype_n,
            "type_num": dtype,
            "desc":     desc,
            "volname":  volname,
            "size_gb":  size_gb,
            "free_gb":  free_gb,
            "notes":    "; ".join(notes),
            "severity": sev,
        })
        if sev in ("critical", "suspicious"):
            add_event(datetime.now(tz=timezone.utc), "drive",
                      f"{device} — {fs} ({dtype_n}) {'; '.join(notes)}", sev)

    return results

# ─────────────────────────────────────────────────────────────────────────────
# 20. Minecraft — accounts
# ─────────────────────────────────────────────────────────────────────────────
_MC_LAUNCHERS = {
    "Vanilla":    [os.path.expandvars(r"%APPDATA%\.minecraft")],
    "MultiMC":    [os.path.expandvars(r"%APPDATA%\MultiMC")],
    "Prism":      [os.path.expandvars(r"%APPDATA%\PrismLauncher")],
    "GDLauncher": [os.path.expandvars(r"%APPDATA%\gdlauncher"),
                   os.path.expandvars(r"%APPDATA%\gdlauncher_carbon")],
    "ATLauncher": [os.path.expandvars(r"%APPDATA%\ATLauncher")],
    "Badlion":    [os.path.expandvars(r"%APPDATA%\.bmc"),
                   os.path.expandvars(r"%APPDATA%\Badlion Client")],
    "Lunar":      [os.path.expandvars(r"%USERPROFILE%\.lunarclient")],
    "CurseForge": [os.path.expandvars(r"%APPDATA%\.curseforge")],
}

def _read_json_safe(path: str) -> dict | list | None:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None

def _extract_accounts_from_json(data, launcher: str) -> list[dict]:
    accounts = []
    if not data: return accounts

    # Vanilla launcher_accounts.json
    if isinstance(data, dict) and "accounts" in data:
        accs = data["accounts"]
        if isinstance(accs, dict):
            for uid, acc in accs.items():
                accounts.append({
                    "launcher": launcher,
                    "username": acc.get("minecraftProfile",{}).get("name") or acc.get("username","?"),
                    "uuid":     acc.get("minecraftProfile",{}).get("id") or uid,
                    "type":     acc.get("type","unknown"),
                })
        elif isinstance(accs, list):
            for acc in accs:
                if not isinstance(acc, dict): continue
                accounts.append({
                    "launcher": launcher,
                    "username": acc.get("name") or acc.get("username","?"),
                    "uuid":     acc.get("uuid") or acc.get("id","?"),
                    "type":     acc.get("type","unknown"),
                })
    # MultiMC / Prism accounts.json
    elif isinstance(data, dict) and "accounts" not in data and "profiles" not in data:
        for uid, prof in data.items():
            if isinstance(prof, dict) and ("name" in prof or "displayName" in prof):
                accounts.append({
                    "launcher": launcher,
                    "username": prof.get("name") or prof.get("displayName","?"),
                    "uuid":     uid,
                    "type":     prof.get("type","unknown"),
                })
    # launcher_profiles.json
    elif isinstance(data, dict) and "authenticationDatabase" in data:
        for uid, prof in data["authenticationDatabase"].items():
            accounts.append({
                "launcher": launcher,
                "username": prof.get("displayName","?"),
                "uuid":     uid,
                "type":     "authDatabase",
            })
    return accounts

def collect_minecraft_accounts() -> list[dict]:
    all_accounts = []
    account_files = [
        "launcher_accounts.json", "launcher_profiles.json",
        "accounts.json",
    ]
    for launcher, dirs in _MC_LAUNCHERS.items():
        for d in dirs:
            if not os.path.isdir(d): continue
            for af in account_files:
                fp = os.path.join(d, af)
                if os.path.isfile(fp):
                    data = _read_json_safe(fp)
                    accs = _extract_accounts_from_json(data, launcher)
                    all_accounts.extend(accs)
            # Lunar has a nested path
            nested = os.path.join(d, "settings", "game", "accounts.json")
            if os.path.isfile(nested):
                data = _read_json_safe(nested)
                accs = _extract_accounts_from_json(data, launcher)
                all_accounts.extend(accs)
    # Deduplicate by UUID
    seen_uuid = set()
    deduped = []
    for a in all_accounts:
        key = a.get("uuid","?")
        if key not in seen_uuid:
            seen_uuid.add(key)
            deduped.append(a)
    return deduped

# ─────────────────────────────────────────────────────────────────────────────
# 19. Minecraft — installed clients, versions, mods
# ─────────────────────────────────────────────────────────────────────────────
_KNOWN_CLIENT_FOLDERS = {
    "Vanilla":       os.path.expandvars(r"%APPDATA%\.minecraft"),
    "Lunar Client":  os.path.expandvars(r"%USERPROFILE%\.lunarclient"),
    "Badlion":       os.path.expandvars(r"%APPDATA%\.bmc"),
    "Feather":       os.path.expandvars(r"%APPDATA%\.feather"),
    "CheatBreaker":  os.path.expandvars(r"%APPDATA%\.cheatbreaker"),
    "MultiMC":       os.path.expandvars(r"%APPDATA%\MultiMC"),
    "Prism":         os.path.expandvars(r"%APPDATA%\PrismLauncher"),
}

_CHEAT_MC_FOLDERS = [
    ".weave","Vape","VapeV4","Impact","Aristois","wurst","LiquidBounce",
    "meteor-client","Future","Sigma","Ares","Novoline","Remix","Rise",
    "Exhibition","Astolfo","Vertex","Flux","Quasar","Drip","DripX",
    "Stardust","Atom","Reflex","Ember","Boze","Solis","Fentanyl",
    "Pyro","Azura","Gorilla","Zephyr","Tenacity","Eagle","Albedo",
    "Cheeto","Monsoon","Motion","Inertia","Autumn","Entropy","Hybrid",
    "RusherHack","BlackOut","Luma","GhostClient","WeaveLoader",
]

def collect_minecraft_clients() -> dict:
    mc_base = os.path.expandvars(r"%APPDATA%\.minecraft")
    result = {
        "installed_launchers": [],
        "versions": [],
        "cheat_folders": [],
        "mods": [],
        "non_standard_files": [],
        "recent_jars": [],
    }

    # Installed launchers
    for name, folder in _KNOWN_CLIENT_FOLDERS.items():
        if os.path.isdir(folder):
            result["installed_launchers"].append({"name":name,"path":folder,"severity":classify(name) or "info"})

    if not os.path.isdir(mc_base):
        return result

    # Versions
    versions_dir = os.path.join(mc_base, "versions")
    if os.path.isdir(versions_dir):
        result["versions"] = sorted([
            v for v in os.listdir(versions_dir)
            if os.path.isdir(os.path.join(versions_dir, v))
        ])

    # Mods
    mods_dir = os.path.join(mc_base, "mods")
    if os.path.isdir(mods_dir):
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=7)
        for fname in os.listdir(mods_dir):
            fp = os.path.join(mods_dir, fname)
            try: size = os.path.getsize(fp)
            except: size = 0
            try: mt = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)
            except: mt = None
            sev = classify(fname) or "info"
            result["mods"].append({"name":fname,"size":size,"modified":mt,"severity":sev})
            if sev in ("critical","suspicious"):
                add_event(mt or datetime.now(tz=timezone.utc), "minecraft_mod", fname, sev)

    # Cheat client folders inside .minecraft
    for cf in _CHEAT_MC_FOLDERS:
        fp = os.path.join(mc_base, cf)
        if os.path.exists(fp):
            sev = classify(cf) or "critical"
            result["cheat_folders"].append({"name":cf,"path":fp,"severity":sev})
            add_event(datetime.now(tz=timezone.utc), "minecraft_cheat", fp, sev)

    # Non-standard jars in .minecraft root
    cutoff_24h = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    standard_dirs = {"versions","mods","resourcepacks","saves","logs","config","crash-reports","lib","libraries","assets","bin","runtime","jre","jdk","launcher"}
    for fname in os.listdir(mc_base):
        fp = os.path.join(mc_base, fname)
        if os.path.isfile(fp) and fname.lower().endswith(".jar"):
            sev = classify(fname) or "suspicious"
            result["non_standard_files"].append({"name":fname,"path":fp,"severity":sev})
            add_event(datetime.now(tz=timezone.utc), "minecraft_jar", fp, sev)
        elif os.path.isfile(fp):
            try:
                mt = datetime.fromtimestamp(os.path.getmtime(fp), tz=timezone.utc)
                if mt >= cutoff_24h:
                    sev = classify(fname) or "info"
                    result["recent_jars"].append({"name":fname,"path":fp,"modified":mt,"severity":sev})
            except Exception:
                pass

    return result

# ─────────────────────────────────────────────────────────────────────────────
# 20. Minecraft — recently deleted files (from Recycle Bin metadata)
# ─────────────────────────────────────────────────────────────────────────────
def collect_mc_deleted_files() -> list[dict]:
    results = []
    cutoff  = datetime.now(tz=timezone.utc) - timedelta(days=7)
    for drive in ["C", "D", "E"]:
        rbin = rf"{drive}:\$Recycle.Bin"
        if not os.path.isdir(rbin): continue
        try:
            for user_sid in os.listdir(rbin):
                sid_path = os.path.join(rbin, user_sid)
                if not os.path.isdir(sid_path): continue
                for fname in os.listdir(sid_path):
                    # $I files contain metadata (original path, delete time)
                    if not fname.upper().startswith("$I"): continue
                    meta_path = os.path.join(sid_path, fname)
                    try:
                        data = Path(meta_path).read_bytes()
                        if len(data) < 28: continue
                        ft      = struct.unpack_from("<Q", data, 16)[0]
                        del_dt  = filetime_to_dt(struct.pack("<Q", ft))
                        # Original path at offset 28 (UTF-16)
                        orig    = data[28:].decode("utf-16-le", errors="replace").rstrip("\x00")
                        mc_kw   = ["minecraft","\.mc","mojang","lunar","badlion",".jar",".pf"]
                        if any(kw in orig.lower() for kw in mc_kw):
                            sev = classify(orig) or "suspicious"
                            if del_dt and del_dt >= cutoff:
                                results.append({"original_path":orig,"deleted":del_dt,"severity":sev})
                                add_event(del_dt, "deleted_file", orig, sev)
                    except Exception:
                        pass
        except Exception:
            pass
    return sorted(results, key=lambda x: x["deleted"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

# ─────────────────────────────────────────────────────────────────────────────
# 21. Discord — accounts via LevelDB scan
# ─────────────────────────────────────────────────────────────────────────────
_DISCORD_INSTALLS = {
    "Discord":     os.path.expandvars(r"%APPDATA%\discord\Local Storage\leveldb"),
    "Discord PTB": os.path.expandvars(r"%APPDATA%\discordptb\Local Storage\leveldb"),
    "Discord Canary": os.path.expandvars(r"%APPDATA%\discordcanary\Local Storage\leveldb"),
}

_USER_PAT   = re.compile(rb'"id"\s*:\s*"(\d{17,20})"[^}]{0,300}"username"\s*:\s*"([^"]{1,50})"', re.DOTALL)
_USER_PAT2  = re.compile(rb'"username"\s*:\s*"([^"]{1,50})"[^}]{0,300}"id"\s*:\s*"(\d{17,20})"', re.DOTALL)
_GLOBAL_PAT = re.compile(rb'"global_name"\s*:\s*"([^"]{1,50})"')

def _scan_leveldb_for_users(leveldb_path: str) -> list[dict]:
    users = {}
    if not os.path.isdir(leveldb_path): return []
    for ext in ["*.ldb", "*.log"]:
        for fpath in Path(leveldb_path).glob(ext):
            try:
                data = fpath.read_bytes()
                for m in _USER_PAT.finditer(data):
                    uid   = m.group(1).decode("utf-8", errors="replace")
                    uname = m.group(2).decode("utf-8", errors="replace")
                    users[uid] = {"id":uid,"username":uname}
                for m in _USER_PAT2.finditer(data):
                    uname = m.group(1).decode("utf-8", errors="replace")
                    uid   = m.group(2).decode("utf-8", errors="replace")
                    if uid not in users:
                        users[uid] = {"id":uid,"username":uname}
            except Exception:
                pass
    return list(users.values())

def collect_discord_accounts() -> dict:
    result = {}
    for install_name, ldb_path in _DISCORD_INSTALLS.items():
        users = _scan_leveldb_for_users(ldb_path)
        if users:
            result[install_name] = users
    return result

# ─────────────────────────────────────────────────────────────────────────────
# 22. Discord — injection detection
# ─────────────────────────────────────────────────────────────────────────────
_DISCORD_APP_DIRS = {
    "Discord":        os.path.expandvars(r"%APPDATA%\discord"),
    "Discord PTB":    os.path.expandvars(r"%APPDATA%\discordptb"),
    "Discord Canary": os.path.expandvars(r"%APPDATA%\discordcanary"),
}
_INJECTION_PATTERNS = [
    b"require('https'", b"require('http'", b"XMLHttpRequest",
    b"fetch(", b"token", b"localStorage", b"getItem(",
    b"webhook", b"discord.com/api/webhooks",
    b"eval(", b"Function(",
]

def _find_discord_core_index(base_dir: str) -> str | None:
    if not os.path.isdir(base_dir): return None
    # Look for app-*/modules/discord_desktop_core*/discord_desktop_core/index.js
    for app_dir in sorted(Path(base_dir).glob("app-*"), reverse=True):
        for core_dir in sorted(app_dir.glob("modules/discord_desktop_core*/discord_desktop_core"), reverse=True):
            idx = core_dir / "index.js"
            if idx.exists(): return str(idx)
    return None

def collect_discord_injection() -> list[dict]:
    results = []
    for name, base in _DISCORD_APP_DIRS.items():
        idx_path = _find_discord_core_index(base)
        if not idx_path: continue
        try:
            content = Path(idx_path).read_bytes()
            # Vanilla Discord core index.js is typically < 200 bytes: module.exports = require('./core');
            vanilla_size_threshold = 500
            is_large = len(content) > vanilla_size_threshold
            hits = [p.decode("utf-8","replace") for p in _INJECTION_PATTERNS if p in content]
            if is_large or hits:
                sev = "critical" if (hits and is_large) else "suspicious"
                results.append({
                    "install": name,
                    "path": idx_path,
                    "file_size": len(content),
                    "suspicious_patterns": hits,
                    "severity": sev,
                })
                add_event(datetime.now(tz=timezone.utc), "discord_inject",
                          f"{name} core injected ({len(hits)} patterns)", sev)
        except Exception:
            pass
    return results

# ─────────────────────────────────────────────────────────────────────────────
# Risk score
# ─────────────────────────────────────────────────────────────────────────────
def calc_risk_score(data: dict) -> int:
    score = 0

    def count_sev(items, sev):
        if isinstance(items, list):
            return sum(1 for x in items if isinstance(x,dict) and x.get("severity")==sev)
        return 0

    # Prefetch
    pf_entries = data.get("prefetch",{}).get("entries",[])
    score += min(30, count_sev(pf_entries,"critical") * 10)
    score += min(10, count_sev(pf_entries,"suspicious") * 3)
    if data.get("prefetch",{}).get("clusters"): score += 8

    # UserAssist
    score += min(20, count_sev(data.get("userassist",[]),"critical") * 8)
    score += min(8,  count_sev(data.get("userassist",[]),"suspicious") * 2)

    # Processes
    score += min(25, count_sev(data.get("processes",[]),"critical") * 12)
    score += min(10, count_sev(data.get("processes",[]),"suspicious") * 3)

    # Minecraft
    mc = data.get("minecraft",{})
    score += min(20, len(mc.get("cheat_folders",[])) * 10)
    score += min(10, count_sev(mc.get("mods",[]),"critical") * 5)

    # Discord injection
    score += min(15, len(data.get("discord_injection",[])) * 15)

    # Security config
    cfg = data.get("security_config",{})
    if cfg.get("secure_boot") is False:       score += 5
    if cfg.get("memory_integrity") is False:  score += 3

    # Startup
    score += min(10, count_sev(data.get("startup_keys",[]),"critical") * 5)
    score += min(5,  count_sev(data.get("startup_keys",[]),"suspicious") * 2)

    # Defender exclusions
    excl = data.get("defender_exclusions",{})
    for key in ["paths","extensions","processes"]:
        score += min(10, count_sev(excl.get(key,[]),"suspicious") * 3 + count_sev(excl.get(key,[]),"critical") * 5)

    # cscui
    if data.get("cscui",{}).get("severity") == "critical": score += 10

    return min(100, score)

# ─────────────────────────────────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────────────────────────────────
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#0d1117;color:#c9d1d9;font-size:14px;line-height:1.6}
a{color:#58a6ff}
.hdr{background:linear-gradient(135deg,#161b22,#21262d);padding:24px 32px;border-bottom:2px solid #30363d;display:flex;align-items:center;gap:28px;flex-wrap:wrap}
.risk-circle{width:96px;height:96px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;font-weight:700;flex-shrink:0;border:3px solid}
.rc-critical{background:radial-gradient(circle,#4d0a0a,#1a0505);border-color:#e74c3c;color:#ff6b6b}
.rc-high{background:radial-gradient(circle,#4d2a0a,#1a0e05);border-color:#e67e22;color:#ffa040}
.rc-medium{background:radial-gradient(circle,#3d380a,#151205);border-color:#f1c40f;color:#ffd740}
.rc-low{background:radial-gradient(circle,#0a3d1a,#051508);border-color:#2ecc71;color:#69db7c}
.risk-num{font-size:30px;line-height:1}
.risk-lbl{font-size:11px;opacity:.75;margin-top:2px}
.hdr-meta h1{font-size:20px;color:#f0f6fc;margin-bottom:6px}
.hdr-meta p{color:#8b949e;font-size:13px;margin:1px 0}
.stats{background:#161b22;padding:12px 32px;border-bottom:1px solid #30363d;display:flex;gap:16px;flex-wrap:wrap}
.sb{padding:4px 14px;border-radius:16px;font-size:12px;font-weight:700}
.sb-c{background:#2d0a0a;color:#ff6b6b;border:1px solid #c0392b}
.sb-s{background:#2d1a0a;color:#ffa040;border:1px solid #e67e22}
.sb-ok{background:#0a2d12;color:#69db7c;border:1px solid #27ae60}
.sb-i{background:#0a1a2d;color:#58a6ff;border:1px solid #1a6eb5}
.content{max-width:1300px;margin:0 auto;padding:20px 28px}
details{margin-bottom:10px}
summary{cursor:pointer;padding:11px 18px;background:#161b22;border:1px solid #30363d;border-radius:8px;font-weight:600;font-size:14px;color:#f0f6fc;user-select:none;list-style:none;display:flex;align-items:center;gap:8px}
summary::-webkit-details-marker{display:none}
summary::before{content:'▶';font-size:10px;transition:transform .2s;margin-right:4px;color:#8b949e}
details[open] summary::before{transform:rotate(90deg)}
details[open] summary{border-radius:8px 8px 0 0}
.sbody{background:#0d1117;border:1px solid #30363d;border-top:none;border-radius:0 0 8px 8px;padding:14px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#161b22;color:#8b949e;padding:7px 11px;text-align:left;font-weight:600;border-bottom:1px solid #30363d;white-space:nowrap}
td{padding:7px 11px;border-bottom:1px solid #1c2128;vertical-align:top;word-break:break-all}
tr:hover td{background:#161b22}
tr.rc td{background:rgba(231,76,60,.07);color:#ff8080}
tr.rs td{background:rgba(230,126,34,.07);color:#ffa040}
tr.ri td{color:#8b949e}
.bc{background:#2d0a0a;color:#ff6b6b;border:1px solid #c0392b;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.bs{background:#2d1a0a;color:#ffa040;border:1px solid #e67e22;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.bo{background:#0a2d12;color:#69db7c;border:1px solid #27ae60;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.bi{background:#0a1a2d;color:#58a6ff;border:1px solid #1a6eb5;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;white-space:nowrap}
.none{color:#69db7c;font-style:italic;padding:10px}
.sec-icon{margin-right:4px}
code{background:#161b22;padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;font-size:12px;color:#79c0ff}
.ts{color:#8b949e;font-size:12px}
.summary-section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:16px}
.summary-section h3{color:#f0f6fc;margin-bottom:10px;font-size:15px}
.risk-bar{height:8px;background:#21262d;border-radius:4px;margin-top:8px;overflow:hidden}
.risk-bar-fill{height:100%;border-radius:4px;transition:width .5s}
h2.section-group{color:#8b949e;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:20px 0 8px}
"""

def _badge(sev: str) -> str:
    if sev == "critical":   return '<span class="bc">CRITICAL</span>'
    if sev == "suspicious": return '<span class="bs">SUSPICIOUS</span>'
    if sev == "info":       return '<span class="bi">INFO</span>'
    return '<span class="bo">CLEAN</span>'

def _tr_class(sev: str) -> str:
    if sev == "critical":   return ' class="rc"'
    if sev == "suspicious": return ' class="rs"'
    if sev == "info":       return ' class="ri"'
    return ""

def _fmt_dt(dt) -> str:
    if not dt: return "—"
    if isinstance(dt, datetime): return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    return html_esc(str(dt))

def _section(title: str, icon: str, content: str, has_flags: bool = False) -> str:
    open_attr = " open" if has_flags else ""
    return (f'<details{open_attr}><summary><span class="sec-icon">{icon}</span>{html_esc(title)}</summary>'
            f'<div class="sbody">{content}</div></details>\n')

def _table(headers: list[str], rows: list[list], sev_col_idx: int = -1) -> str:
    if not rows:
        return '<div class="none">✔ No findings</div>'
    ths = "".join(f"<th>{html_esc(h)}</th>" for h in headers)
    trs = ""
    for row in rows:
        sev = row[sev_col_idx] if sev_col_idx >= 0 and sev_col_idx < len(row) else "info"
        cells = "".join(f"<td>{html_esc(c) if not str(c).startswith('<') else c}</td>" for c in row)
        trs += f"<tr{_tr_class(sev)}>{cells}</tr>"
    return f"<table><thead><tr>{ths}</tr></thead><tbody>{trs}</tbody></table>"

def build_html_report(sysinfo: dict, data: dict, risk_score: int) -> str:
    rc_class = "rc-critical" if risk_score >= 75 else ("rc-high" if risk_score >= 50 else ("rc-medium" if risk_score >= 25 else "rc-low"))
    risk_label = "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW"))
    risk_color = "#e74c3c" if risk_score >= 75 else ("#e67e22" if risk_score >= 50 else ("#f1c40f" if risk_score >= 25 else "#2ecc71"))

    # Count all flags
    def cnt(items, sev=None):
        if not isinstance(items, list): return 0
        if sev: return sum(1 for x in items if isinstance(x,dict) and x.get("severity")==sev)
        return sum(1 for x in items if isinstance(x,dict) and x.get("severity") in ("critical","suspicious"))

    total_critical   = (
        cnt(data.get("prefetch",{}).get("entries",[]),"critical") +
        cnt(data.get("userassist",[]),"critical") +
        cnt(data.get("processes",[]),"critical") +
        len(data.get("minecraft",{}).get("cheat_folders",[])) +
        cnt(data.get("minecraft",{}).get("mods",[]),"critical") +
        len(data.get("discord_injection",[]))
    )
    total_suspicious = (
        cnt(data.get("prefetch",{}).get("entries",[]),"suspicious") +
        cnt(data.get("userassist",[]),"suspicious") +
        cnt(data.get("processes",[]),"suspicious") +
        cnt(data.get("startup_keys",[]),"suspicious") +
        cnt(data.get("temp_folder",[]),"suspicious") +
        cnt(data.get("drive_scan",[]),"suspicious")
    )

    stats = (
        f'<span class="sb sb-c">🔴 {total_critical} Critical</span>'
        f'<span class="sb sb-s">🟠 {total_suspicious} Suspicious</span>'
        f'<span class="sb sb-i">📋 {len(TIMELINE)} Timeline Events</span>'
    )

    # Prefetch section
    pf_data    = data.get("prefetch", {})
    pf_entries = pf_data.get("entries", [])
    pf_flagged = [e for e in pf_entries if e.get("severity")]
    pf_clusters = pf_data.get("clusters", [])
    pf_rows    = []
    for e in pf_flagged:
        runs_str = "<br>".join(_fmt_dt(r) for r in (e.get("all_runs") or [])[:3])
        pf_rows.append([
            e["exe"], str(e.get("runs",0)),
            _fmt_dt(e.get("last_run")),
            "Yes" if e.get("from_suspicious_path") else "No",
            "Yes" if e.get("compressed") else "No",
            _badge(e["severity"]), e["severity"]
        ])
    pf_cluster_html = ""
    if pf_clusters:
        pf_cluster_html = f'<div style="margin-bottom:12px;padding:10px;background:#2d1a0a;border-left:3px solid #e67e22;border-radius:4px">⚠ <strong>{len(pf_clusters)} timestamp cluster(s) detected</strong> — multiple files ran within 60 seconds of each other (common cheat launcher pattern).<ul style="margin-top:6px;padding-left:20px">'
        for cluster in pf_clusters:
            names = ", ".join(html_esc(e["exe"]) for e in cluster)
            ts_str = _fmt_dt(cluster[0].get("last_run")) if cluster else "?"
            pf_cluster_html += f"<li>{html_esc(ts_str)}: {names}</li>"
        pf_cluster_html += "</ul></div>"
    pf_content = pf_cluster_html + (pf_data.get("error") and f'<div style="color:#ff6b6b;padding:8px">⚠ {html_esc(pf_data["error"])}</div>' or "") + _table(["EXE Name","Run Count","Last Run (UTC)","Susp. Path","Compressed","Severity","_sev"], pf_rows, 6)

    # UserAssist section
    ua_flagged = [e for e in data.get("userassist",[]) if e.get("severity")]
    ua_rows = [[e["decoded"][:100], str(e.get("run_count",0)), _fmt_dt(e.get("last_run")),
                _badge(e["severity"]), e["severity"]] for e in ua_flagged]
    ua_content = _table(["Decoded Path","Runs","Last Run (UTC)","Severity","_sev"], ua_rows, 4)

    # Temp folder section
    temp_items = [x for x in data.get("temp_folder",[]) if x.get("severity") in ("critical","suspicious")]
    temp_rows  = [[x["path"], _fmt_dt(x.get("created")), _fmt_dt(x.get("modified")),
                   _badge(x["severity"]), x["severity"]] for x in temp_items]
    temp_content = _table(["Path","Created","Modified","Severity","_sev"], temp_rows, 4)

    # Security config
    cfg = data.get("security_config",{})
    def cfg_badge(val):
        if val is True:  return '<span class="bo">ENABLED</span>'
        if val is False: return '<span class="bs">DISABLED</span>'
        return '<span class="bi">UNKNOWN</span>'
    cfg_content = f"""<table>
<thead><tr><th>Setting</th><th>Status</th><th>Notes</th></tr></thead>
<tbody>
<tr><td>Secure Boot</td><td>{cfg_badge(cfg.get('secure_boot'))}</td><td>{'⚠ Unsigned code can run at boot' if cfg.get('secure_boot') is False else ''}</td></tr>
<tr><td>Memory Integrity (VBS/HVCI)</td><td>{cfg_badge(cfg.get('memory_integrity'))}</td><td>{'⚠ Kernel memory unprotected' if cfg.get('memory_integrity') is False else ''}</td></tr>
<tr><td>Fast Boot</td><td>{cfg_badge(cfg.get('fast_boot'))}</td><td>{'Fast Boot enabled — full shutdown bypassed' if cfg.get('fast_boot') is True else ''}</td></tr>
</tbody></table>"""

    # cscui.dll
    cscui = data.get("cscui",{})
    cscui_sev = cscui.get("severity","info")
    cscui_content = f"""<table><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>
<tr><td>Path</td><td><code>{html_esc(cscui.get('path',''))}</code></td></tr>
<tr><td>Exists</td><td>{'Yes' if cscui.get('exists') else '<span class="bc">NO — FILE MISSING</span>'}</td></tr>
<tr><td>Last Modified</td><td>{html_esc(cscui.get('modified','Unknown'))}</td></tr>
<tr><td>Signature Status</td><td>{_badge(cscui_sev)} {html_esc(cscui.get('sig_status','unknown'))}</td></tr>
</tbody></table>"""

    # PowerShell history
    ps_hist = data.get("ps_history",[])
    ps_rows = [[html_esc(cmd)] for cmd in ps_hist[-100:]]
    ps_content = _table(["Command"], ps_rows) if ps_rows else '<div class="none">No PowerShell history found</div>'

    # DNS cache
    dns_untrusted = [r for r in data.get("dns_cache",[]) if not r.get("trusted")]
    dns_rows = [[r["hostname"], r["ip"], _badge(r["severity"]), r["severity"]] for r in dns_untrusted]
    dns_content = f'<p style="color:#8b949e;margin-bottom:10px">Showing {len(dns_untrusted)} non-trusted domains (total cache: {len(data.get("dns_cache",[]))})</p>' + _table(["Hostname","IP","Severity","_sev"], dns_rows, 3)

    # Event logs
    ev_rows = [[e.get("timestamp","?"), e.get("event_id","?"), html_esc(e.get("object","?")),
                html_esc(e.get("process","?")), _badge(e.get("severity","info")), e.get("severity","info")]
               for e in data.get("event_logs",[])[:50]]
    ev_content = _table(["Timestamp","Event ID","Object","Process","Severity","_sev"], ev_rows, 5)

    # AppData new folders
    af_rows = [[x["path"], _fmt_dt(x.get("created")), _badge(x["severity"]), x["severity"]]
               for x in data.get("appdata_new_folders",[])]
    af_content = _table(["Path","Created","Severity","_sev"], af_rows, 3)

    # Drive scan
    ds_items = data.get("drive_scan",[])
    ds_rows  = [[x["path"], _fmt_dt(x.get("modified")), _badge(x["severity"]), x["severity"]]
                for x in ds_items[:200]]
    ds_extra = f'<p style="color:#8b949e;margin-bottom:8px">{len(ds_items)} modified files found</p>' if ds_items else ""
    ds_content = ds_extra + _table(["Path","Modified","Severity","_sev"], ds_rows, 3)

    # Startup keys
    sk_rows = [[r["hive"], html_esc(r["name"]), html_esc(r["value"][:120]),
                _badge(r["severity"]), r["severity"]]
               for r in data.get("startup_keys",[])]
    sk_content = _table(["Hive","Name","Value","Severity","_sev"], sk_rows, 4)

    # Recently installed
    ri_rows = [[html_esc(r["name"]), r.get("install_date","?"), html_esc(r.get("publisher","?")),
                r.get("version","?"), _badge(r["severity"]), r["severity"]]
               for r in data.get("recently_installed",[])]
    ri_content = _table(["Program","Install Date","Publisher","Version","Severity","_sev"], ri_rows, 5)

    # Scheduled tasks
    st_flagged = [t for t in data.get("scheduled_tasks",[]) if t.get("severity") in ("critical","suspicious")]
    st_rows    = [[html_esc(t["name"]), html_esc(t.get("command","?")[:100]),
                   html_esc(t.get("author","?")), _badge(t["severity"]), t["severity"]]
                  for t in st_flagged]
    st_content = _table(["Task Name","Command","Author","Severity","_sev"], st_rows, 4)

    # Defender exclusions
    excl = data.get("defender_exclusions",{})
    def excl_section(items):
        if not items: return '<div class="none">✔ None</div>'
        rows = [[html_esc(i["value"]), _badge(i["severity"]), i["severity"]] for i in items]
        return _table(["Value","Severity","_sev"], rows, 2)
    excl_content = (
        "<strong>Paths:</strong>" + excl_section(excl.get("paths",[])) +
        "<strong>Extensions:</strong>" + excl_section(excl.get("extensions",[])) +
        "<strong>Processes:</strong>" + excl_section(excl.get("processes",[]))
    )

    # Processes
    proc_flagged = [p for p in data.get("processes",[]) if p.get("severity") in ("critical","suspicious")]
    proc_all     = data.get("processes",[])
    proc_rows    = [[html_esc(p["name"]), p.get("pid","?"), html_esc(p.get("path","?")[:100]),
                     _badge(p["severity"]), p["severity"]]
                    for p in proc_all[:300]]
    proc_content = (f'<p style="color:#8b949e;margin-bottom:8px">{len(proc_all)} total processes — '
                    f'{len(proc_flagged)} flagged</p>') + _table(["Name","PID","Path","Severity","_sev"], proc_rows, 4)

    # Hosts file
    hosts = data.get("hosts_file",[])
    hosts_rows = [[r["ip"], r["hostname"], _badge(r["severity"]), r["severity"]] for r in hosts]
    hosts_content = _table(["IP","Hostname","Severity","_sev"], hosts_rows, 3)

    # Services
    svc_all     = data.get("services", [])
    svc_flagged = [s for s in svc_all if s.get("severity") in ("critical","suspicious")]
    svc_flag_rows = [[html_esc(s["name"]), html_esc(s["display"][:55]), html_esc(s["state"]),
                      html_esc(s["startmode"]), html_esc(s["path"][:90]),
                      html_esc(s["notes"][:100]), _badge(s["severity"]), s["severity"]]
                     for s in svc_flagged]
    svc_all_rows  = [[html_esc(s["name"]), html_esc(s["display"][:55]),
                      html_esc(s["state"]), html_esc(s["startmode"]),
                      _badge(s["severity"]), s["severity"]]
                     for s in svc_all]
    svc_content = (
        f'<p style="color:#8b949e;margin-bottom:8px">'
        f'{len(svc_all)} total services — '
        f'<span style="color:#ff6b6b;font-weight:700">{len(svc_flagged)} flagged</span></p>'
        '<strong>Flagged Services:</strong>'
        + (_table(["Name","Display Name","State","Start Mode","Path","Notes","Severity","_sev"],
                  svc_flag_rows, 7) if svc_flag_rows else '<div class="none">✔ No flagged services</div>')
        + '<details style="margin-top:12px"><summary style="cursor:pointer;padding:8px 12px;'
          'background:#161b22;border:1px solid #30363d;border-radius:6px;font-size:12px;color:#8b949e">'
          f'▶ Full service list ({len(svc_all)} entries)</summary>'
          '<div style="padding-top:6px">'
        + _table(["Name","Display Name","State","Start Mode","Severity","_sev"], svc_all_rows, 5)
        + '</div></details>'
    )

    # Drives
    drv_all      = data.get("drives", [])
    drv_has_flags = any(d.get("severity") in ("critical","suspicious") for d in drv_all)
    drv_rows     = [[html_esc(d["device"]),
                     html_esc(d["fs"]),
                     html_esc(d["type"]),
                     html_esc(d.get("volname","") or "—"),
                     (f'{d["size_gb"]} GB' if d.get("size_gb") is not None else "?"),
                     (f'{d["free_gb"]} GB' if d.get("free_gb") is not None else "?"),
                     html_esc(d.get("notes","") or "—"),
                     _badge(d["severity"]), d["severity"]]
                    for d in drv_all]
    drv_content  = _table(["Drive","Filesystem","Type","Volume Name","Size","Free","Notes","Severity","_sev"],
                           drv_rows, 8)

    # Minecraft accounts
    mc_accs = data.get("minecraft_accounts",[])
    mc_acc_rows = [[html_esc(a.get("launcher","?")), html_esc(a.get("username","?")),
                    html_esc(a.get("uuid","?")), html_esc(a.get("type","?"))]
                   for a in mc_accs]
    mc_acc_content = _table(["Launcher","Username","UUID","Auth Type"], mc_acc_rows)

    # Minecraft clients
    mc = data.get("minecraft",{})
    mc_clients_rows = [[html_esc(c["name"]), html_esc(c["path"]), _badge(c["severity"]), c["severity"]]
                       for c in mc.get("installed_launchers",[])]
    mc_cheat_rows   = [[html_esc(c["name"]), html_esc(c["path"]), _badge(c["severity"]), c["severity"]]
                       for c in mc.get("cheat_folders",[])]
    mc_vers_content = ("<ul style='list-style:none;display:flex;flex-wrap:wrap;gap:8px;padding:4px'>" +
                       "".join(f'<li><code>{html_esc(v)}</code></li>' for v in mc.get("versions",[])) +
                       "</ul>") if mc.get("versions") else '<div class="none">None found</div>'
    mc_mods_rows    = [[html_esc(m["name"]), str(round(m.get("size",0)/1024,1))+" KB",
                        _fmt_dt(m.get("modified")), _badge(m["severity"]), m["severity"]]
                       for m in mc.get("mods",[])]
    mc_jars_rows    = [[html_esc(j["name"]), html_esc(j.get("path","")), _fmt_dt(j.get("modified")),
                        _badge(j.get("severity","info")), j.get("severity","info")]
                       for j in mc.get("non_standard_files",[])]

    mc_content = (
        "<strong>Installed Launchers / Clients:</strong>" +
        _table(["Name","Path","Severity","_sev"], mc_clients_rows, 3) +
        "<br><strong style='color:#e74c3c'>⚠ Cheat Client Folders Found:</strong>" +
        (_table(["Folder","Path","Severity","_sev"], mc_cheat_rows, 3) if mc_cheat_rows else '<div class="none">✔ None found</div>') +
        "<br><strong>Installed Versions:</strong>" + mc_vers_content +
        "<br><strong>Mods:</strong>" +
        _table(["Mod File","Size","Modified","Severity","_sev"], mc_mods_rows, 4) +
        "<br><strong>Non-Standard JARs in .minecraft root:</strong>" +
        (_table(["File","Path","Modified","Severity","_sev"], mc_jars_rows, 4) if mc_jars_rows else '<div class="none">✔ None found</div>')
    )

    # Minecraft deleted files
    del_rows = [[html_esc(r.get("original_path","?")), _fmt_dt(r.get("deleted")),
                 _badge(r.get("severity","info")), r.get("severity","info")]
                for r in data.get("mc_deleted",[])[:50]]
    del_content = _table(["Original Path","Deleted Time","Severity","_sev"], del_rows, 3)

    # Discord accounts
    dc_accs = data.get("discord_accounts",{})
    dc_acc_rows = []
    for install, users in dc_accs.items():
        for u in users:
            dc_acc_rows.append([html_esc(install), html_esc(u.get("username","?")), html_esc(u.get("id","?"))])
    dc_acc_content = _table(["Install","Username","User ID"], dc_acc_rows) if dc_acc_rows else '<div class="none">No accounts found</div>'

    # Discord injection
    di_items = data.get("discord_injection",[])
    di_rows  = [[html_esc(d["install"]), html_esc(d["path"]), str(d["file_size"])+" bytes",
                 html_esc(", ".join(d.get("suspicious_patterns",[])[:5])),
                 _badge(d["severity"]), d["severity"]]
                for d in di_items]
    di_content = _table(["Install","File","Size","Suspicious Patterns","Severity","_sev"], di_rows, 5) if di_rows else '<div class="none">✔ No injection detected</div>'

    # Timeline
    sorted_tl = sorted(TIMELINE, key=lambda x: x["ts"])
    tl_rows   = [[_fmt_dt(e["ts"]), html_esc(e["cat"]), html_esc(e["desc"][:100]),
                  _badge(e.get("sev","info")), e.get("sev","info")]
                 for e in sorted_tl]
    tl_content = _table(["Timestamp","Category","Description","Severity","_sev"], tl_rows, 4)

    # Summary section
    top_findings = []
    for e in pf_entries:
        if e.get("severity") == "critical":
            top_findings.append(f"🔴 Prefetch: <strong>{html_esc(e['exe'])}</strong> ran {e.get('runs',0)} time(s)")
    for e in data.get("userassist",[]):
        if e.get("severity") == "critical":
            top_findings.append(f"🔴 UserAssist: <strong>{html_esc(e['decoded'][:80])}</strong>")
    for c in mc.get("cheat_folders",[]):
        top_findings.append(f"🔴 Cheat folder: <strong>{html_esc(c['name'])}</strong> at {html_esc(c['path'])}")
    for d in di_items:
        top_findings.append(f"🔴 Discord injection in <strong>{html_esc(d['install'])}</strong>")
    for p in data.get("processes",[]):
        if p.get("severity") == "critical":
            top_findings.append(f"🔴 Running process: <strong>{html_esc(p['name'])}</strong>")
    if pf_clusters:
        top_findings.append(f"🟠 Prefetch timestamp clustering: {len(pf_clusters)} cluster(s) detected")
    summary_html = ""
    if top_findings:
        summary_html = '<div class="summary-section"><h3>⚠ Top Findings</h3><ul style="padding-left:20px">'
        summary_html += "".join(f"<li style='margin:4px 0'>{f}</li>" for f in top_findings[:20])
        summary_html += "</ul></div>"
    summary_html += f"""<div class="summary-section">
<h3>Risk Score</h3>
<div style="display:flex;align-items:center;gap:16px;margin-top:6px">
  <span style="font-size:36px;font-weight:700;color:{risk_color}">{risk_score}<span style="font-size:16px;color:#8b949e">/100</span></span>
  <div style="flex:1"><div class="risk-bar"><div class="risk-bar-fill" style="width:{risk_score}%;background:{risk_color}"></div></div>
  <span style="color:#8b949e;font-size:12px">{risk_label}</span></div>
</div></div>"""

    # Build final HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SS Collector Report — {html_esc(sysinfo['user'])} — {html_esc(sysinfo['timestamp'])}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="hdr">
  <div class="risk-circle {rc_class}"><span class="risk-num">{risk_score}</span><span class="risk-lbl">{risk_label}</span></div>
  <div class="hdr-meta">
    <h1>🛡 SS Toolkit — Evidence Report</h1>
    <p>Generated: {html_esc(sysinfo['timestamp'])}</p>
    <p>Host: <strong>{html_esc(sysinfo['hostname'])}</strong> &nbsp;|&nbsp; User: <strong>{html_esc(sysinfo['user'])}</strong></p>
    <p>OS: {html_esc(sysinfo['os'])}</p>
  </div>
</div>
<div class="stats">{stats}</div>
<div class="content">
{summary_html}

<h2 class="section-group">🖥 System Evidence</h2>
{_section("Prefetch Analysis ("+str(len(pf_entries))+" files, "+str(len(pf_flagged))+" flagged)", "📂", pf_content, bool(pf_flagged or pf_clusters))}
{_section("UserAssist Registry ("+str(len(ua_flagged))+" flagged)", "📋", ua_content, bool(ua_flagged))}
{_section("Temp Folder ("+str(len(temp_items))+" suspicious items)", "🗑", temp_content, bool(temp_items))}
{_section("Running Processes ("+str(len(proc_flagged))+" flagged)", "⚙", proc_content, bool(proc_flagged))}
{_section("Startup Registry Keys", "🚀", sk_content, bool([r for r in data.get("startup_keys",[]) if r.get("severity")!="info"]))}
{_section("Windows Defender Exclusions", "🛡", excl_content, bool(excl.get("paths") or excl.get("extensions") or excl.get("processes")))}
{_section("Security Configuration", "🔒", cfg_content, cfg.get("secure_boot") is False or cfg.get("memory_integrity") is False)}
{_section("cscui.dll Integrity", "🔧", cscui_content, cscui_sev in ("critical","suspicious"))}
{_section("PowerShell History ("+str(len(ps_hist))+" commands)", "💻", ps_content)}
{_section("DNS Cache ("+str(len(dns_untrusted))+" untrusted domains)", "🌐", dns_content, bool(dns_untrusted))}
{_section("Event Logs (4663/4656/4658)", "📜", ev_content, bool(data.get("event_logs",[])))}
{_section("AppData New Folders (last 24h)", "📁", af_content, bool(data.get("appdata_new_folders",[])))}
{_section("Drive Scan — Modified DLL/EXE (last 24h, "+str(len(data.get('drive_scan',[])))+" found)", "💾", ds_content, bool(data.get("drive_scan",[])))}
{_section("Recently Installed Programs", "📦", ri_content)}
{_section("Scheduled Tasks (flagged)", "⏰", st_content, bool(st_flagged))}
{_section("Hosts File", "🌍", hosts_content, bool([r for r in hosts if r.get("severity")=="suspicious"]))}
{_section("Windows Services ("+str(len(svc_flagged))+" flagged of "+str(len(svc_all))+")", "🔧", svc_content, bool(svc_flagged))}
{_section("Drive Filesystems — FAT32 / exFAT Check ("+str(len(drv_all))+" drives)", "💿", drv_content, drv_has_flags)}

<h2 class="section-group">⛏ Minecraft</h2>
{_section("Minecraft Accounts ("+str(len(mc_accs))+" found)", "👤", mc_acc_content, bool(mc_accs))}
{_section("Minecraft Clients, Versions & Mods", "🎮", mc_content, bool(mc.get("cheat_folders")))}
{_section("Recently Deleted Minecraft Files", "🗑", del_content, bool(data.get("mc_deleted",[])))}

<h2 class="section-group">💬 Discord</h2>
{_section("Discord Accounts ("+str(sum(len(v) for v in dc_accs.values()))+" found)", "🔵", dc_acc_content, bool(dc_acc_rows))}
{_section("Discord Injection Check", "⚠", di_content, bool(di_items))}

<h2 class="section-group">📅 Full Timeline</h2>
{_section("All Events — Chronological ("+str(len(TIMELINE))+" events)", "📅", tl_content)}

</div>
<div style="text-align:center;color:#484f58;padding:20px;font-size:12px;border-top:1px solid #21262d">
  SS Toolkit Evidence Collector &nbsp;|&nbsp; Generated {html_esc(sysinfo['timestamp'])}
</div>
</body>
</html>"""
    return html

# ─────────────────────────────────────────────────────────────────────────────
# Terminal display helpers
# ─────────────────────────────────────────────────────────────────────────────
def display_summary(data: dict, risk_score: int):
    rule("SCAN COMPLETE", "✔  ")
    col = RED if risk_score >= 75 else (YELLOW if risk_score >= 50 else (YELLOW if risk_score >= 25 else GREEN))
    cprint(f"  Risk Score: {risk_score}/100", col + BOLD)
    print()

    sections = [
        ("Prefetch flagged",     [e for e in data.get("prefetch",{}).get("entries",[]) if e.get("severity")]),
        ("UserAssist flagged",   [e for e in data.get("userassist",[]) if e.get("severity")]),
        ("Suspicious processes", [p for p in data.get("processes",[]) if p.get("severity") in ("critical","suspicious")]),
        ("Cheat folders (MC)",   data.get("minecraft",{}).get("cheat_folders",[])),
        ("Discord injections",   data.get("discord_injection",[])),
        ("Startup key flags",    [r for r in data.get("startup_keys",[]) if r.get("severity") != "info"]),
        ("Drive scan hits",      data.get("drive_scan",[])),
        ("New AppData folders",  data.get("appdata_new_folders",[])),
        ("PF clusters",          data.get("prefetch",{}).get("clusters",[])),
        ("Flagged services",     [s for s in data.get("services",[]) if s.get("severity") in ("critical","suspicious")]),
        ("FAT32 / unusual drives",[d for d in data.get("drives",[]) if d.get("severity") in ("critical","suspicious")]),
    ]

    for label, items in sections:
        n = len(items)
        if n == 0:
            cprint(f"  ✔  {label:<30} 0", GREEN)
        else:
            has_crit = any(isinstance(i,dict) and i.get("severity")=="critical" for i in items)
            col2 = RED + BOLD if has_crit else YELLOW
            cprint(f"  ⚠  {label:<30} {n}", col2)

def display_prefetch(data: dict):
    entries  = data.get("entries",[])
    flagged  = [e for e in entries if e.get("severity")]
    clusters = data.get("clusters",[])
    rule(f"Prefetch — {len(entries)} files, {len(flagged)} flagged", "📂  ")
    if data.get("error"):
        cprint(f"  {data['error']}", YELLOW)
    if clusters:
        cprint(f"  ⚠ TIMESTAMP CLUSTERING: {len(clusters)} cluster(s) — multiple files ran within 60s", YELLOW + BOLD)
    for e in flagged[:30]:
        col = sev_col(e["severity"])
        lr  = e["last_run"].strftime("%Y-%m-%d %H:%M:%S") if e.get("last_run") else "unknown"
        cprint(f"  [{e['severity'].upper():10}] {e['exe']:<40} runs={e.get('runs',0)}  {lr}"
               + (" [SUSP PATH]" if e.get("from_suspicious_path") else ""), col)

def display_userassist(entries: list):
    flagged = [e for e in entries if e.get("severity")]
    rule(f"UserAssist — {len(entries)} entries, {len(flagged)} flagged", "📋  ")
    for e in flagged[:30]:
        col = sev_col(e["severity"])
        cprint(f"  [{e['severity'].upper():10}] {e['decoded'][:80]}", col)

def display_security(cfg: dict, cscui: dict):
    rule("Security Configuration", "🔒  ")
    def show(label, val):
        if val is True:   cprint(f"  ✔  {label:<30} ENABLED",  GREEN)
        elif val is False: cprint(f"  ⚠  {label:<30} DISABLED", YELLOW)
        else:              cprint(f"  ?  {label:<30} UNKNOWN",  DIM)
    show("Secure Boot",               cfg.get("secure_boot"))
    show("Memory Integrity (VBS)",    cfg.get("memory_integrity"))
    show("Fast Boot",                 cfg.get("fast_boot"))
    sev = cscui.get("severity","info")
    col = sev_col(sev)
    cprint(f"  {'⚠' if sev else '✔'}  cscui.dll signature{'':<19} {cscui.get('sig_status','unknown')}", col or GREEN)

def display_minecraft(mc: dict, accounts: list):
    rule(f"Minecraft — {len(accounts)} account(s) found", "⛏  ")
    for a in accounts:
        print(f"  [{a.get('launcher','?')}] {a.get('username','?')} — UUID: {a.get('uuid','?')}")
    if mc.get("cheat_folders"):
        cprint(f"\n  ⚠  CHEAT FOLDERS FOUND:", RED + BOLD)
        for c in mc["cheat_folders"]:
            cprint(f"     {c['name']} → {c['path']}", RED)
    if mc.get("versions"):
        print(f"\n  Versions: {', '.join(mc['versions'][:10])}")

def display_discord(accounts: dict, injection: list):
    rule(f"Discord", "💬  ")
    for install, users in accounts.items():
        print(f"  [{install}]")
        for u in users:
            print(f"    {u.get('username','?')} — ID: {u.get('id','?')}")
    if injection:
        cprint(f"\n  ⚠  DISCORD INJECTION DETECTED:", RED + BOLD)
        for d in injection:
            cprint(f"     {d['install']}: {d['path']}", RED)
            if d.get("suspicious_patterns"):
                cprint(f"     Patterns: {', '.join(d['suspicious_patterns'][:5])}", RED)

# ─────────────────────────────────────────────────────────────────────────────
# Output path
# ─────────────────────────────────────────────────────────────────────────────
def get_output_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print(f"\n{CYAN}{BOLD}{'═'*72}{RESET}")
    print(f"{CYAN}{BOLD}  SS Toolkit — Windows Evidence Collector  (Professional Edition){RESET}")
    print(f"{CYAN}{BOLD}{'═'*72}{RESET}\n")

    # Elevation check
    if sys.platform == "win32":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            is_admin = False
        if not is_admin:
            cprint("  ⚠  WARNING: Not running as Administrator.", YELLOW + BOLD)
            cprint("     Some checks (Prefetch, Event Logs, Defender) may fail.", YELLOW)
            cprint("     Right-click collector.exe → 'Run as administrator'\n", YELLOW)

    sysinfo = collect_sysinfo()
    cprint(f"  Host : {sysinfo['hostname']}  |  User : {sysinfo['user']}", DIM)
    cprint(f"  OS   : {sysinfo['os']}", DIM)
    cprint(f"  Time : {sysinfo['timestamp']}\n", DIM)
    print()

    # ── Run all collectors ───────────────────────────────────────────────────
    progress("Scanning Prefetch files...")
    pf = collect_prefetch()

    progress("Decoding UserAssist registry (ROT13)...")
    ua = collect_userassist()

    progress("Scanning Temp folder...")
    temp = collect_temp_folder()

    progress("Checking cscui.dll integrity...")
    cscui = collect_cscui_dll()

    progress("Checking Secure Boot / VBS / Fast Boot...")
    sec_cfg = collect_security_config()

    progress("Reading PowerShell history...")
    ps_hist = collect_ps_history()

    progress("Scanning DNS cache...")
    dns = collect_dns_cache()

    progress("Querying Windows Event Logs (4663/4656/4658)...")
    evts = collect_event_logs()

    progress("Scanning AppData for new folders (24h)...")
    appdata_new = collect_appdata_new_folders()

    progress("Scanning drives for modified DLL/EXE (24h)...")
    drive = collect_drive_scan()

    progress("Checking startup registry keys...")
    startup = collect_startup_keys()

    progress("Checking recently installed programs...")
    installed = collect_recently_installed()

    progress("Scanning scheduled tasks...")
    schtasks = collect_scheduled_tasks()

    progress("Checking Windows Defender exclusions...")
    defender = collect_defender_exclusions()

    progress("Enumerating processes with file paths...")
    procs = collect_processes()

    progress("Reading hosts file...")
    hosts = collect_hosts_file()

    progress("Enumerating Windows services...")
    services = collect_services()

    progress("Scanning drive filesystems (FAT32 / exFAT check)...")
    drives = collect_drives()

    progress("Finding Minecraft accounts...")
    mc_accounts = collect_minecraft_accounts()

    progress("Detecting Minecraft clients, versions, mods...")
    mc_data = collect_minecraft_clients()

    progress("Scanning Recycle Bin for deleted Minecraft files...")
    mc_deleted = collect_mc_deleted_files()

    progress("Extracting Discord accounts from LevelDB...")
    dc_accounts = collect_discord_accounts()

    progress("Checking Discord for injections...")
    dc_inject = collect_discord_injection()

    progress("Calculating risk score...")
    all_data = {
        "prefetch":           pf,
        "userassist":         ua,
        "temp_folder":        temp,
        "cscui":              cscui,
        "security_config":    sec_cfg,
        "ps_history":         ps_hist,
        "dns_cache":          dns,
        "event_logs":         evts,
        "appdata_new_folders":appdata_new,
        "drive_scan":         drive,
        "startup_keys":       startup,
        "recently_installed": installed,
        "scheduled_tasks":    schtasks,
        "defender_exclusions":defender,
        "processes":          procs,
        "hosts_file":         hosts,
        "services":           services,
        "drives":             drives,
        "minecraft_accounts": mc_accounts,
        "minecraft":          mc_data,
        "mc_deleted":         mc_deleted,
        "discord_accounts":   dc_accounts,
        "discord_injection":  dc_inject,
    }
    risk = calc_risk_score(all_data)

    progress("Generating HTML report...")
    html = build_html_report(sysinfo, all_data, risk)

    progress("Saving JSON data...")
    out_dir  = get_output_dir()
    username = sysinfo["user"]
    date_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    html_path = os.path.join(out_dir, f"collector_report_{username}_{date_str}.html")
    json_path = os.path.join(out_dir, f"collector_data_{username}_{date_str}.json")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    def json_serial(obj):
        if isinstance(obj, datetime): return obj.isoformat()
        return str(obj)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({**all_data, "meta": sysinfo, "risk_score": risk,
                   "timeline": [{"ts":e["ts"].isoformat(),"cat":e["cat"],"desc":e["desc"],"sev":e["sev"]}
                                 for e in sorted(TIMELINE, key=lambda x: x["ts"])]},
                  f, indent=2, default=json_serial)

    # ── Display results ──────────────────────────────────────────────────────
    print("\n")
    display_prefetch(pf)
    display_userassist(ua)
    display_security(sec_cfg, cscui)
    display_minecraft(mc_data, mc_accounts)
    display_discord(dc_accounts, dc_inject)
    display_summary(all_data, risk)

    cprint(f"\n  HTML report : {html_path}", GREEN + BOLD)
    cprint(f"  JSON data   : {json_path}", GREEN + BOLD)
    print(f"\n{CYAN}{'═'*72}{RESET}")
    input("\n  Press Enter to exit...")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        cprint(f"\n{RED}{BOLD}FATAL ERROR:{RESET}", RED)
        traceback.print_exc()
        input("\nPress Enter to exit...")
