"""
shared.py — Common constants, helpers, and suspicious-string lists
used across every tool in ss-toolkit.

Detection is tiered into three levels:
  CRITICAL   — paid ghost clients, injection frameworks, AC bypass tools
  SUSPICIOUS — free / open-source clients, generic cheat features
  DEBUG      — reverse-engineering / debug tools (suspicious context)
"""

from datetime import datetime, timezone
import struct

# ─────────────────────────────────────────────────────────────────────────────
# TIER 1 — CRITICAL
# Paid / private ghost clients built specifically to bypass anti-cheat.
# Finding any of these is a strong ban indicator.
# ─────────────────────────────────────────────────────────────────────────────

GHOST_CLIENTS = [
    # ── Vape family ──────────────────────────────────────────────────────────
    "vape", "vape lite", "vapelite", "vape v4", "vapev4", "vape v3",

    # ── Drip family ──────────────────────────────────────────────────────────
    "drip", "dripx", "drip x", "drip-x",

    # ── Other high-end ghost clients ─────────────────────────────────────────
    "stardust",
    "atom",           # Atom ghost client
    "reflex",         # Reflex ghost client
    "flaw",
    "ember",
    "starscript",
    "boze",
    "solis",
    "fentanyl",       # private ghost client
    "pyro",
    "azura",
    "flux",           # Flux ghost client
    "exhibition",
    "astolfo",        # Astolfo ghost client
    "autumn",
    "vertex",         # Vertex ghost client
    "entropy",
    "quasar",
    "gorilla",
    "prism",          # Prism ghost client
    "zephyr",
    "tenacity",
    "hybrid",
    "eagle",
    "albedo",
    "cheeto",
    "monsoon",
    "motion",         # Motion ghost client
    "inertia",        # Inertia ghost client
    "novoline",       # Novoline ghost client
    "remix",          # Remix ghost client
    "rise",           # Rise ghost client (paid tier)
    "sigma",          # Sigma paid tier ghost
    "raven",          # Raven B+ / ghost version
    "ares",           # Ares ghost client
    "rusherhack",     # RusherHack (bypass edition)
    "schildblade",
    "blackout",
    "luma",
    "ambrosialegacy", "ambrosia",
    "cringeware",
    "horion",         # Bedrock ghost client

    # ── Weave injection framework (used by many ghost clients) ───────────────
    "weave",          # Weave loader / framework
    "weave-loader", "weaveloader", "weave_loader",

    # ── Generic "ghost client" label ─────────────────────────────────────────
    "ghost client", "ghostclient",
]

# ─────────────────────────────────────────────────────────────────────────────
# TIER 1 — CRITICAL
# Anti-cheat bypass tools, injection frameworks, and Java agent abuse.
# These are almost never found legitimately during an SS.
# ─────────────────────────────────────────────────────────────────────────────

BYPASS_INDICATORS = [
    # ── Named AC bypasses ────────────────────────────────────────────────────
    "watchdog bypass", "watchdogbypass",
    "grim bypass", "grimbypass", "grim ac bypass",
    "intave bypass", "intavebypass",
    "polar bypass", "polarbypass",
    "vulcan bypass", "vulcanbypass",
    "matrix bypass", "matrixbypass",
    "aac bypass", "aacbypass",
    "ncp bypass", "ncpbypass",
    "verus bypass", "verusbypass",
    "karhu bypass", "karhubypass",
    "wraith bypass", "wraithbypass",
    "velocity bypass", "velocitybypass",
    "mineplex bypass",
    "hypixel bypass",
    "badlion bypass",

    # ── Java agent injection ─────────────────────────────────────────────────
    "javaagent",      # -javaagent JVM flag — rare in legit Minecraft
    "java agent",
    "premain",        # Java agent entry point method name
    "agentmain",      # Dynamic attach agent entry point
    "instrumentation",# java.lang.instrument abuse
    "agent.jar",
    "-javaagent:",

    # ── Bytecode / class manipulation ────────────────────────────────────────
    "classtransformer",  "class transformer",
    "classtransformation",
    "bytebuddy", "byte buddy", "byte-buddy",
    "javassist",
    "objectweb asm", "objectweb.asm",
    "bytecode inject", "bytecode manipulation",
    "foreign code",
    "class injection",
    "runtime inject",

    # ── Mixin abuse (legitimate Mixin is in dev, not prod) ───────────────────
    "unknown mixin",
    "unsigned mixin",
    "external mixin",
    "foreign mixin config",

    # ── Memory / process manipulation ────────────────────────────────────────
    "memory patch",
    "memorywrite",
    "writeprocessmemory",
    "readprocessmemory",
    "openprocess",
    "virtualallocex",
    "createremotethread",   # classic DLL injection API
    "dll inject", "dllinjection", "dll injection",
    "process inject",

    # ── Unsigned / modified JARs flagged by OAC ─────────────────────────────
    "unsigned jar",
    "invalid signature",
    "modified game",
    "tampered class",
    "checksum mismatch",
    "unknown classpath",
    "foreign classpath",
    "classpath inject",
    "suspicious thread",
    "hook detected",
    "inline hook",

    # ── Java cheat development tools ─────────────────────────────────────────
    "recaf",          # Java bytecode editor — primary tool for cheat dev
]

# ─────────────────────────────────────────────────────────────────────────────
# TIER 2 — SUSPICIOUS
# Free / open-source clients and generic cheat feature keywords.
# Still worth flagging but lower confidence on their own.
# ─────────────────────────────────────────────────────────────────────────────

FREE_CLIENTS = [
    "wurst",
    "impact",
    "aristois",
    "meteor",
    "future",
    "liquidbounce",
    "nodus",
    "enchanted",
]

CHEAT_FEATURES = [
    "killaura", "kill_aura", "kill aura",
    "xray", "x-ray", "x ray",
    "aimbot", "aim_bot", "aim bot",
    "esp",
    "freecam", "free_cam", "free cam",
    "noclip", "no_clip", "no clip",
    "autoclicker", "auto_clicker", "auto clicker",
    "scaffold",
    "crystalaura", "crystal_aura", "crystal aura",
    "automine", "auto_mine",
    "bhop", "bunny hop", "bunnyhop",
    "strafe",
    "reach",
    "hitbox",
    "velocity",   # as a cheat feature (reduce knockback)
    "antikb", "anti kb", "anti-kb",
    "blink",
    "triggerbot", "trigger bot",
    "aimassist", "aim assist",
    "autoblock", "auto block",
    "fastplace", "fast place",
    "fastbreak", "fast break",
    "timer",       # cheat timer (speed)
    "speed hack", "speedhack",
    "fly hack", "flyhack",
    "jesus", "waterwalk",
]

# ─────────────────────────────────────────────────────────────────────────────
# TIER 2 — SUSPICIOUS
# Reverse-engineering / debug tools.  Legitimate users don't run these
# while playing Minecraft, but having them running isn't auto-ban level.
# ─────────────────────────────────────────────────────────────────────────────

DEBUG_TOOLS = [
    "processhacker", "process hacker", "process_hacker",
    "cheatengine", "cheat engine", "cheat_engine",
    "wireshark",
    "fiddler",
    "artmoney",
    "tsearch",
    "ollydbg",
    "x64dbg",
    "x32dbg",
    "dnspy",
    "de4dot",
    "dotpeek",
    "ilspy",
    "jadx",
    "jd-gui", "jdgui",
    "cfr",            # CFR Java decompiler
    "procmon",        # Process Monitor
    "procexp",        # Process Explorer
    "apimonitor",
    "pestudio",
    "immunity debugger",
    "windbg",
    "ida pro", "idapro",
    "ghidra",
]

# ─────────────────────────────────────────────────────────────────────────────
# Flat combined list (used by prefetch / registry tools for quick checks)
# ─────────────────────────────────────────────────────────────────────────────

CHEAT_CLIENT_NAMES = GHOST_CLIENTS + BYPASS_INDICATORS + FREE_CLIENTS + CHEAT_FEATURES + DEBUG_TOOLS

# Extensions that are extra-suspicious when found in prefetch / UA lists
SUSPICIOUS_EXTENSIONS = [".jar", ".exe", ".bat", ".vbs", ".ps1", ".dll"]

# Keywords Ocean Anti-Cheat itself prints when something is flagged
OAC_FLAG_KEYWORDS = [
    "FLAGGED", "SUSPICIOUS", "DETECTED", "MODIFIED", "TAMPERED",
    "INJECTED", "HOOK", "ABNORMAL", "WARNING", "CRITICAL", "ALERT",
    "UNSIGNED", "MISMATCH", "FOREIGN", "UNKNOWN CLASS", "AGENT DETECTED",
]

# Severity colours for Rich tables
SEVERITY_STYLE = {
    "critical":   "bold red",
    "suspicious": "bold yellow",
    "clean":      "bold green",
    "info":       "dim",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def classify_name(name: str) -> str:
    """
    Return the highest severity tier for *name*:
      'critical'   — ghost client or bypass tool
      'suspicious' — free client, cheat feature, or debug tool
      ''           — nothing found
    """
    low = name.lower()

    for kw in GHOST_CLIENTS + BYPASS_INDICATORS:
        if kw in low:
            return "critical"

    for kw in FREE_CLIENTS + CHEAT_FEATURES + DEBUG_TOOLS:
        if kw in low:
            return "suspicious"

    return ""


def is_suspicious(name: str) -> bool:
    """Return True if *name* contains any known cheat keyword (case-insensitive)."""
    return classify_name(name) != ""


def filetime_to_dt(filetime_bytes: bytes) -> datetime | None:
    """
    Convert an 8-byte Windows FILETIME (little-endian) to a Python datetime.
    FILETIME is 100-nanosecond intervals since 1601-01-01 UTC.
    Returns None if the value is zero / invalid.
    """
    if len(filetime_bytes) < 8:
        return None
    ft = struct.unpack_from("<Q", filetime_bytes)[0]
    if ft == 0:
        return None
    EPOCH_DIFF = 116_444_736_000_000_000
    unix_100ns = ft - EPOCH_DIFF
    if unix_100ns < 0:
        return None
    unix_sec = unix_100ns / 10_000_000
    return datetime.fromtimestamp(unix_sec, tz=timezone.utc)


def rot13(text: str) -> str:
    """Pure-Python ROT13 that handles only ASCII letters."""
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def load_config(path: str = "config.json") -> dict:
    """Load config.json, returning an empty dict if missing."""
    import json, os
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)
