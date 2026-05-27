"""
shared.py — Common constants, helpers, and suspicious-string lists
used across every tool in ss-toolkit.
"""

from datetime import datetime, timezone
import struct

# ─────────────────────────────────────────────────────────────────────────────
# Suspicious string lists
# ─────────────────────────────────────────────────────────────────────────────

# Known / popular Minecraft cheat client names and related keywords.
# All stored lowercase so comparisons are case-insensitive.
CHEAT_CLIENT_NAMES = [
    # Named clients
    "wurst", "impact", "aristois", "meteor", "future", "inertia",
    "ares", "liquidbounce", "sigma", "vape", "luma", "rise",
    "novoline", "ambrosialegacy", "cringeware", "nodus", "rusherhack",
    "remix", "motion", "horion", "schildblade", "blackout",
    "monsoon", "drip", "enchanted", "raven", "pyro",
    # Generic cheat feature keywords
    "killaura", "kill_aura", "xray", "x-ray", "aimbot", "aim_bot",
    "esp", "freecam", "free_cam", "noclip", "no_clip", "autoclicker",
    "auto_clicker", "scaffold", "crystalaura", "crystal_aura",
    # Utility / bypass tools often found during SS
    "processhacker", "process_hacker", "cheatengine", "cheat_engine",
    "wireshark", "fiddler", "artmoney", "tsearch", "ollydbg", "x64dbg",
    "dnspy", "de4dot", "dotpeek", "ilspy",
    # Injectors / loaders
    "injector", "loader", "bypass", "inject",
]

# Extensions that are extra-suspicious when found in prefetch / UA lists
SUSPICIOUS_EXTENSIONS = [".jar", ".exe", ".bat", ".vbs", ".ps1", ".dll"]

# Keywords Ocean Anti-Cheat itself prints when something is flagged
OAC_FLAG_KEYWORDS = [
    "FLAGGED", "SUSPICIOUS", "DETECTED", "MODIFIED", "TAMPERED",
    "INJECTED", "HOOK", "ABNORMAL", "WARNING", "CRITICAL", "ALERT",
]

# Severity colours for Rich tables
SEVERITY_STYLE = {
    "critical": "bold red",
    "suspicious": "bold yellow",
    "clean":      "bold green",
    "info":       "dim",
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def is_suspicious(name: str) -> bool:
    """Return True if *name* contains any known cheat keyword (case-insensitive)."""
    low = name.lower()
    return any(kw in low for kw in CHEAT_CLIENT_NAMES)


def filetime_to_dt(filetime_bytes: bytes) -> datetime | None:
    """
    Convert an 8-byte Windows FILETIME (little-endian) to a Python datetime.
    FILETIME is the number of 100-nanosecond intervals since 1601-01-01 UTC.
    Returns None if the value is zero / invalid.
    """
    if len(filetime_bytes) < 8:
        return None
    ft = struct.unpack_from("<Q", filetime_bytes)[0]
    if ft == 0:
        return None
    # Subtract FILETIME epoch offset (seconds between 1601-01-01 and 1970-01-01)
    EPOCH_DIFF = 116_444_736_000_000_000
    unix_100ns = ft - EPOCH_DIFF
    if unix_100ns < 0:
        return None
    unix_sec = unix_100ns / 10_000_000
    return datetime.fromtimestamp(unix_sec, tz=timezone.utc)


def rot13(text: str) -> str:
    """Pure-Python ROT13 that handles only ASCII letters (leaves others unchanged)."""
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
