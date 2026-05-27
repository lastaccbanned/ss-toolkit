"""
discord_bot.py — Tool 5: Discord Screenshare Guide Bot
────────────────────────────────────────────────────────
A Discord bot that walks a staff member through a Minecraft screenshare
step by step.  Each step is shown as a rich embed with instructions, and
staff can navigate forward/back or mark the session as Pass/Fail.

Commands (prefix: !, configurable in config.json):
  !ss start [@player]  — Begin a new screenshare session in this channel.
  !ss next             — Advance to the next step.
  !ss prev             — Go back one step.
  !ss flag <reason>    — Record a suspicious finding for the current step.
  !ss findings         — Show all flagged findings so far.
  !ss pass             — Close the session with a PASS verdict.
  !ss fail [reason]    — Close the session with a FAIL verdict.
  !ss cancel           — Abort the session without a verdict.
  !ss help             — Show this command list.

Setup:
  1.  Copy config.example.json → config.json
  2.  Create a bot at https://discord.com/developers/applications
  3.  Copy the bot token into config.json  →  "discord_token"
  4.  Invite the bot to your server with the  bot  scope + Send Messages +
      Embed Links + Read Message History permissions.
  5.  Run this tool from the ss-toolkit menu (option 5) or directly:
          python tools/discord_bot.py

Usage (from menu or directly):
    python tools/discord_bot.py
"""

import os
import sys
from datetime import datetime, timezone

# ── Check discord.py is installed ────────────────────────────────────────────
try:
    import discord
    from discord.ext import commands
    _DISCORD_AVAILABLE = True
except ImportError:
    discord = None          # type: ignore
    commands = None         # type: ignore
    _DISCORD_AVAILABLE = False

from tools.shared import load_config

# ─────────────────────────────────────────────────────────────────────────────
# Screenshare steps
# ─────────────────────────────────────────────────────────────────────────────

STEPS: list[dict] = [
    {
        "title":       "Step 1 — Introduction",
        "colour":      0x3498DB,
        "description": (
            "Welcome to the screenshare.\n\n"
            "**What to say to the player:**\n"
            "> 'We're going to do a quick screenshare to make sure everything is fair. "
            "Please share your screen now and **don't close anything**. "
            "If you disconnect or close your screen at any point it will count as a refusal.'\n\n"
            "📌 Wait until the player's screen is clearly visible before continuing."
        ),
        "checklist": [
            "Screen share is visible and covers the full desktop",
            "Player is aware the session is being recorded / logged",
            "No suspicious windows closed before sharing",
        ],
    },
    {
        "title":       "Step 2 — Minecraft F3 Debug Screen",
        "colour":      0x2ECC71,
        "description": (
            "Ask the player to open Minecraft and press **F3** (the debug screen).\n\n"
            "**Look for:**\n"
            "• `Mods: X loaded` — note the count (vanilla = 0)\n"
            "• Forge / Fabric / OptiFine version displayed\n"
            "• Any mods listed that you don't recognise\n\n"
            "**What to say:**\n"
            "> 'Please open Minecraft and press F3.  Hold it up so I can read the left side.'"
        ),
        "checklist": [
            "Note any mod loader (Forge / Fabric / etc.)",
            "Note mod count",
            "Ask about any unrecognised mods",
        ],
    },
    {
        "title":       "Step 3 — .minecraft Folder",
        "colour":      0x2ECC71,
        "description": (
            "Ask the player to open their `.minecraft` folder:\n"
            "> *Windows:* Press `Win + R`, type `%appdata%\\.minecraft`, press Enter.\n"
            "> *Mac:* Open Finder → Go → Go to Folder → `~/Library/Application Support/minecraft`\n\n"
            "**Check:**\n"
            "• `mods/` — any unfamiliar `.jar` files?\n"
            "• `shaderpacks/` — unusual shader packs?\n"
            "• `resourcepacks/` — resource packs with strange names?\n"
            "• `logs/latest.log` — look for crash lines mentioning unknown mods\n\n"
            "**Red flags:** jars not matching known mods, jars with obfuscated names, "
            "`.jar` files in the root folder."
        ),
        "checklist": [
            "All mods in mods/ are identifiable",
            "No suspicious jars in root or other folders",
            "Logs do not mention unknown mods",
        ],
    },
    {
        "title":       "Step 4 — Run Ocean Anti-Cheat (OAC)",
        "colour":      0xF39C12,
        "description": (
            "Ask the player to run the **Ocean Anti-Cheat** scanner.\n\n"
            "**How to get OAC:**\n"
            "1. Download from the official OAC Discord / website.\n"
            "2. Run the `.exe` — it does NOT need installation.\n"
            "3. Click **Scan** and wait for it to complete.\n"
            "4. Click **Export PDF** and upload the PDF here (or share it via screen share).\n\n"
            "⏳ *The scan usually takes 30–60 seconds.*"
        ),
        "checklist": [
            "OAC was downloaded fresh (not a cached old scan)",
            "Player did not close any windows before scanning",
            "PDF exported and visible / uploaded",
        ],
    },
    {
        "title":       "Step 5 — Analyse OAC Results",
        "colour":      0xF39C12,
        "description": (
            "Review the OAC PDF using **Tool 1 (PDF Scanner)** in ss-toolkit, "
            "or visually scan the PDF for red/orange entries.\n\n"
            "**Key things to flag:**\n"
            "• Any row marked `FLAGGED` or `SUSPICIOUS`\n"
            "• Modified game files\n"
            "• Injected DLLs\n"
            "• Abnormal process hooks\n\n"
            "Use `!ss flag <reason>` to record any findings from this step."
        ),
        "checklist": [
            "All OAC rows reviewed",
            "Flagged entries noted with !ss flag",
        ],
    },
    {
        "title":       "Step 6 — Check Windows Prefetch",
        "colour":      0xE67E22,
        "description": (
            "Check the Windows Prefetch folder for recently-run programs.\n\n"
            "**How:**\n"
            "> Press `Win + R`, type `C:\\\\Windows\\\\Prefetch`, press Enter.\n"
            "> Sort by **Date Modified** (most recent first).\n\n"
            "**Look for:**\n"
            "• Known cheat clients (wurst, impact, aristois, meteor, etc.)\n"
            "• Injectors / loaders\n"
            "• Process Hacker, Cheat Engine, x64dbg\n"
            "• Files with obfuscated / random names\n\n"
            "📌 Use **Tool 2 (Prefetch Analyzer)** in ss-toolkit to scan the folder automatically."
        ),
        "checklist": [
            "Prefetch folder opened and visible",
            "Suspicious entries noted",
            "Timestamps cross-referenced with play sessions",
        ],
    },
    {
        "title":       "Step 7 — Check UserAssist Registry",
        "colour":      0xE74C3C,
        "description": (
            "Export and decode the Windows UserAssist registry key.\n\n"
            "**On the suspect machine:**\n"
            "1. Press `Win + R`, type `regedit`, press Enter.\n"
            "2. Navigate to:\n"
            "   `HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist`\n"
            "3. Right-click the `UserAssist` key → Export → save as `ua.reg`.\n"
            "4. Upload `ua.reg` here or use **Tool 3** in ss-toolkit to decode it.\n\n"
            "**What to look for:**\n"
            "Decoded paths that mention cheat clients, injectors, or hacking tools."
        ),
        "checklist": [
            "ua.reg exported without closing regedit first",
            "Decoded with Tool 3",
            "Suspicious paths noted with !ss flag",
        ],
    },
    {
        "title":       "Step 8 — Check for Recording / VM / Debug Software",
        "colour":      0x9B59B6,
        "description": (
            "Check whether the player is using software that could indicate cheating "
            "or attempts to hide it.\n\n"
            "**Screen recorders / capture:**\n"
            "• OBS, Bandicam, XSplit, Fraps — innocent on their own, but suspicious if "
            "  Minecraft is NOT being recorded while they claim to be streaming\n\n"
            "**Virtual Machines:**\n"
            "• VMware, VirtualBox taskbar icons or processes — playing inside a VM is a "
            "  common method to hide cheats\n\n"
            "**Debug / reverse-engineering tools:**\n"
            "• Process Hacker, x64dbg, Cheat Engine, WireShark, dnSpy open in taskbar\n\n"
            "**Task Manager:**\n"
            "> Ask: 'Can you open Task Manager and show me the Processes tab?'"
        ),
        "checklist": [
            "Task Manager viewed — no suspicious processes",
            "No VM software detected",
            "No active injectors or debug tools visible",
        ],
    },
    {
        "title":       "Step 9 — Final Verdict",
        "colour":      0x1ABC9C,
        "description": (
            "Review all findings before issuing your verdict.\n\n"
            "**Commands:**\n"
            "• `!ss findings` — review everything you flagged\n"
            "• `!ss pass`     — player is clean; end the session\n"
            "• `!ss fail <reason>` — player is banned / punished\n\n"
            "**Tips:**\n"
            "• Even if you found nothing definitive, strong suspicion on multiple steps "
            "  is usually sufficient for your server's rules.\n"
            "• Document everything — screenshots + `!ss findings` log."
        ),
        "checklist": [
            "All findings reviewed",
            "Verdict issued with !ss pass or !ss fail",
        ],
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Session state (per channel)
# ─────────────────────────────────────────────────────────────────────────────

class ScreenshareSession:
    def __init__(self, staff_id: int, player_name: str):
        self.staff_id    = staff_id
        self.player_name = player_name
        self.step_index  = 0
        self.findings:   list[str] = []
        self.started_at  = datetime.now(tz=timezone.utc)

    @property
    def current_step(self) -> dict:
        return STEPS[self.step_index]

    @property
    def is_last_step(self) -> bool:
        return self.step_index >= len(STEPS) - 1


active_sessions: dict[int, ScreenshareSession] = {}   # channel_id → session

# ─────────────────────────────────────────────────────────────────────────────
# Embed builders
# ─────────────────────────────────────────────────────────────────────────────

def build_step_embed(session: ScreenshareSession):
    step  = session.current_step
    embed = discord.Embed(
        title=step["title"],
        description=step["description"],
        colour=step["colour"],
    )
    embed.set_author(name=f"Screensharing: {session.player_name}")
    embed.set_footer(
        text=f"Step {session.step_index + 1}/{len(STEPS)}  •  "
             f"{len(session.findings)} finding(s)  •  "
             f"Type !ss next to continue or !ss prev to go back"
    )

    checklist_str = "\n".join(f"☐  {item}" for item in step.get("checklist", []))
    if checklist_str:
        embed.add_field(name="Checklist", value=checklist_str, inline=False)

    return embed


def build_summary_embed(session: ScreenshareSession, verdict: str, reason: str = ""):
    colour  = 0x2ECC71 if verdict == "PASS" else (0xE74C3C if verdict == "FAIL" else 0x95A5A6)
    emoji   = "✅" if verdict == "PASS" else ("❌" if verdict == "FAIL" else "⏹")
    elapsed = int((datetime.now(tz=timezone.utc) - session.started_at).total_seconds() / 60)

    embed = discord.Embed(
        title=f"{emoji} Screenshare {verdict}  —  {session.player_name}",
        colour=colour,
    )
    embed.add_field(name="Staff",    value=f"<@{session.staff_id}>",  inline=True)
    embed.add_field(name="Duration", value=f"{elapsed} min",          inline=True)
    if reason:
        embed.add_field(name="Reason", value=reason, inline=False)
    if session.findings:
        embed.add_field(
            name="Findings",
            value="\n".join(f"• {f}" for f in session.findings),
            inline=False,
        )
    else:
        embed.add_field(name="Findings", value="None", inline=False)
    embed.set_footer(text=session.started_at.strftime("Started %Y-%m-%d %H:%M UTC"))
    return embed

# ─────────────────────────────────────────────────────────────────────────────
# Bot definition
# ─────────────────────────────────────────────────────────────────────────────

def create_bot(prefix: str):  # -> commands.Bot
    intents         = discord.Intents.default()
    intents.message_content = True
    bot             = commands.Bot(command_prefix=prefix, intents=intents)
    bot.remove_command("help")   # we provide our own

    # ── !ss ──────────────────────────────────────────────────────────────────
    @bot.group(name="ss", invoke_without_command=True)
    async def ss(ctx: commands.Context) -> None:
        await ctx.send(
            "Unknown sub-command.  Type `!ss help` for a list of commands."
        )

    @ss.command(name="help")
    async def ss_help(ctx: commands.Context) -> None:
        embed = discord.Embed(
            title="📋 Screenshare Bot — Commands",
            colour=0x3498DB,
        )
        cmds = {
            "!ss start [@player]": "Begin a new screenshare session.",
            "!ss next":            "Advance to the next step.",
            "!ss prev":            "Go back one step.",
            "!ss flag <reason>":   "Record a suspicious finding.",
            "!ss findings":        "Show all findings so far.",
            "!ss pass":            "Close with PASS verdict.",
            "!ss fail [reason]":   "Close with FAIL verdict.",
            "!ss cancel":          "Abort without a verdict.",
        }
        for cmd, desc in cmds.items():
            embed.add_field(name=f"`{cmd}`", value=desc, inline=False)
        await ctx.send(embed=embed)

    @ss.command(name="start")
    async def ss_start(ctx: commands.Context, *, player_name: str = "Unknown") -> None:
        ch_id = ctx.channel.id
        if ch_id in active_sessions:
            await ctx.send(
                "⚠  A screenshare is already active in this channel.  "
                "Use `!ss cancel` to end it first."
            )
            return
        session = ScreenshareSession(
            staff_id=ctx.author.id,
            player_name=player_name.lstrip("@"),
        )
        active_sessions[ch_id] = session
        embed = build_step_embed(session)
        await ctx.send(
            f"🎬  Screenshare started for **{session.player_name}** by <@{ctx.author.id}>.",
            embed=embed,
        )

    @ss.command(name="next")
    async def ss_next(ctx: commands.Context) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.get(ch_id)
        if not session:
            await ctx.send("No active screenshare in this channel.  Use `!ss start`.")
            return
        if session.is_last_step:
            await ctx.send("You're on the last step.  Use `!ss pass` or `!ss fail` to close.")
            return
        session.step_index += 1
        await ctx.send(embed=build_step_embed(session))

    @ss.command(name="prev")
    async def ss_prev(ctx: commands.Context) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.get(ch_id)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        if session.step_index == 0:
            await ctx.send("You're already on the first step.")
            return
        session.step_index -= 1
        await ctx.send(embed=build_step_embed(session))

    @ss.command(name="flag")
    async def ss_flag(ctx: commands.Context, *, reason: str) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.get(ch_id)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        step_name = session.current_step["title"]
        entry     = f"[{step_name}] {reason}"
        session.findings.append(entry)
        await ctx.send(f"🚩 Finding recorded:\n> {entry}")

    @ss.command(name="findings")
    async def ss_findings(ctx: commands.Context) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.get(ch_id)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        if not session.findings:
            await ctx.send("No findings recorded yet.")
            return
        text = "\n".join(f"• {f}" for f in session.findings)
        embed = discord.Embed(
            title=f"Findings — {session.player_name}",
            description=text,
            colour=0xF39C12,
        )
        await ctx.send(embed=embed)

    @ss.command(name="pass")
    async def ss_pass(ctx: commands.Context) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.pop(ch_id, None)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        embed = build_summary_embed(session, "PASS")
        await ctx.send(embed=embed)

    @ss.command(name="fail")
    async def ss_fail(ctx: commands.Context, *, reason: str = "No reason given") -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.pop(ch_id, None)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        embed = build_summary_embed(session, "FAIL", reason)
        await ctx.send(embed=embed)

    @ss.command(name="cancel")
    async def ss_cancel(ctx: commands.Context) -> None:
        ch_id   = ctx.channel.id
        session = active_sessions.pop(ch_id, None)
        if not session:
            await ctx.send("No active screenshare in this channel.")
            return
        embed = build_summary_embed(session, "CANCELLED")
        await ctx.send("Session cancelled.", embed=embed)

    # ── Ready event ──────────────────────────────────────────────────────────
    @bot.event
    async def on_ready() -> None:
        print(f"[ss-toolkit bot] Logged in as {bot.user} (id={bot.user.id})")
        print(f"[ss-toolkit bot] Prefix: {prefix}")
        print(f"[ss-toolkit bot] Ready.  Invite URL:")
        print(
            f"  https://discord.com/api/oauth2/authorize"
            f"?client_id={bot.user.id}&permissions=68608&scope=bot"
        )

    return bot

# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    from rich.console import Console
    from rich.panel import Panel
    _console = Console()

    if not _DISCORD_AVAILABLE:
        _console.print(
            "[red]discord.py is not installed.[/red]  "
            "Run:  [bold]pip install discord.py[/bold]"
        )
        return

    _console.rule("[bold blue]Tool 5 — Discord Screenshare Bot[/bold blue]")
    _console.print(
        "This bot guides staff through Minecraft screenshares step by step.\n"
    )

    cfg    = load_config()
    token  = cfg.get("discord_token", "")
    prefix = cfg.get("discord_prefix", "!")

    if not token or token == "YOUR_BOT_TOKEN_HERE":
        _console.print(Panel(
            "No Discord bot token found in [bold]config.json[/bold].\n\n"
            "Steps to set up:\n"
            "  1. Copy  config.example.json  →  config.json\n"
            "  2. Go to  https://discord.com/developers/applications\n"
            "  3. Create a new application → Bot → copy the Token\n"
            "  4. Paste the token into  config.json  under  'discord_token'\n"
            "  5. Run this tool again.",
            title="[bold yellow]Setup Required[/bold yellow]",
            border_style="yellow",
        ))
        return

    _console.print(f"[dim]Starting bot with prefix:[/dim] [bold]{prefix}[/bold]")
    _console.print("[dim]Press Ctrl+C to stop the bot.[/dim]\n")

    try:
        bot = create_bot(prefix)
        bot.run(token)
    except discord.LoginFailure:
        _console.print(
            "[red]Login failed — invalid token.[/red]  "
            "Check  config.json  and make sure the token is correct."
        )
    except KeyboardInterrupt:
        _console.print("\n[dim]Bot stopped.[/dim]")


if __name__ == "__main__":
    main()
