# 🛡️ ss-toolkit — Minecraft Screensharing Toolkit

A beginner-friendly Python toolkit for Minecraft server staff to run
thorough, consistent screenshares.  Everything launches from a single
numbered menu.

---

## 📦 Requirements

- **Python 3.11+**
- Pip packages (install once):

```bash
pip install -r requirements.txt
```

| Package | Used by |
|---------|---------|
| `pdfplumber` | Tool 1 — PDF Scanner |
| `matplotlib` + `Pillow` | Tool 4 — Timeline |
| `discord.py` | Tool 5 — Discord Bot |
| `rich` | All tools (terminal UI) |
| `colorama` | All tools (colour support) |

---

## 🚀 Quick Start

```bash
# 1. Clone or download the toolkit
cd ss-toolkit

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Set up config.json for the Discord bot
cp config.example.json config.json
# Edit config.json and fill in your Discord bot token

# 4. Launch the menu
python main.py
```

---

## 📋 Tool Guide

### Tool 1 — OAC PDF Scanner

**What it does:** Reads an Ocean Anti-Cheat scan PDF and highlights every
suspicious line — OAC's own `FLAGGED`/`DETECTED` keywords AND known cheat
client names.

**How to use:**
1. On the suspect machine, run Ocean Anti-Cheat and export the result as a PDF.
2. Select **Tool 1** from the menu.
3. Paste the path to the PDF (e.g. `C:\Users\Player\Desktop\scan.pdf`).
4. The tool prints a colour-coded table of findings.
5. Optionally save a plain-text report.

**What to flag:** Any row marked `FLAGGED`, `SUSPICIOUS`, `DETECTED`, or
containing known cheat client names (Wurst, Impact, Aristois, Meteor, etc.).

---

### Tool 2 — Prefetch File Analyzer

**What it does:** Parses Windows `.pf` files from `C:\Windows\Prefetch`,
extracts the executable name + run timestamps, flags suspicious EXEs, and
detects **timestamp clustering** (multiple suspicious programs run within
30 seconds of each other — a classic sign of a cheat launcher).

**How to use:**
1. Select **Tool 2** from the menu.
2. Enter the path to the Prefetch folder (`C:\Windows\Prefetch`) or a
   single `.pf` file.
3. Review the colour-coded table.
4. Optionally export events for the Timeline (Tool 4).

**Supported Windows versions:** XP (v17), Vista/7 (v23), 8/8.1 (v26).
For **Windows 10/11** (v30 compressed files):
```bash
pip install mam
```

> **Tip:** Ask the player to navigate to `C:\Windows\Prefetch` on screen,
> sort by Date Modified, and show you the most recent 20 files.

---

### Tool 3 — UserAssist ROT13 Decoder

**What it does:** Decodes the Windows UserAssist registry key.  Windows
records which programs a user has opened via Start Menu/Explorer with their
paths encoded in ROT13.  This tool decodes them and flags anything suspicious.

**How to use — .reg export (recommended):**
1. On the suspect machine, press `Win + R`, type `regedit`.
2. Navigate to:
   ```
   HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
   ```
3. Right-click `UserAssist` → **Export** → save as `ua.reg`.
4. Select **Tool 3** from the menu → option `1` → enter the path to `ua.reg`.

**How to use — live registry (Windows only):**
- Select **Tool 3** → option `2`.  Reads the current user's live registry.

**What to look for:** Decoded paths containing cheat client names,
injectors, or debug tools.

---

### Tool 4 — Visual Timeline Builder

**What it does:** Builds a colour-coded PNG timeline of all events collected
by the other tools.  Events from Tools 2 and 3 can be exported and merged
here, or you can add events manually.

**Event colours:**
| Colour | Severity |
|--------|----------|
| 🔴 Red | Critical |
| 🟠 Orange | Suspicious |
| 🔵 Blue | Info |
| 🟢 Green | Clean |

**How to use:**
1. Run Tools 2 and 3 first and answer **y** when asked to export to timeline.
2. Select **Tool 4** from the menu.
3. Press `5` to render the PNG.
4. The image is saved to `data/timeline.png` by default.

> Requires `matplotlib` and `Pillow`:  `pip install matplotlib Pillow`

---

### Tool 5 — Discord Screenshare Bot

**What it does:** A Discord bot that walks staff through a 9-step
screenshare process with rich embeds, a checklist for each step, and
commands to record findings and issue a Pass/Fail verdict.

**Setup:**
1. Go to <https://discord.com/developers/applications> and create a new application.
2. Go to **Bot** → **Reset Token** → copy the token.
3. Edit `config.json`:
   ```json
   {
     "discord_token": "YOUR_TOKEN_HERE",
     "discord_prefix": "!"
   }
   ```
4. Invite the bot to your server:
   - Bot → OAuth2 → URL Generator → Scopes: `bot` → Permissions:
     `Send Messages`, `Embed Links`, `Read Message History`
   - Open the generated URL and add the bot to your server.
5. Select **Tool 5** from the menu to start the bot.

**Commands:**

| Command | Description |
|---------|-------------|
| `!ss start @Player` | Begin a screenshare session |
| `!ss next` | Advance to the next step |
| `!ss prev` | Go back one step |
| `!ss flag <reason>` | Record a suspicious finding |
| `!ss findings` | Show all recorded findings |
| `!ss pass` | Close with a PASS verdict |
| `!ss fail [reason]` | Close with a FAIL verdict |
| `!ss cancel` | Abort without a verdict |
| `!ss help` | Show all commands |

**Screenshare steps the bot walks through:**

1. Introduction & screen share request
2. Minecraft F3 debug screen
3. `.minecraft` folder inspection
4. Run Ocean Anti-Cheat
5. Analyse OAC results
6. Check Windows Prefetch
7. Check UserAssist registry
8. Check for recording/VM/debug software
9. Final verdict

---

### Tool 6 — Cheat Hash Database

**What it does:** A local SQLite database of known cheat file hashes
(MD5 + SHA-256).  You can scan individual files or entire folders and
get an instant match result.

**How to use:**
1. Select **Tool 6** from the menu.
2. The database is created automatically at `data/cheats.db` with example
   entries so you can see the format.
3. Replace the placeholder entries with real hashes from your moderation team.

**Key features:**

| Option | Description |
|--------|-------------|
| List entries | View all known hashes |
| Check a file | Hash a file and check for a match |
| Check a folder | Recursively scan all files in a folder |
| Add manually | Paste a hash directly |
| Auto-hash a file | Hash a file and add it in one step |
| Delete entry | Remove by ID |
| Export CSV | Share your hash list with other servers |
| Import CSV | Load a hash list from another server |

**CSV format:**
```csv
cheat_name,file_name,md5,sha256,notes
Wurst,wurst-7.0.jar,aabbcc...,001122...,Downloaded from wurst-client.tk
```

---

## 📁 Folder Structure

```
ss-toolkit/
├── main.py                  ← Launch everything from here
├── requirements.txt
├── config.json              ← Your config (create from config.example.json)
├── config.example.json      ← Template
├── README.md
├── tools/
│   ├── shared.py            ← Shared constants & helpers
│   ├── pdf_scanner.py       ← Tool 1
│   ├── prefetch_analyzer.py ← Tool 2
│   ├── userassist_decoder.py← Tool 3
│   ├── timeline_builder.py  ← Tool 4
│   ├── discord_bot.py       ← Tool 5
│   └── hash_database.py     ← Tool 6
└── data/
    ├── cheats.db            ← Auto-created SQLite database
    ├── timeline_events.json ← Events from Tools 2 & 3
    └── timeline.png         ← Rendered timeline output
```

---

## 💡 Tips for Staff

- **Always** tell the player you're recording before starting.
- Check the **run timestamps** carefully — cheats run _before_ joining your server
  are just as relevant as ones run after.
- A **clean OAC scan** does not guarantee innocence — OAC may not detect newer cheats.
  Cross-reference with Prefetch and UserAssist.
- When in doubt, **document everything** — screenshots + the `!ss findings` log.
- Add real cheat hashes to **Tool 6** as you find them, and share the CSV with
  other servers.

---

## ❓ Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| Win10 prefetch not parsing | Run `pip install mam` |
| Discord bot not responding | Check token in `config.json`; ensure bot has message read/send perms |
| Timeline renders blank | Check `data/timeline_events.json` exists and has entries |
| PDF scanner finds nothing | Make sure the PDF is the actual OAC output, not a screenshot |

---

## 📝 Licence

MIT — free to use, modify, and share.  If you improve the cheat list or
add new tools, consider contributing back to the community!
