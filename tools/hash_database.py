"""
hash_database.py — Tool 6: SQLite Cheat Hash Database
──────────────────────────────────────────────────────
A local SQLite database of known cheat-file hashes.

Features:
  • Add hashes manually or by hashing a local file (MD5 + SHA-256)
  • Check a file or a directory of files against the database
  • List all known hashes
  • Import / export as CSV
  • Pre-populated with labelled placeholder entries so you can see
    the format immediately — replace with real hashes from your team.

DB location:  data/cheats.db   (configurable via config.json)

Usage (from menu or directly):
    python tools/hash_database.py
"""

import csv
import hashlib
import io
import os
import sqlite3
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel

from tools.shared import load_config

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_DB = os.path.join("data", "cheats.db")

SEED_ENTRIES = [
    # These are *placeholder* entries so the database is not empty on first run.
    # Replace / supplement with real hashes from your moderation team.
    #
    # (cheat_name, file_name, md5, sha256, notes)
    (
        "Example-Wurst",
        "wurst-7.0.jar",
        "aabbccddeeff00112233445566778899",
        "0" * 64,
        "Example placeholder – replace with real hash",
    ),
    (
        "Example-Impact",
        "impact-4.9.jar",
        "112233445566778899aabbccddeeff00",
        "1" * 64,
        "Example placeholder – replace with real hash",
    ),
    (
        "ProcessHacker",
        "ProcessHacker.exe",
        "ffeeddccbbaa99887766554433221100",
        "f" * 64,
        "Legitimate tool sometimes used to hide processes during SS",
    ),
]


def _connect(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> sqlite3.Connection:
    """Create tables if they don't exist and seed example rows."""
    conn = _connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hashes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            cheat_name  TEXT    NOT NULL,
            file_name   TEXT,
            md5         TEXT    UNIQUE,
            sha256      TEXT    UNIQUE,
            added_at    TEXT    DEFAULT (datetime('now')),
            notes       TEXT
        )
    """)
    conn.commit()

    # Only seed if the table is completely empty
    if conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0] == 0:
        conn.executemany(
            "INSERT OR IGNORE INTO hashes (cheat_name, file_name, md5, sha256, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            SEED_ENTRIES,
        )
        conn.commit()
        console.print("[dim]Database initialised with example entries.[/dim]")

    return conn

# ─────────────────────────────────────────────────────────────────────────────
# Hash utilities
# ─────────────────────────────────────────────────────────────────────────────

def hash_file(path: str) -> tuple[str, str]:
    """Return (md5_hex, sha256_hex) for a file.  Reads in chunks."""
    md5    = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

# ─────────────────────────────────────────────────────────────────────────────
# CRUD operations
# ─────────────────────────────────────────────────────────────────────────────

def add_hash(conn: sqlite3.Connection, cheat_name: str, file_name: str,
             md5: str, sha256: str, notes: str = "") -> bool:
    """Insert a new hash entry.  Returns True on success, False if duplicate."""
    try:
        conn.execute(
            "INSERT INTO hashes (cheat_name, file_name, md5, sha256, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (cheat_name, file_name, md5.lower(), sha256.lower(), notes),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def check_hash(conn: sqlite3.Connection, md5: str | None = None,
               sha256: str | None = None) -> sqlite3.Row | None:
    """
    Return the matching row if *md5* or *sha256* is found in the database.
    Returns None if no match.
    """
    if md5:
        row = conn.execute(
            "SELECT * FROM hashes WHERE md5 = ?", (md5.lower(),)
        ).fetchone()
        if row:
            return row

    if sha256:
        row = conn.execute(
            "SELECT * FROM hashes WHERE sha256 = ?", (sha256.lower(),)
        ).fetchone()
        if row:
            return row

    return None


def list_hashes(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM hashes ORDER BY cheat_name, file_name"
    ).fetchall()


def delete_hash(conn: sqlite3.Connection, row_id: int) -> bool:
    cur = conn.execute("DELETE FROM hashes WHERE id = ?", (row_id,))
    conn.commit()
    return cur.rowcount > 0

# ─────────────────────────────────────────────────────────────────────────────
# CSV import / export
# ─────────────────────────────────────────────────────────────────────────────

CSV_COLUMNS = ["cheat_name", "file_name", "md5", "sha256", "notes"]


def export_csv(conn: sqlite3.Connection, path: str) -> None:
    rows = list_hashes(conn)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row[col] for col in CSV_COLUMNS})


def import_csv(conn: sqlite3.Connection, path: str) -> tuple[int, int]:
    """Returns (imported, skipped)."""
    imported = skipped = 0
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ok = add_hash(
                conn,
                row.get("cheat_name", "UNKNOWN"),
                row.get("file_name",  ""),
                row.get("md5",        ""),
                row.get("sha256",     ""),
                row.get("notes",      ""),
            )
            if ok:
                imported += 1
            else:
                skipped += 1
    return imported, skipped

# ─────────────────────────────────────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────────────────────────────────────

def print_hashes(rows: list) -> None:
    if not rows:
        console.print("[yellow]Database is empty.[/yellow]")
        return

    table = Table(
        title=f"Cheat Hash Database  ({len(rows)} entries)",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("ID",         width=4,  no_wrap=True)
    table.add_column("Cheat Name", min_width=18)
    table.add_column("File Name",  min_width=18)
    table.add_column("MD5",        min_width=34)
    table.add_column("SHA-256",    min_width=34)
    table.add_column("Notes")

    for row in rows:
        table.add_row(
            str(row["id"]),
            row["cheat_name"],
            row["file_name"] or "—",
            row["md5"]    or "—",
            row["sha256"] or "—",
            row["notes"]  or "",
        )
    console.print(table)


def print_match(match: sqlite3.Row) -> None:
    console.print(Panel(
        f"[bold red]⚠  HASH MATCH FOUND[/bold red]\n\n"
        f"  [bold]Cheat Name:[/bold]  {match['cheat_name']}\n"
        f"  [bold]File Name:[/bold]   {match['file_name'] or 'N/A'}\n"
        f"  [bold]MD5:[/bold]         {match['md5']    or 'N/A'}\n"
        f"  [bold]SHA-256:[/bold]     {match['sha256'] or 'N/A'}\n"
        f"  [bold]Notes:[/bold]       {match['notes']  or '—'}",
        title="[bold red]KNOWN CHEAT DETECTED[/bold red]",
        border_style="red",
    ))

# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    console.rule("[bold blue]Tool 6 — Cheat Hash Database[/bold blue]")

    cfg     = load_config()
    db_path = cfg.get("database_path", DEFAULT_DB)
    conn    = init_db(db_path)
    console.print(f"[dim]Database:[/dim] {db_path}\n")

    while True:
        count = conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]
        console.print(f"\n[dim]Entries in database:[/dim] {count}\n")
        console.print("  [bold]1.[/bold] List all entries")
        console.print("  [bold]2.[/bold] Check a file against the database")
        console.print("  [bold]3.[/bold] Check a folder of files")
        console.print("  [bold]4.[/bold] Add a hash manually")
        console.print("  [bold]5.[/bold] Add a file (auto-hash it)")
        console.print("  [bold]6.[/bold] Delete an entry by ID")
        console.print("  [bold]7.[/bold] Export to CSV")
        console.print("  [bold]8.[/bold] Import from CSV")
        console.print("  [bold]0.[/bold] Back to main menu\n")

        choice = console.input("[bold]Choice:[/bold] ").strip()

        # ── 1. List ───────────────────────────────────────────────────────────
        if choice == "0":
            break

        elif choice == "1":
            print_hashes(list_hashes(conn))

        # ── 2. Check file ─────────────────────────────────────────────────────
        elif choice == "2":
            path = console.input("[bold]File path:[/bold] ").strip().strip('"').strip("'")
            if not os.path.isfile(path):
                console.print("[red]File not found.[/red]")
                continue
            console.print("[dim]Hashing…[/dim]")
            md5, sha256 = hash_file(path)
            console.print(f"  MD5:     {md5}")
            console.print(f"  SHA-256: {sha256}")
            match = check_hash(conn, md5=md5, sha256=sha256)
            if match:
                print_match(match)
            else:
                console.print("[bold green]✔  No match found in database.[/bold green]")

        # ── 3. Check folder ───────────────────────────────────────────────────
        elif choice == "3":
            folder = console.input("[bold]Folder path:[/bold] ").strip().strip('"').strip("'")
            if not os.path.isdir(folder):
                console.print("[red]Folder not found.[/red]")
                continue

            matches_found = 0
            files = [
                os.path.join(root, fname)
                for root, _, fnames in os.walk(folder)
                for fname in fnames
            ]
            console.print(f"[dim]Scanning {len(files)} files…[/dim]")

            with console.status("[dim]Working…[/dim]"):
                for fpath in files:
                    try:
                        md5, sha256 = hash_file(fpath)
                        match = check_hash(conn, md5=md5, sha256=sha256)
                        if match:
                            console.print(f"\n[red]Match:[/red] {fpath}")
                            print_match(match)
                            matches_found += 1
                    except OSError:
                        pass  # skip unreadable files

            if matches_found == 0:
                console.print(f"[bold green]✔  Scanned {len(files)} files — no matches found.[/bold green]")
            else:
                console.print(f"\n[bold red]⚠  {matches_found} match(es) found.[/bold red]")

        # ── 4. Manual add ─────────────────────────────────────────────────────
        elif choice == "4":
            cheat_name = console.input("Cheat/tool name:  ").strip()
            file_name  = console.input("File name (optional):  ").strip()
            md5        = console.input("MD5 hash (or blank):  ").strip()
            sha256     = console.input("SHA-256 hash (or blank):  ").strip()
            notes      = console.input("Notes (optional):  ").strip()

            if not (md5 or sha256):
                console.print("[red]Must provide at least one hash.[/red]")
                continue

            ok = add_hash(conn, cheat_name, file_name, md5, sha256, notes)
            if ok:
                console.print("[green]Entry added.[/green]")
            else:
                console.print("[yellow]Duplicate — hash already exists in database.[/yellow]")

        # ── 5. Auto-hash a file ───────────────────────────────────────────────
        elif choice == "5":
            path = console.input("[bold]File to hash:[/bold] ").strip().strip('"').strip("'")
            if not os.path.isfile(path):
                console.print("[red]File not found.[/red]")
                continue

            md5, sha256 = hash_file(path)
            console.print(f"  MD5:     {md5}")
            console.print(f"  SHA-256: {sha256}")

            cheat_name = console.input("Cheat/tool name:  ").strip()
            notes      = console.input("Notes (optional): ").strip()

            ok = add_hash(conn, cheat_name, os.path.basename(path), md5, sha256, notes)
            if ok:
                console.print("[green]Entry added.[/green]")
            else:
                console.print("[yellow]Duplicate — hash already exists.[/yellow]")

        # ── 6. Delete ──────────────────────────────────────────────────────────
        elif choice == "6":
            id_str = console.input("Enter ID to delete: ").strip()
            try:
                row_id = int(id_str)
            except ValueError:
                console.print("[red]Invalid ID.[/red]")
                continue
            if delete_hash(conn, row_id):
                console.print(f"[green]Entry {row_id} deleted.[/green]")
            else:
                console.print("[yellow]ID not found.[/yellow]")

        # ── 7. Export CSV ─────────────────────────────────────────────────────
        elif choice == "7":
            path = console.input("Export path (blank = data/hashes.csv): ").strip() or "data/hashes.csv"
            export_csv(conn, path)
            console.print(f"[green]Exported to:[/green] {path}")

        # ── 8. Import CSV ─────────────────────────────────────────────────────
        elif choice == "8":
            path = console.input("CSV file path: ").strip().strip('"').strip("'")
            if not os.path.isfile(path):
                console.print("[red]File not found.[/red]")
                continue
            imported, skipped = import_csv(conn, path)
            console.print(f"[green]Imported {imported} entries.[/green]  Skipped {skipped} duplicates.")

        else:
            console.print("[red]Invalid choice.[/red]")

    conn.close()


if __name__ == "__main__":
    main()
