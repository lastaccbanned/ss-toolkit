"""
pdf_scanner.py — Tool 1: Ocean Anti-Cheat PDF Parser
─────────────────────────────────────────────────────
Reads an OAC scan PDF and highlights every suspicious finding:
  • Lines that contain OAC flag keywords (FLAGGED, DETECTED, …)
  • Lines that mention known cheat client names
  • A summary count at the end

Usage (from menu or directly):
    python tools/pdf_scanner.py
"""

import os
import sys

try:
    import pdfplumber
    _PDF_AVAILABLE = True
except ImportError:
    pdfplumber = None  # type: ignore
    _PDF_AVAILABLE = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from tools.shared import CHEAT_CLIENT_NAMES, OAC_FLAG_KEYWORDS, SEVERITY_STYLE

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _classify_line(line: str) -> tuple[str, list[str]]:
    """
    Return (severity, [matched_keywords]) for a single line of PDF text.
    severity is one of 'critical', 'suspicious', or '' (clean / uninteresting).
    """
    low = line.lower()
    matched: list[str] = []

    # Check for OAC's own flag keywords first (higher severity)
    for kw in OAC_FLAG_KEYWORDS:
        if kw.lower() in low:
            matched.append(kw)

    # Check for cheat client names
    for kw in CHEAT_CLIENT_NAMES:
        if kw in low:
            matched.append(kw)

    if not matched:
        return "", []

    # Any OAC flag keyword → critical; cheat name only → suspicious
    if any(kw.upper() in OAC_FLAG_KEYWORDS for kw in matched):
        return "critical", matched
    return "suspicious", matched


def _extract_text(pdf_path: str) -> list[tuple[int, str]]:  # noqa: F821
    """
    Open the PDF and return a flat list of (page_number, line_text) tuples.
    """
    lines: list[tuple[int, str]] = []
    with pdfplumber.open(pdf_path) as pdf:
        for page_num, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            for raw_line in text.splitlines():
                stripped = raw_line.strip()
                if stripped:
                    lines.append((page_num, stripped))
    return lines

# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def scan_pdf(pdf_path: str) -> dict:
    """
    Scan *pdf_path* and return a results dict:
        {
            "path": str,
            "total_lines": int,
            "findings": [{"page": int, "line": str, "severity": str, "keywords": list}],
            "critical_count": int,
            "suspicious_count": int,
        }
    """
    lines = _extract_text(pdf_path)
    findings = []
    for page, line in lines:
        severity, keywords = _classify_line(line)
        if severity:
            findings.append({
                "page":     page,
                "line":     line,
                "severity": severity,
                "keywords": keywords,
            })

    critical   = sum(1 for f in findings if f["severity"] == "critical")
    suspicious = sum(1 for f in findings if f["severity"] == "suspicious")

    return {
        "path":             pdf_path,
        "total_lines":      len(lines),
        "findings":         findings,
        "critical_count":   critical,
        "suspicious_count": suspicious,
    }


def print_results(results: dict) -> None:
    """Pretty-print scan results to the terminal using Rich."""
    path   = results["path"]
    finds  = results["findings"]
    crit   = results["critical_count"]
    susp   = results["suspicious_count"]

    # ── Summary panel ──────────────────────────────────────────────────────
    colour = "red" if crit else ("yellow" if susp else "green")
    verdict = "⚠  SUSPICIOUS" if (crit or susp) else "✔  CLEAN"
    summary = (
        f"[bold]File:[/bold] {path}\n"
        f"[bold]Total lines scanned:[/bold] {results['total_lines']}\n"
        f"[bold red]Critical flags:[/bold red] {crit}\n"
        f"[bold yellow]Suspicious flags:[/bold yellow] {susp}\n"
        f"[bold]Verdict:[/bold] [{colour}]{verdict}[/{colour}]"
    )
    console.print(Panel(summary, title="[bold]OAC PDF Scan Summary[/bold]", border_style=colour))

    if not finds:
        console.print("\n[bold green]No suspicious findings detected.[/bold green]")
        return

    # ── Findings table ──────────────────────────────────────────────────────
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        show_lines=True,
        expand=True,
    )
    table.add_column("Page",     style="dim",  no_wrap=True, width=5)
    table.add_column("Severity", no_wrap=True, width=12)
    table.add_column("Matched Keywords", width=30)
    table.add_column("Line Text")

    for f in finds:
        sev   = f["severity"]
        style = SEVERITY_STYLE.get(sev, "")
        kws   = ", ".join(f["keywords"])
        table.add_row(
            str(f["page"]),
            f"[{style}]{sev.upper()}[/{style}]",
            f"[{style}]{kws}[/{style}]",
            f["line"][:120],  # cap long lines for readability
        )

    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    if not _PDF_AVAILABLE:
        console.print(
            "[red]pdfplumber is not installed.[/red]  "
            "Run:  [bold]pip install pdfplumber[/bold]"
        )
        return
    console.rule("[bold blue]Tool 1 — OAC PDF Scanner[/bold blue]")
    console.print(
        "Drop an [bold]Ocean Anti-Cheat[/bold] scan PDF here and this tool will "
        "flag every suspicious line.\n"
    )

    pdf_path = console.input("[bold]Enter path to PDF file:[/bold] ").strip().strip('"').strip("'")

    if not pdf_path:
        console.print("[red]No path entered. Returning to menu.[/red]")
        return

    if not os.path.isfile(pdf_path):
        console.print(f"[red]File not found:[/red] {pdf_path}")
        return

    console.print(f"\n[dim]Scanning {pdf_path} …[/dim]")

    try:
        results = scan_pdf(pdf_path)
    except Exception as exc:
        console.print(f"[red]Error reading PDF:[/red] {exc}")
        return

    print_results(results)

    # Offer to export a plain-text report
    save = console.input("\n[dim]Save a text report? (y/N):[/dim] ").strip().lower()
    if save == "y":
        report_path = pdf_path.rsplit(".", 1)[0] + "_ss_report.txt"
        with open(report_path, "w") as f:
            f.write(f"OAC Scan Report\n{'='*60}\n")
            f.write(f"File:            {results['path']}\n")
            f.write(f"Total lines:     {results['total_lines']}\n")
            f.write(f"Critical flags:  {results['critical_count']}\n")
            f.write(f"Suspicious flags:{results['suspicious_count']}\n\n")
            for find in results["findings"]:
                f.write(
                    f"[Page {find['page']}] [{find['severity'].upper()}] "
                    f"Keywords: {', '.join(find['keywords'])}\n"
                    f"  {find['line']}\n\n"
                )
        console.print(f"[green]Report saved to:[/green] {report_path}")


if __name__ == "__main__":
    main()
