"""Terminal (rich) and JSON reporting."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table

STATUS_ICON = {
    "pass": "[green]✓[/]",
    "fail": "[red]✗[/]",
    "skip": "[yellow]–[/]",
    "error": "[red]![/]",
}


def render_report(report: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()

    table = Table(title=f"VeriCode · {report.get('target')}", show_lines=False)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Detail")
    for check in report.get("checks", []):
        table.add_row(
            check["name"],
            STATUS_ICON.get(check["status"], check["status"]),
            (check.get("detail") or "")[:200],
        )
    console.print(table)

    secrets = report.get("secrets") or []
    if secrets:
        st = Table(title=f"Secrets found: {len(secrets)}")
        st.add_column("Rule")
        st.add_column("File")
        st.add_column("Line")
        st.add_column("Severity")
        for s in secrets[:50]:
            st.add_row(s["rule"], s["file"], str(s["line"]), s["severity"])
        console.print(st)
    else:
        console.print("[green]✓ No hardcoded secrets detected[/]")

    if "cves" in report:
        cves = report["cves"] or []
        if cves:
            ct = Table(title=f"Dependency vulnerabilities: {len(cves)}")
            ct.add_column("Package")
            ct.add_column("Version")
            ct.add_column("ID")
            ct.add_column("Summary")
            for c in cves[:50]:
                ct.add_row(c["name"], c["version"], c["id"], c["summary"][:80])
            console.print(ct)
        else:
            console.print("[green]✓ No known vulnerabilities in dependencies[/]")

    console.print()
    color = "green" if report.get("ok", True) else "red"
    console.print(f"[bold]Result:[/] [{color}]{report.get('summary')}[/]")
