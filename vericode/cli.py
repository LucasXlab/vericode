"""VeriCode command-line entry point."""

from __future__ import annotations

import json as jsonlib
import sys
from pathlib import Path

import click
from rich.console import Console

from .core import run


@click.command()
@click.argument("target", default=".", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "json_output", is_flag=True, help="Output JSON instead of a pretty report.")
@click.option(
    "--strict", is_flag=True, help="Exit non-zero if any check fails or a secret/CVE is found."
)
@click.option("--no-cve", is_flag=True, help="Skip dependency CVE lookup (no network).")
@click.option("--exclude", "exclude", multiple=True, help="Relative path to exclude (repeatable).")
def main(
    target: Path, json_output: bool, strict: bool, no_cve: bool, exclude: tuple[str, ...]
) -> None:
    """VeriCode — verify AI-generated code actually works.

    Runs type-check, tests, secret-scan and (optional) CVE lookup on TARGET.
    """
    console = Console()
    try:
        result = run(
            target,
            json_output=json_output,
            no_cve=no_cve,
            exclude=set(exclude),
            console=console,
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure cleanly to the user
        console.print(f"[red]Error:[/] {exc}")
        sys.exit(2)

    if json_output:
        click.echo(jsonlib.dumps(result, indent=2, default=str))

    if strict:
        bad = (
            any(c["status"] in ("fail", "error") for c in result["checks"])
            or bool(result["secrets"])
            or bool(result["cves"])
        )
        if bad:
            sys.exit(1)


if __name__ == "__main__":
    main()
