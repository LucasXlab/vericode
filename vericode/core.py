"""Orchestration: run all checks on a target path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import deps, projects, report, scanner


def run(
    target: str | Path,
    *,
    json_output: bool = False,
    no_cve: bool = False,
    exclude: set[str] | None = None,
    console: Any = None,
    reveal_secrets: bool = False,
) -> dict[str, Any]:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {root}")

    if root.is_file():
        ptype = None
        checks: list[dict] = []
        secrets = [f.to_dict() for f in scanner.scan_path(root, exclude)]
        cves: list[dict] = []
        result: dict[str, Any] = {
            "target": str(root),
            "project_type": ptype,
            "checks": checks,
            "secrets": secrets,
            "cves": cves,
            # Same key as the directory path: a file that hides a secret is
            # not ok, and the JSON schema stays identical in both modes.
            "ok": not secrets,
            "summary": _summarize(checks, secrets, cves),
        }

        if not json_output:
            report.render_report(result, console)
        return result

    ptype = projects.detect_primary(root)
    checks = [
        projects.run_typecheck(root, ptype).to_dict(),
        projects.run_tests(root, ptype).to_dict(),
    ]
    secrets = [f.to_dict(reveal=reveal_secrets) for f in scanner.scan_path(root, exclude)]
    cves: list[dict] = []
    if not no_cve:
        dependencies = deps.parse_dependencies(root, ptype)
        cves = [v.to_dict() for v in deps.query_osv(dependencies)]

    ok = not (any(c["status"] in ("fail", "error") for c in checks) or secrets or cves)
    result: dict[str, Any] = {
        "target": str(root),
        "project_type": ptype,
        "checks": checks,
        "secrets": secrets,
        "cves": cves,
        "ok": ok,
        "summary": _summarize(checks, secrets, cves),
    }

    if not json_output:
        report.render_report(result, console)
    return result


def _summarize(checks: list[dict], secrets: list[dict], cves: list[dict]) -> str:
    """Plain-text summary (no rich markup — markup belongs to the report layer)."""
    fails = sum(1 for c in checks if c["status"] == "fail")
    skips = sum(1 for c in checks if c["status"] == "skip")
    parts: list[str] = []
    if fails:
        parts.append(f"{fails} check(s) FAILED")
    if secrets:
        parts.append(f"{len(secrets)} secret(s) found")
    if cves:
        parts.append(f"{len(cves)} vulnerable dep(s)")
    if not parts:
        base = "All checks passed"
        if skips:
            base += f" ({skips} skipped)"
        return base
    return "; ".join(parts)
