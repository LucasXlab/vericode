import io
import json

import requests
from click.testing import CliRunner
from rich.console import Console

from vericode import core, deps, report
from vericode.cli import main


def test_run_finds_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
    (tmp_path / "app.py").write_text("secret = '" + secret + "'\n")
    (tmp_path / "requirements.txt").write_text("")
    result = core.run(tmp_path, no_cve=True)
    assert result["secrets"]
    assert result["ok"] is False
    assert result["project_type"] == "python"
    assert any(c["name"] == "typecheck" for c in result["checks"])


def test_run_no_cve_uses_parse(tmp_path, monkeypatch):
    calls = {}

    def fake_query(d):
        calls["n"] = len(d)
        return []

    monkeypatch.setattr(deps, "query_osv", fake_query)
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    result = core.run(tmp_path, no_cve=False)
    assert "cves" in result
    assert calls.get("n", 0) >= 1


def test_run_all_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    (tmp_path / "requirements.txt").write_text("")
    res = core.run(tmp_path, no_cve=True)
    assert "All checks passed" in res["summary"]


def test_run_missing_path():
    try:
        core.run("/nonexistent/path/xyz-abc")
    except FileNotFoundError:
        return
    raise AssertionError("expected FileNotFoundError")


def test_json_output_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    (tmp_path / "requirements.txt").write_text("")
    res = core.run(tmp_path, json_output=True, no_cve=True)
    assert {"target", "project_type", "checks", "secrets", "cves", "summary", "ok"} <= set(
        res.keys()
    )
    assert res["ok"] is True
    assert "[" not in res["summary"], "JSON summary must be plain text, no rich markup"


def test_render_report(capsys, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    res = {
        "target": "/x",
        "project_type": "python",
        "checks": [{"name": "typecheck", "status": "pass", "detail": "ok", "summary": ""}],
        "secrets": [],
        "cves": [],
        "summary": "[green]All checks passed[/]",
    }
    console = Console(file=io.StringIO(), width=100)
    report.render_report(res, console)
    assert "VeriCode" in console.file.getvalue()


def test_cli_json(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    (tmp_path / "requirements.txt").write_text("")
    r = CliRunner().invoke(main, [str(tmp_path), "--json", "--no-cve"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert data["project_type"] == "python"


def test_cli_strict_fails_on_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(deps, "query_osv", lambda d: [])
    secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
    (tmp_path / "app.py").write_text("k='" + secret + "'\n")
    (tmp_path / "requirements.txt").write_text("")
    r = CliRunner().invoke(main, [str(tmp_path), "--strict", "--no-cve"])
    assert r.exit_code == 1


def test_cli_handles_request_error(monkeypatch):
    def boom(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "post", boom)
    assert deps.query_osv([deps.Dependency("PyPI", "x", "1.0")]) == []


def test_run_single_file_and_cli(tmp_path):
    file_path = tmp_path / "script.py"
    secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
    file_path.write_text("token = '" + secret + "'\n")

    res = core.run(file_path, json_output=True)
    assert res["target"] == str(file_path.resolve())
    assert res["project_type"] is None
    assert res["checks"] == []
    assert len(res["secrets"]) >= 1

    r = CliRunner().invoke(main, [str(file_path), "--json"])
    assert r.exit_code == 0
    data = json.loads(r.output)
    assert len(data["secrets"]) >= 1

    r_strict = CliRunner().invoke(main, [str(file_path), "--strict"])
    assert r_strict.exit_code == 1
