import json

import requests

from vericode import deps


def test_parse_requirements(tmp_path):
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.19.0\nflask==2.0.1\n# comment\nsix>=1.16\n")
    d = deps._parse_requirements(p)
    names = {x.name for x in d}
    assert "requests" in names and "flask" in names
    assert all(x.ecosystem == "PyPI" for x in d)


def test_parse_package_lock(tmp_path):
    p = tmp_path / "package-lock.json"
    p.write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/left-pad": {"version": "1.3.0"},
                    "node_modules/ms": {"version": "2.1.3"},
                }
            }
        )
    )
    d = deps._parse_package_lock(p)
    assert {x.name for x in d} == {"left-pad", "ms"}


def test_parse_gomod(tmp_path):
    p = tmp_path / "go.mod"
    p.write_text(
        "module example.com/x\n\ngo 1.21\n\nrequire (\n"
        "\tgithub.com/foo/bar v1.2.3\n\tgithub.com/baz/qux v0.1.0 // comment\n)\n"
    )
    d = deps._parse_gomod(p)
    assert {"github.com/foo/bar", "github.com/baz/qux"} <= {x.name for x in d}


def test_parse_cargo_lock(tmp_path):
    p = tmp_path / "Cargo.lock"
    p.write_text(
        'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\n\n'
        '[[package]]\nname = "tokio"\nversion = "1.0.0"\n'
    )
    d = deps._parse_cargo_lock(p)
    assert {x.name for x in d} == {"serde", "tokio"}


def test_query_osv_mocked(monkeypatch):
    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulns": [{"id": "GHSA-xxxx", "summary": "bad"}]}

    def fake_post(*a, **k):
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)
    v = deps.query_osv([deps.Dependency("PyPI", "requests", "2.19.0")])
    assert len(v) == 1 and v[0].id == "GHSA-xxxx"


def test_query_osv_handles_failure(monkeypatch):
    def fake_post(*a, **k):
        raise requests.RequestException("boom")

    monkeypatch.setattr(requests, "post", fake_post)
    assert deps.query_osv([deps.Dependency("PyPI", "x", "1.0")]) == []


def test_parse_dependencies_dispatch(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    d = deps.parse_dependencies(tmp_path, "python")
    assert any(x.name == "requests" for x in d)


import time
from unittest.mock import patch

def test_query_osv_uses_cache(tmp_path, monkeypatch):
    # Redirect cache to tmp_path
    monkeypatch.setattr(deps, "CACHE_DIR", tmp_path / "cache")

    call_count = {"n": 0}

    class FakeResp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"vulns": [{"id": "GHSA-xxxx", "summary": "bad"}]}

    def fake_post(*a, **k):
        call_count["n"] += 1
        return FakeResp()

    monkeypatch.setattr(requests, "post", fake_post)

    dep = deps.Dependency("PyPI", "requests", "2.19.0")
    # First call hits network
    v1 = deps.query_osv([dep])
    assert call_count["n"] == 1
    assert len(v1) == 1

    # Second call should use cache
    v2 = deps.query_osv([dep])
    assert call_count["n"] == 1  # no additional call
    assert len(v2) == 1 and v2[0].id == "GHSA-xxxx"

    # Expired cache should re-query
    cache_file = list((tmp_path / "cache").glob("*.json"))[0]
    data = json.loads(cache_file.read_text())
    data["ts"] = time.time() - deps.CACHE_TTL - 10
    cache_file.write_text(json.dumps(data))
    v3 = deps.query_osv([dep])
    assert call_count["n"] == 2
    assert len(v3) == 1
