"""Dependency parsing (lockfiles) and CVE lookup via the keyless OSV API."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CACHE_DIR = Path.home() / ".cache" / "vericode"
CACHE_TTL = 86400  # 1 day


@dataclass
class Dependency:
    ecosystem: str
    name: str
    version: str

    def to_dict(self) -> dict:
        return {"ecosystem": self.ecosystem, "name": self.name, "version": self.version}


@dataclass
class Vuln:
    name: str
    version: str
    id: str
    summary: str

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "id": self.id, "summary": self.summary}


def _ver(v: str) -> str:
    return v.strip().lstrip("^~>=<").strip()


def _parse_requirements(path: Path) -> list[Dependency]:
    if not path.exists():
        return []
    out: list[Dependency] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            out.append(Dependency("PyPI", name.strip(), _ver(ver)))
    return out


def _parse_pipfile_lock(path: Path) -> list[Dependency]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Dependency] = []
    for sec in ("default", "develop"):
        for name, meta in (data.get(sec) or {}).items():
            ver = (meta or {}).get("version", "").lstrip("=")
            if ver:
                out.append(Dependency("PyPI", name, ver))
    return out


def _parse_package_lock(path: Path) -> list[Dependency]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    out: list[Dependency] = []
    for pkg, meta in (data.get("packages") or {}).items():
        if not pkg or not pkg.startswith("node_modules/"):
            continue
        name = pkg.split("node_modules/")[-1]
        ver = (meta or {}).get("version")
        if name and ver:
            out.append(Dependency("npm", name, ver))
    return out


def _parse_gomod(path: Path) -> list[Dependency]:
    if not path.exists():
        return []
    out: list[Dependency] = []
    in_req = False
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = line.strip()
        if s.startswith("require ("):
            in_req = True
            continue
        if in_req:
            if s == ")":
                in_req = False
                continue
            if not s or s.startswith("//"):
                continue
            parts = s.split()
            if len(parts) >= 2:
                out.append(Dependency("Go", parts[0], parts[1].strip()))
        elif s and not s.startswith("//") and " " in s:
            parts = s.split()
            if len(parts) == 2 and parts[1][0].isdigit():
                out.append(Dependency("Go", parts[0], parts[1].strip()))
    return out


def _parse_cargo_lock(path: Path) -> list[Dependency]:
    if not path.exists():
        return []
    out: list[Dependency] = []
    for block in path.read_text(encoding="utf-8", errors="ignore").split("[[package]]")[1:]:
        name = ver = None
        for line in block.splitlines():
            s = line.strip()
            if s.startswith("name ="):
                name = s.split("=", 1)[1].strip().strip('"')
            elif s.startswith("version ="):
                ver = s.split("=", 1)[1].strip().strip('"')
        if name and ver:
            out.append(Dependency("crates.io", name, ver))
    return out


def parse_dependencies(root: Path, ptype: str | None = None) -> list[Dependency]:
    deps: list[Dependency] = []
    if ptype in (None, "python"):
        deps += _parse_requirements(root / "requirements.txt")
        deps += _parse_pipfile_lock(root / "Pipfile.lock")
    if ptype in (None, "node"):
        deps += _parse_package_lock(root / "package-lock.json")
    if ptype in (None, "go"):
        deps += _parse_gomod(root / "go.mod")
    if ptype in (None, "rust"):
        deps += _parse_cargo_lock(root / "Cargo.lock")
    return deps


def _cache_key(d: Dependency) -> str:
    return f"{d.ecosystem}:{d.name}:{d.version}"


def _cache_path(d: Dependency) -> Path:
    key = _cache_key(d)
    h = hashlib.sha256(key.encode()).hexdigest()
    return CACHE_DIR / f"{h}.json"


def _get_from_cache(d: Dependency) -> list[Vuln] | None:
    path = _cache_path(d)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) > CACHE_TTL:
            return None
        return [
            Vuln(v["name"], v["version"], v["id"], v["summary"])
            for v in data.get("vulns", [])
        ]
    except (json.JSONDecodeError, OSError, KeyError):
        return None


def _save_to_cache(d: Dependency, vulns: list[Vuln]) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _cache_path(d)
        data = {
            "ts": time.time(),
            "vulns": [v.to_dict() for v in vulns],
        }
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass  # ignore cache write failures


def query_osv(deps: list[Dependency], timeout: int = 20) -> list[Vuln]:
    """Query OSV for each dependency. Keyless & anonymous; degrades to [] on error.
    Uses a disk TTL cache in ~/.cache/vericode keyed by ecosystem:name:version.
    """
    if not deps:
        return []
    vulns: list[Vuln] = []
    try:
        for d in deps:
            cached = _get_from_cache(d)
            if cached is not None:
                vulns.extend(cached)
                continue
            resp = requests.post(
                OSV_QUERY_URL,
                json={"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version},
                timeout=timeout,
            )
            resp.raise_for_status()
            dep_vulns = [
                Vuln(d.name, d.version, v.get("id", ""), v.get("summary", ""))
                for v in resp.json().get("vulns", [])
            ]
            _save_to_cache(d, dep_vulns)
            vulns.extend(dep_vulns)
    except (requests.RequestException, ValueError):
        return []
    return vulns
