"""Secret / sensitive-value scanner.

Local-first, dependency-free detection of likely hardcoded secrets using a set
of well-known patterns plus Shannon-entropy heuristics for long random strings.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    "vendor",
    ".tox",
    "site-packages",
}
MAX_FILE_BYTES = 1_000_000
TEXT_EXTS = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".go",
    ".rs",
    ".java",
    ".rb",
    ".php",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".env",
    ".txt",
    ".md",
    ".sh",
    ".bash",
    ".cfg",
    ".ini",
    ".lock",
    ".sql",
    "",
}

SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        "high",
    ),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "high"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    (
        "Slack Webhook",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
        "high",
    ),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "high"),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{24,}"), "high"),
    ("Stripe Restricted Key", re.compile(r"rk_live_[0-9A-Za-z]{24,}"), "high"),
    ("GitHub Token", re.compile(r"ghp_[0-9A-Za-z]{36}"), "high"),
    ("GitLab Token", re.compile(r"glpat-[0-9A-Za-z_-]{20,}"), "high"),
    ("npm Token", re.compile(r"npm_[0-9A-Za-z]{36}"), "high"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "high"),
    (
        "Generic Secret Assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{16,}['\"]"
        ),
        "medium",
    ),
]

_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# Deliberately excludes '/' and '+' so that URLs (which rely on '/') are not flagged as
# high-entropy secrets. Pure-alphanumeric random blobs (the common secret shape) still match.
_B64 = re.compile(r"\b[A-Za-z0-9]{40,}\b")
ENTROPY_THRESHOLD = 4.0


@dataclass
class Finding:
    rule: str
    file: str
    line: int
    snippet: str
    severity: str = "high"

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "severity": self.severity,
        }


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_text(path: Path) -> bool:
    if path.suffix.lower() not in TEXT_EXTS:
        return False
    try:
        with path.open("rb") as f:
            chunk = f.read(MAX_FILE_BYTES)
        chunk.decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


def scan_text(text: str, filename: str = "<text>") -> list[Finding]:
    findings: list[Finding] = []
    for idx, line in enumerate(text.splitlines(), 1):
        for name, pat, sev in SECRET_PATTERNS:
            if pat.search(line):
                findings.append(Finding(name, filename, idx, line.strip()[:120], sev))
                break
        for m in _HEX.findall(line) + _B64.findall(line):
            if len(m) >= 32 and shannon_entropy(m) >= ENTROPY_THRESHOLD:
                findings.append(
                    Finding(
                        "High-entropy string",
                        filename,
                        idx,
                        m[:60] + ("…" if len(m) > 60 else ""),
                        "low",
                    )
                )
    return findings


def scan_path(root: Path, exclude: set[str] | None = None) -> Iterator[Finding]:
    exclude = exclude or set()
    if root.is_file():
        if not _is_text(root):
            return
        if str(root) in exclude or root.name in exclude:
            return
        try:
            text = root.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return
        for f in scan_text(text, root.name):
            yield f
        return

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if SKIP_DIRS & set(path.parts) or any(p.endswith(".egg-info") for p in path.parts):
            continue
        rel = path.relative_to(root)
        if str(rel) in exclude:
            continue
        if not _is_text(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for f in scan_text(text, str(rel)):
            yield f
