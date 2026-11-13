# Changelog

All notable changes to VeriCode are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/).
This file merges the entries written by the two parallel sessions; every item maps to a real commit.

## [Unreleased]

- Four external pull requests (#7–#10) are open and under review.
- No PyPI publication under a non-conflicting name, no Git tag, no GitHub Release yet.
- No external community posts (Show HN / Reddit / X / 中文社区); copy is prepared in `phase8/LAUNCH-FINAL.md`.

## [0.1.1] - 2026-11-13

### Fixed

- **Secret values are masked in output by default** (`c2f1753`, `397b93a`). `--json` used to print the raw credential it had found (`snippet` held the untouched source line), which made the tool's own output unsafe to paste into CI logs, issue reports or chat. Findings now render as `api_key = '********'` and keep the file/line so you can jump to the offending line. `--reveal-secrets` opts back into raw values for local use. Detection behaviour is unchanged — only the printed value is masked.
- **CI pinned to `ubuntu-24.04`** (`a13ab73`). `ubuntu-latest` began resolving to Ubuntu 26.04, where `actions/setup-python@v5` no longer provides Python 3.9; all pull-request runs failed at setup. The push run is green again across 3.9–3.13.
- Plain-text `summary` plus machine-readable `ok` in `--json` (`b509f04`); `--strict` treats `error` status as failure with regression tests (`35ac14f`).
- Demo provenance corrected, feature screenshots embedded (`e271f93`, `db7d339`).

### Added

- Regression tests for masking (`tests/test_redaction.py`).
- `ruff format --check` as a CI gate (`3464361`).
- This changelog, consolidated from both sessions' entries.

## [0.1.0] - 2026-11-10

Initial public release at <https://github.com/LucasXlab/vericode> (`8dd6e36`).

### Added

- One-command local verification: project detection (Python / Node / Go / Rust), type-check, test run, dependency-free secret scanning, keyless OSV dependency CVE lookup.
- `--json` for machines, `--strict` for CI, `--no-cve` for offline use, `--exclude` for paths; terminal report via `rich`.
- Bilingual README, `SPEC.md`, `CONTRIBUTING.md`, `QA.md`, `LAUNCH.md`, MIT license.
- Visual assets: SVG logo, 1280×640 social preview, feature screenshots, `assets/demo.gif`.

### Install note (fixed before the repository was rewritten)

The PyPI name `vericode` belongs to an unrelated 2025 package (a pylint/flake8 wrapper by a different author, Apache-2.0). Both READMEs therefore install from this repository, the PyPI badges were removed, the distribution name is `vericode-cli`, and the command remains `vericode`. `.gitignore` also carries `!assets/demo.gif` so the hero GIF is actually tracked.

### Known limitations

- Coverage is 76% overall; `projects.py` (external command orchestration) is at 54%.
- Dependency CVE lookup contacts OSV by default; use `--no-cve` to stay fully offline.
- Secret rules are regex + Shannon entropy heuristics: expect false positives and false negatives. This is a pre-merge check, not a security proof.
- The demo GIF is rendered from real CLI output (3 frames, 1000×520); `vhs` / `asciinema` were unavailable, so it is **not** a terminal recording.
