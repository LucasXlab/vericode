# Changelog

All notable changes to VeriCode. Versions follow SemVer; entries are derived from the actual commit history, not from plans.

## [Unreleased]

### Fixed — 2026-11-13
- **CI**: pin the runner to `ubuntu-24.04`. `ubuntu-latest` began resolving to Ubuntu 26.04, where `actions/setup-python@v5` no longer provides Python 3.9; every pull-request run failed at setup with `The version '3.9' ... was not found for Ubuntu 26.04` (`a13ab73`). The push run on `a13ab73` is green again across 3.9–3.13.
- **Install instructions**: the PyPI name `vericode` belongs to an unrelated 2025 package (a pylint/flake8 wrapper, Apache-2.0). Both READMEs now install from the repository, the PyPI badges were removed, and the distribution name is `vericode-cli` while the command stays `vericode`.
- **Hero demo**: `assets/demo.gif` was excluded by `*.gif` in `.gitignore`; added an explicit exception and embedded the GIF in both READMEs. The GIF is rendered from real CLI output (3 frames, 1000×520) — it is not a terminal capture made with `vhs`/`asciinema`.

### Changed — 2026-11-10
- Machine-readable `ok` field and plain-text `summary` in `--json` output (`b509f04`).
- `--strict` now treats `error` status as failure, with regression tests (`35ac14f`).
- `ruff format --check` added as a CI gate (`3464361`).
- Demo provenance corrected and feature screenshots embedded (`e271f93`, `db7d339`).

## [0.1.0] — 2026-11-10

Initial public release at <https://github.com/LucasXlab/vericode> (`8dd6e36`).

- One-command local verification: type-check, test run, hardcoded-secret scan, and keyless OSV dependency CVE lookup.
- Project detection for Python, Node, Go and Rust.
- Terminal report via `rich`, `--json` for machines, `--strict` for CI, `--no-cve` for offline use, `--exclude` for paths.
- Documentation: `README.md`, `README.zh-CN.md`, `SPEC.md`, `CONTRIBUTING.md`, `QA.md`, `LAUNCH.md`, MIT license.
- Visual assets: SVG logo, 1280×640 social preview, feature screenshots, demo GIF.

### Known limitations
- `--json` still includes the source `snippet` verbatim (the terminal table does not); redaction is planned.
- Coverage is 76% overall; `projects.py` (external command orchestration) is at 54%.
- Dependency CVE lookup contacts OSV by default; use `--no-cve` to stay fully offline.
- Secret rules are regex + Shannon entropy heuristics: expect false positives and false negatives. This is a pre-merge check, not a security proof.

## Not yet done

- No PyPI release under a non-conflicting name; no Git tag / GitHub Release yet.
- No external community posts (Show HN / Reddit / X / 中文社区) have been published; copy is prepared in `phase8/LAUNCH-FINAL.md`.
- Four external pull requests (#7–#10) are open and under review.
