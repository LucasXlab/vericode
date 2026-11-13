# Changelog

All notable changes to VeriCode are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-11-13

### Fixed

- **Secret values are masked in output by default.** `--json` used to print the raw
  credential it had found (`snippet` held the untouched source line), which made the
  tool's own output unsafe to paste into CI logs, issue reports or chat. Findings now
  render as `api_key = '********'` and keep the file/line so you can jump to the
  offending line. The new `--reveal-secrets` flag opts back into raw values for local
  use. Detection behaviour is unchanged — only the printed value is masked.

### Added

- Regression tests covering the masking behaviour (`tests/test_redaction.py`).

## [0.1.0] - 2026-11-10

### Added

- Initial release: project detection (Python / Node / Go / Rust), type-check, test
  run, dependency-free secret scanning, keyless OSV dependency CVE lookup, and the
  `--json` / `--strict` / `--no-cve` / `--exclude` flags.
- CI workflow, bilingual README, demo assets.
