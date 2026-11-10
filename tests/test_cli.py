"""Regression tests for --strict exit-code semantics."""

from unittest.mock import patch

from click.testing import CliRunner

from vericode.cli import main


def _result(statuses):
    return {
        "checks": [{"status": s} for s in statuses],
        "secrets": [],
        "cves": [],
    }


def test_strict_fails_when_a_check_errors():
    with patch("vericode.cli.run", return_value=_result(["error"])):
        out = CliRunner().invoke(main, [".", "--strict"])
    assert out.exit_code == 1


def test_strict_still_fails_when_a_check_fails():
    with patch("vericode.cli.run", return_value=_result(["fail"])):
        out = CliRunner().invoke(main, [".", "--strict"])
    assert out.exit_code == 1


def test_strict_passes_when_everything_is_ok():
    with patch("vericode.cli.run", return_value=_result(["pass", "skip"])):
        out = CliRunner().invoke(main, [".", "--strict"])
    assert out.exit_code == 0
