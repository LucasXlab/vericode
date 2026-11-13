"""Regression tests: secret values must not leak into output by default.

A secret scanner that prints the secret it found is a liability — its own JSON
output ends up in CI logs, bug reports and chat pastes. Findings therefore mask
the secret value unless the caller explicitly asks for the raw text.
"""

import json

from click.testing import CliRunner

from vericode import core
from vericode.cli import main
from vericode.scanner import MASK

STRIPE_KEY = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
AWS_SECRET = "Q7vRt2LmZx9BpKd4NfGh6WsEjUy3IcOlA5TnQrSvXz"  # 44 chars, synthetic
ENTROPY_BLOB = "Zk8vQ2mNpLxR7tYbW4cD9hJ3sF6gH1kA0eU5rT8nV2qZ"


def _write(tmp_path, content):
    (tmp_path / "app.py").write_text(content)
    return tmp_path


def test_json_output_masks_secret_value(tmp_path):
    root = _write(tmp_path, f"stripe_key = '{STRIPE_KEY}'\n")
    result = core.run(root, json_output=True, no_cve=True)
    payload = json.dumps(result)
    assert STRIPE_KEY not in payload
    assert MASK in payload


def test_reveal_secrets_returns_raw_value(tmp_path):
    root = _write(tmp_path, f"stripe_key = '{STRIPE_KEY}'\n")
    result = core.run(root, json_output=True, no_cve=True, reveal_secrets=True)
    assert STRIPE_KEY in json.dumps(result)


def test_masking_keeps_assignment_context(tmp_path):
    root = _write(tmp_path, f'aws_secret_access_key = "{AWS_SECRET}"\n')
    result = core.run(root, json_output=True, no_cve=True)
    payload = json.dumps(result)
    assert AWS_SECRET not in payload
    assert "aws_secret_access_key" in payload
    assert MASK in payload


def test_high_entropy_blob_is_masked(tmp_path):
    root = _write(tmp_path, f"blob = '{ENTROPY_BLOB}'\n")
    result = core.run(root, json_output=True, no_cve=True)
    payload = json.dumps(result)
    assert ENTROPY_BLOB not in payload


def test_cli_json_does_not_leak_secret(tmp_path):
    root = _write(tmp_path, f"stripe_key = '{STRIPE_KEY}'\n")
    out = CliRunner().invoke(main, [str(root), "--json"])
    assert out.exit_code == 0
    assert STRIPE_KEY not in out.output
    assert MASK in out.output


def test_cli_reveal_secrets_flag_exposes_value(tmp_path):
    root = _write(tmp_path, f"stripe_key = '{STRIPE_KEY}'\n")
    out = CliRunner().invoke(main, [str(root), "--json", "--reveal-secrets"])
    assert out.exit_code == 0
    assert STRIPE_KEY in out.output


def test_report_still_finds_the_secret(tmp_path):
    """Masking must not weaken detection: the finding itself is still reported."""
    root = _write(tmp_path, f"stripe_key = '{STRIPE_KEY}'\n")
    result = core.run(root, json_output=True, no_cve=True)
    assert result["secrets"], "secret should still be reported"
    assert result["secrets"][0]["file"] == "app.py"
    assert result["secrets"][0]["line"] == 1
    assert result["ok"] is False
