import string

from vericode import scanner


def test_aws_access_key():
    aws = "AKIA" + "IOSFODNN7EXAMPLE"
    assert any(x.rule == "AWS Access Key" for x in scanner.scan_text("key = " + aws))


def test_private_key():
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIE...\n-----END " + "RSA PRIVATE KEY-----"
    assert any("Private Key" in x.rule for x in scanner.scan_text(pem))


def test_slack_token():
    slack = "xoxb" + "-1234567890-abcdefghij"
    assert any("Slack Token" in x.rule for x in scanner.scan_text("token = " + slack))


def test_jwt():
    head = "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    jwt = head + "A" * 40
    assert any(x.rule == "JWT" for x in scanner.scan_text("auth = " + jwt))


def test_generic_assignment():
    val = "abcdefghijklmnopqrstuvwxyz" + "012345"
    line = 'api_key = "' + val + '"'
    assert any("Generic" in x.rule for x in scanner.scan_text(line))


def test_entropy_string():
    blob = (string.ascii_letters + string.digits) * 2
    assert any("High-entropy" in x.rule for x in scanner.scan_text("x = " + blob))


def test_benign_no_false_positive():
    text = "def add(a, b):\n    return a + b\nname = 'alice'\nurl = 'https://example.com/path'"
    assert scanner.scan_text(text) == []


def test_scan_path_skips_git(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("password = supersecretpassword1234567890")
    secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
    (tmp_path / "code.py").write_text("token = '" + secret + "'")
    rules = [x.rule for x in scanner.scan_path(tmp_path)]
    assert any("Stripe" in r for r in rules)
    assert not any("supersecret" in x.snippet for x in scanner.scan_path(tmp_path))


def test_shannon_entropy_uniform_high():
    assert scanner.shannon_entropy("abcdefgh") > 2.5
    assert scanner.shannon_entropy("") == 0.0


def test_scan_path_single_file(tmp_path):
    file_path = tmp_path / "snippet.py"
    secret = "sk_live_" + "abcdefghijklmnopqrstuvwxyz012345"
    file_path.write_text("api_key = '" + secret + "'\n")

    findings = list(scanner.scan_path(file_path))
    assert len(findings) >= 1
    assert any("Stripe" in f.rule or "Generic" in f.rule for f in findings)
    assert findings[0].file == "snippet.py"

    # Exclude works for single file
    assert list(scanner.scan_path(file_path, exclude={"snippet.py"})) == []
