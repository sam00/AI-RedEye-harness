"""Secret-redaction tests for human-facing report text."""

from __future__ import annotations

import json
from pathlib import Path

from redeye.output.markdown import write_markdown_report
from redeye.redaction import MASK, redact_obj, redact_secrets
from redeye.schema import Finding, Location, Severity


def test_redacts_known_token_shapes() -> None:
    assert "sk-ant-" not in redact_secrets("key sk-ant-abcdefghijklmnopqrstuvwxyz1234")
    assert "AKIA" not in redact_secrets("aws AKIAIOSFODNN7EXAMPLE here")
    assert "ghp_" not in redact_secrets("token ghp_" + "a" * 36)
    out = redact_secrets("header.eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part_here")
    assert MASK in out


def test_redacts_assignment_keeps_key_name() -> None:
    out = redact_secrets('api_key: "supersecretvalue123"')
    assert "api_key" in out  # key name preserved
    assert "supersecretvalue123" not in out
    assert MASK in out


def test_non_secret_text_untouched() -> None:
    text = "def add(a, b):\n    return a + b\n"
    assert redact_secrets(text) == text


def test_redacts_compound_env_style_keys() -> None:
    # ``_`` is a word character, so a plain ``\b``-anchored key regex misses
    # UPPER_SNAKE compounds entirely -- these must all be masked.
    cases = [
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "AUTH_TOKEN=abcdef1234567890",
        "AZURE_CLIENT_SECRET=s3cr3tvalue",
        "SECRET_KEY=django-insecure-abc123def456",
    ]
    for line in cases:
        key, value = line.split("=", 1)
        out = redact_secrets(line)
        assert key in out  # key name preserved
        assert value not in out
        assert MASK in out


def test_redacts_short_credential_values() -> None:
    out = redact_secrets("pwd=abc12")
    assert "pwd" in out
    assert "abc12" not in out
    assert MASK in out


def test_redacts_client_secret_assignment() -> None:
    out = redact_secrets("client_secret: 9a8b7c6d5e4f0011")
    assert "client_secret" in out
    assert "9a8b7c6d5e4f0011" not in out
    assert MASK in out


def test_redacts_bearer_tokens() -> None:
    out = redact_secrets("Authorization: Bearer abcdef1234567890ABCDEF")
    assert "Bearer" in out  # scheme word preserved
    assert "abcdef1234567890ABCDEF" not in out
    assert MASK in out


def test_redacts_credentials_in_urls() -> None:
    out = redact_secrets("DATABASE_URL=postgres://u:SuperSecretPass@db:5432/app")
    assert "SuperSecretPass" not in out
    assert MASK in out
    assert "db:5432/app" in out  # non-secret URL parts preserved


def test_ordinary_code_lines_untouched() -> None:
    for line in (
        "def get(self, url): return self.session.get(url)",
        "x = compute_total(items)",
    ):
        assert redact_secrets(line) == line


def test_markdown_report_redacts_by_default(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="Hardcoded credential",
        severity=Severity.HIGH,
        description='Found api_key: "sk-ant-abcdefghijklmnopqrstuvwxyz1234" in config',
        locations=[Location(path="config/defaults.yaml", start_line=12)],
    )
    path = tmp_path / "r.md"
    write_markdown_report(path=path, target=tmp_path, application_id=None, findings=[f])
    text = path.read_text(encoding="utf-8")
    assert "sk-ant-abcdefghijklmnopqrstuvwxyz1234" not in text
    assert MASK in text


def test_markdown_report_redact_opt_out(tmp_path: Path) -> None:
    f = Finding(
        id="F-0001",
        title="t",
        severity=Severity.LOW,
        description="token ghp_" + "a" * 36,
        locations=[Location(path="a.py", start_line=1)],
    )
    path = tmp_path / "r.md"
    write_markdown_report(
        path=path, target=tmp_path, application_id=None, findings=[f], redact=False
    )
    assert "ghp_" + "a" * 36 in path.read_text(encoding="utf-8")


def test_redact_obj_walks_structure_and_masks() -> None:
    data = {
        "findings": [
            {"description": 'api_key: "supersecretvalue123"', "line": 12},
        ],
        "count": 1,
        "ok": True,
    }
    out = redact_obj(data)
    assert "supersecretvalue123" not in json.dumps(out)
    assert MASK in out["findings"][0]["description"]
    # Non-string scalars are left untouched.
    assert out["count"] == 1 and out["ok"] is True


def test_redact_obj_keeps_json_valid_with_escaped_quotes() -> None:
    # Regression: a code snippet whose secret value is wrapped in quotes used
    # to corrupt the manifest when redaction ran over *serialized* JSON -- the
    # regex ate the backslash of an escaped \" and left a bare quote. Redacting
    # the object's values (then serializing) must always yield parseable JSON.
    snippet = '    secret = os.environ.get("REDEYE_WEBHOOK_SECRET")'
    payload = {"stages": [{"findings": [{"snippet": snippet}]}]}
    text = json.dumps(redact_obj(payload), indent=2, sort_keys=True)
    reparsed = json.loads(text)  # must not raise
    assert MASK in reparsed["stages"][0]["findings"][0]["snippet"]
