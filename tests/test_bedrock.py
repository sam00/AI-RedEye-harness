"""Bedrock backend credential detection."""

from __future__ import annotations

from redeye.backends.bedrock import BedrockBackend


def test_has_credential_false_without_aws_files_or_env(monkeypatch, tmp_path):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))

    backend = BedrockBackend({})
    assert backend.has_credential() is False


def test_has_credential_true_when_credentials_file_exists(monkeypatch, tmp_path):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("[default]\n")
    monkeypatch.setenv("HOME", str(tmp_path))

    backend = BedrockBackend({})
    assert backend.has_credential() is True
