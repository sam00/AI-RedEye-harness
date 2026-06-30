"""Redact secrets from human-facing report text.

RedEye's structural index deliberately surfaces *suspected secrets* (so a
reviewer knows where to look), and LLM lenses sometimes quote snippets that
contain credentials. That's useful in the tool, but the Markdown report is
frequently pasted into tickets, chat and PR threads -- so we mask obvious
secret material before it lands on disk.

This is conservative on purpose: it targets well-known credential *shapes*
and ``key = value`` assignments for sensitive key names. It is a
defence-in-depth nicety, not a guarantee -- never treat a redacted report as
safe to publish without human review.
"""

from __future__ import annotations

import re

MASK = "***REDACTED***"

# Whole-block / well-known credential shapes. Order matters: PEM blocks first.
_PATTERNS: list[re.Pattern[str]] = [
    # PEM private key blocks (multi-line).
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    # JWTs (three base64url segments).
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    # OpenAI / Anthropic style keys (sk-, sk-ant-...).
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}\b"),
    # GitHub tokens.
    re.compile(r"\bgh[posru]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    # AWS access key id.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # Google API key.
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # Slack tokens.
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
]

# ``key = value`` / ``key: value`` for sensitive key names -> mask the value,
# keep the key so the report still reads sensibly.
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|secret[_-]?key|access[_-]?key|token|"
    r"password|passwd|pwd|client[_-]?secret|private[_-]?key)\b"
    r"(\s*[:=]\s*)"
    r"(['\"]?)([^'\"\s,;}{]{6,})(\3)"
)


def _mask_assignment(m: re.Match[str]) -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}{m.group(5)}"


def redact_secrets(text: str) -> str:
    """Return ``text`` with obvious secret material replaced by ``MASK``."""
    if not text:
        return text
    out = text
    for pat in _PATTERNS:
        out = pat.sub(MASK, out)
    out = _ASSIGNMENT_RE.sub(_mask_assignment, out)
    return out
