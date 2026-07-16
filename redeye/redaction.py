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
from typing import TypeVar, cast

MASK = "***REDACTED***"

_T = TypeVar("_T")

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
# keep the key so the report still reads sensibly. The key may be a compound
# name (``AWS_SECRET_ACCESS_KEY``, ``db.password``) as long as it *ends* with
# a sensitive word -- ``\b`` alone misses UPPER_SNAKE compounds because ``_``
# is a word character.
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.\-])"
    r"([A-Za-z0-9_.\-]*(?:password|passwd|pwd|secret|secret[_-]?key|token|"
    r"api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key))"
    r"(\s*[:=]\s*)"
    r"(['\"]?)([^'\"\s,;}{]{4,})(\3)"
)

# ``Authorization: Bearer <token>`` -- keep the scheme word, mask the token.
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{8,})")

# Credentials embedded in URLs (``scheme://user:password@host``) -> mask the password.
_URL_CREDS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:)([^/\s@'\"]+)@")


def _mask_assignment(m: re.Match[str]) -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}{MASK}{m.group(5)}"


def redact_secrets(text: str) -> str:
    """Return ``text`` with obvious secret material replaced by ``MASK``."""
    if not text:
        return text
    out = text
    for pat in _PATTERNS:
        out = pat.sub(MASK, out)
    out = _BEARER_RE.sub(rf"\g<1>{MASK}", out)
    out = _URL_CREDS_RE.sub(rf"\g<1>{MASK}@", out)
    out = _ASSIGNMENT_RE.sub(_mask_assignment, out)
    return out


def redact_obj(obj: _T) -> _T:
    """Recursively redact secret material in the string values of a JSON-like
    object (dicts, lists, scalars).

    Generic in the input type so callers keep their static type (e.g. a SARIF
    ``dict`` stays a ``dict``); the ``cast`` calls are no-ops at runtime.

    This is the JSON-safe entry point: redaction must run on the *structure*
    (before serialization), never on serialized JSON text. Running the
    assignment regex over already-serialized JSON can eat the backslash of an
    escaped ``\\"`` inside an embedded code snippet, leaving a bare quote that
    prematurely terminates the JSON string and corrupts the document. Operating
    on values lets the serializer re-escape correctly, so the output is always
    valid JSON.
    """
    if isinstance(obj, str):
        return cast(_T, redact_secrets(obj))
    if isinstance(obj, dict):
        return cast(_T, {k: redact_obj(v) for k, v in obj.items()})
    if isinstance(obj, list):
        return cast(_T, [redact_obj(v) for v in obj])
    return obj
