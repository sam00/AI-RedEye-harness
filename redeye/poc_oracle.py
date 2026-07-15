"""Behavioral PoC oracle (improvement #6).

The S8b PoC gate historically decided whether a proof-of-concept was
"concrete" using *syntactic* checks -- does the payload contain a quote, a
``../``, a SQL keyword, etc. That catches empty placeholders but still
accepts a string that merely *looks* like an exploit without actually
demonstrating one.

This module goes one step further: for a safe subset of vulnerability
classes it applies a deterministic *oracle* that reasons about whether the
payload would actually subvert the sink. No code is executed and no network
is touched -- the oracles are pure string/AST analysis, so they run on every
backend and are fully unit-testable offline.

The output is a :class:`OracleVerdict`. A ``demonstrated=True`` verdict is a
strong true-positive signal (it feeds the S8c outcome verifier and the
two-key promotion policy); ``demonstrated=False`` never *drops* a finding on
its own -- it just withholds the extra confidence.

Design note: this module is intentionally free of ``pydantic`` and of any
``redeye`` schema import so it can be reused and tested in isolation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# CWE families the oracle understands. Anything else returns "unsupported".
SUPPORTED_CWES = frozenset({"CWE-89", "CWE-78", "CWE-22", "CWE-918", "CWE-79", "CWE-95"})


@dataclass(frozen=True)
class OracleVerdict:
    """Result of running the behavioral oracle over a single payload."""

    cwe: str | None
    demonstrated: bool
    vuln_class: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "cwe": self.cwe,
            "demonstrated": self.demonstrated,
            "vuln_class": self.vuln_class,
            "reason": self.reason,
        }


# --- SQL injection (CWE-89) -------------------------------------------------
# A payload demonstrates SQLi if it breaks out of the surrounding literal and
# either comments the tail out, injects a boolean tautology, stacks a query,
# or opens a UNION.
_SQLI_BREAKOUT = re.compile(r"""['"]""")
# Matches OR-based tautologies, tolerating the classic unbalanced trailing
# quote: OR 1=1 , OR '1'='1 , OR "a"="a" , OR 'x'='x
_SQLI_TAUTOLOGY = re.compile(r"(?i)\bor\b\s*['\"]?\s*\w+\s*['\"]?\s*=\s*['\"]?\s*\w+")
_SQLI_COMMENT = re.compile(r"(--|#|/\*)")
_SQLI_STACK = re.compile(r";\s*(drop|delete|update|insert|select|alter|create|;)", re.I)
_SQLI_UNION = re.compile(r"(?i)\bunion\b\s+(all\s+)?\bselect\b")


def _sqli(payload: str) -> OracleVerdict:
    breakout = bool(_SQLI_BREAKOUT.search(payload))
    signals = []
    if _SQLI_TAUTOLOGY.search(payload):
        signals.append("boolean-tautology")
    if _SQLI_COMMENT.search(payload):
        signals.append("comment-out-tail")
    if _SQLI_STACK.search(payload):
        signals.append("stacked-query")
    if _SQLI_UNION.search(payload):
        signals.append("union-select")
    # Boolean tautologies, UNION, and stacked queries are demonstrative even
    # without an explicit quote (the payload may be injected into a numeric
    # context). A bare comment-out only counts alongside a quote breakout.
    self_evident = {"boolean-tautology", "union-select", "stacked-query"}
    demonstrated = bool(signals) and (breakout or bool(self_evident & set(signals)))
    reason = (
        f"breakout={breakout}; signals={signals or 'none'}"
        if demonstrated
        else f"no injection escape proven (breakout={breakout}, signals={signals or 'none'})"
    )
    return OracleVerdict("CWE-89", demonstrated, "sql_injection", reason)


# --- OS command injection (CWE-78) -----------------------------------------
_CMD_METACHARS = re.compile(r"(;|\|\||&&|\||`|\$\(|\n|\$\{IFS\})")
_CMD_VERB = re.compile(
    r"(?i)\b(cat|ls|id|whoami|curl|wget|nc|ncat|bash|sh|powershell|ping|rm|touch|echo|nslookup)\b"
)


def _cmd(payload: str) -> OracleVerdict:
    meta = _CMD_METACHARS.search(payload)
    verb = _CMD_VERB.search(payload)
    demonstrated = bool(meta and verb)
    if meta and verb:
        reason = f"metachar={meta.group(0)!r} reaches command {verb.group(0)!r}"
    else:
        reason = "no shell metacharacter chaining a command was found"
    return OracleVerdict("CWE-78", demonstrated, "command_injection", reason)


# --- Path traversal (CWE-22) -----------------------------------------------
_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e(%2f|%5c)|\.\.%2f|\.\.%5c)", re.I)
_SENSITIVE_TARGET = re.compile(r"(?i)(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self)")


def _traversal(payload: str) -> OracleVerdict:
    hops = len(_TRAVERSAL.findall(payload))
    target = bool(_SENSITIVE_TARGET.search(payload))
    # Either a clearly-sensitive target, or at least two traversal hops
    # (a single "../" can appear in legitimate relative paths).
    demonstrated = target or hops >= 2
    reason = (
        f"traversal hops={hops}, sensitive_target={target}"
        if demonstrated
        else f"insufficient traversal evidence (hops={hops}, target={target})"
    )
    return OracleVerdict("CWE-22", demonstrated, "path_traversal", reason)


# --- SSRF (CWE-918) ---------------------------------------------------------
_URL = re.compile(r"(?i)\b(?:https?|gopher|file|ftp|dict)://([^/\s:]+)")
_INTERNAL_HOST = re.compile(
    r"(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata(\.google)?\.internal"
    r"|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|\[::1\])$"
)


def _ssrf(payload: str) -> OracleVerdict:
    m = _URL.search(payload)
    host = m.group(1) if m else ""
    internal = bool(host and _INTERNAL_HOST.match(host))
    demonstrated = internal
    reason = (
        f"payload targets internal/metadata host {host!r}"
        if demonstrated
        else f"no internal SSRF target proven (host={host or 'none'})"
    )
    return OracleVerdict("CWE-918", demonstrated, "ssrf", reason)


# --- XSS (CWE-79) -----------------------------------------------------------
_XSS = re.compile(
    r"(?i)(<script\b|onerror\s*=|onload\s*=|javascript:|<img\b[^>]*onerror|<svg\b[^>]*on)"
)


def _xss(payload: str) -> OracleVerdict:
    demonstrated = bool(_XSS.search(payload))
    reason = (
        "contains an executable HTML/JS injection vector"
        if demonstrated
        else "no active XSS vector found"
    )
    return OracleVerdict("CWE-79", demonstrated, "xss", reason)


# --- Code / eval injection (CWE-95) ----------------------------------------
_CODE_INJECT = re.compile(
    r"(?i)(__import__|os\.system|subprocess|eval\(|exec\(|;\s*import\s|\}\s*\)|\)\s*;)"
)


def _code(payload: str) -> OracleVerdict:
    demonstrated = bool(_CODE_INJECT.search(payload))
    reason = (
        "payload injects executable code tokens"
        if demonstrated
        else "no code-execution tokens found"
    )
    return OracleVerdict("CWE-95", demonstrated, "code_injection", reason)


_DISPATCH = {
    "CWE-89": _sqli,
    "CWE-78": _cmd,
    "CWE-22": _traversal,
    "CWE-918": _ssrf,
    "CWE-79": _xss,
    "CWE-95": _code,
}


def evaluate(payload: str, cwe: str | None) -> OracleVerdict:
    """Run the oracle for ``cwe`` over ``payload``.

    Returns ``demonstrated=False`` with ``vuln_class='unsupported'`` for CWEs
    the oracle doesn't model, so callers can distinguish "oracle says no" from
    "oracle can't judge this class".
    """
    payload = (payload or "").strip()
    if not payload:
        return OracleVerdict(cwe, False, "empty", "empty payload")
    key = (cwe or "").upper().strip()
    fn = _DISPATCH.get(key)
    if fn is None:
        return OracleVerdict(cwe, False, "unsupported", f"no oracle for {cwe or 'unknown CWE'}")
    return fn(payload)
