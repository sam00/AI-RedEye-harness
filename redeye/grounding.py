"""Deterministic grounding pass.

For each candidate finding, this module verifies three things by reading
the actual source file:

1. **File exists.**           Path resolves to a real file under the target.
2. **Line range resolves.**   ``start_line`` is within the file.
3. **Snippet matches CWE.**   The cited line(s) contain tokens we expect for
                              the claimed CWE family.

Findings that pass all three become :py:attr:`Finding.grounded == True` and
keep their lens-assigned severity. Findings that pass (1) and (2) but fail
(3) get a ``weak-evidence`` tag and a confidence cap. Findings that fail
(1) or (2) are *hallucinations* -- they cite code that doesn't exist -- and
get a ``hallucinated`` tag. With ``--strict-grounding`` they are dropped
outright; without it they survive into the report's appendix.

The pass is cheap (file I/O, no LLM) and runs after S4 lens generation,
before S5 policy gate. That order is deliberate: we don't want to spend
adversarial-review tokens on findings whose cited lines don't exist.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from redeye.schema import Evidence, Finding

log = logging.getLogger(__name__)


# CWE-family token sets. The list is conservative: we accept a finding if
# *any* token from the family appears within +/- N lines of the cited line.
# This is a sanity check, not a proof. The model still has to do the
# reasoning -- this just keeps it honest about the file:line it cites.
_CWE_TOKENS: dict[str, list[re.Pattern]] = {
    "CWE-89": [  # SQL injection
        re.compile(
            r"(?i)(execute|raw_query|rawQuery|read_sql|query|cursor|prepare|select\s|insert\s|update\s|delete\s)"
        ),
        re.compile(r"(?i)(sql|sqlalchemy|psycopg|pymysql|mysql|sqlite|pyodbc|pd\.read|\.format\()"),
    ],
    "CWE-78": [  # OS command injection
        re.compile(r"(?i)\b(subprocess|os\.system|popen|exec|shell|child_process|spawn|/bin/)\b"),
    ],
    "CWE-22": [  # Path traversal
        re.compile(r"(?i)\b(open|read|join|path|file|fopen)\b"),
        re.compile(r"\.\./|%2e%2e"),
    ],
    "CWE-79": [  # XSS
        re.compile(
            r"(?i)\b(innerHTML|dangerouslySetInnerHTML|render_template|html|template|response\.write)\b"
        ),
    ],
    "CWE-352": [  # CSRF
        re.compile(r"(?i)\b(csrf|samesite|cookie|session|origin|referer)\b"),
    ],
    "CWE-502": [  # Deserialization
        re.compile(r"(?i)\b(pickle|yaml\.load|ObjectInputStream|marshal|unserialize|fromXML)\b"),
    ],
    "CWE-798": [  # Hardcoded credentials
        re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[=:]"),
        re.compile(r"['\"][A-Za-z0-9_+/=-]{16,}['\"]"),
    ],
    "CWE-327": [  # Weak crypto
        re.compile(r"(?i)\b(md5|sha1|des|rc4|ecb|hashlib|crypto|cipher)\b"),
    ],
    "CWE-295": [  # Improper certificate validation
        re.compile(r"(?i)\b(verify\s*=\s*false|insecure|tls|ssl|InsecureSkipVerify)\b"),
    ],
    "CWE-338": [  # Weak RNG for security
        re.compile(r"(?i)\b(random\.|math\.random|rand\(|srand)\b"),
    ],
    "CWE-918": [  # SSRF
        re.compile(r"(?i)\b(requests\.(get|post)|urlopen|fetch|http\.client|axios)\b"),
    ],
    "CWE-95": [  # Eval / code injection
        re.compile(r"(?i)\b(eval|exec|Function|new\s+Function|vm\.runIn)\b"),
    ],
    "CWE-347": [  # JWT misverification
        re.compile(r"(?i)\b(jwt|jsonwebtoken|verify|alg|none|algorithm)\b"),
    ],
    "CWE-200": [  # Information exposure
        re.compile(r"(?i)\b(log|logger|print|console\.log|stack|trace|exception|error)\b"),
    ],
}


@dataclass
class GroundingReport:
    """Roll-up of what the grounding pass did, attached to the stage result."""

    grounded: int = 0
    weak_evidence: int = 0
    hallucinated_path: int = 0
    hallucinated_line: int = 0
    dropped: int = 0
    notes: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.notes = []

    def to_dict(self) -> dict[str, int | list[str]]:
        return {
            "grounded": self.grounded,
            "weak_evidence": self.weak_evidence,
            "hallucinated_path": self.hallucinated_path,
            "hallucinated_line": self.hallucinated_line,
            "dropped": self.dropped,
            "notes": self.notes,
        }


def _resolve(target: Path, cited: str) -> Path | None:
    """Resolve a finding's cited path against the target. Reject paths
    that escape the target via ``..`` -- that's either a bug or an attempt
    to read outside the scan scope, both of which we refuse.
    """
    cited = cited.replace("\\", "/").lstrip("./")
    candidate = (target / cited).resolve()
    try:
        candidate.relative_to(target.resolve())
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    return candidate


def _read_window(path: Path, start_line: int, end_line: int | None, *, padding: int = 5) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    end = end_line or start_line
    lo = max(0, start_line - 1 - padding)
    hi = min(len(lines), end + padding)
    return "\n".join(lines[lo:hi])


def _cwe_family_tokens(cwe: str | None) -> list[re.Pattern]:
    if not cwe:
        return []
    cwe = cwe.upper().strip()
    return _CWE_TOKENS.get(cwe, [])


def _token_match(window: str, patterns: Iterable[re.Pattern]) -> bool:
    return any(p.search(window) for p in patterns)


def ground_one(*, finding: Finding, target: Path) -> Finding:
    """Mutate ``finding`` in place: append Evidence rows, set ``grounded``,
    apply ``weak-evidence`` / ``hallucinated`` tags as warranted.
    """
    if not finding.locations:
        finding.evidence.append(Evidence(kind="file_exists", check="fail", detail="no locations"))
        finding.tags.append("hallucinated:no-location")
        return finding

    # Validate the *primary* location only -- secondary locations are
    # narrative, not the truth claim.
    primary = finding.locations[0]
    resolved = _resolve(target, primary.path)
    if resolved is None:
        finding.evidence.append(
            Evidence(
                kind="file_exists", check="fail", detail=f"path {primary.path!r} does not exist"
            )
        )
        finding.tags.append("hallucinated:bad-path")
        return finding

    finding.evidence.append(Evidence(kind="file_exists", check="pass", detail=str(primary.path)))

    try:
        line_count = sum(1 for _ in resolved.open(encoding="utf-8", errors="replace"))
    except OSError:
        line_count = 0
    if not (1 <= primary.start_line <= line_count):
        finding.evidence.append(
            Evidence(
                kind="line_resolves",
                check="fail",
                detail=f"start_line {primary.start_line} out of range (file has {line_count} lines)",
            )
        )
        finding.tags.append("hallucinated:bad-line")
        return finding
    finding.evidence.append(
        Evidence(
            kind="line_resolves", check="pass", detail=f"line {primary.start_line} of {line_count}"
        )
    )

    # Snippet match: do tokens for the claimed CWE family appear in a small
    # window around the cited line?
    window = _read_window(
        resolved, primary.start_line, primary.locations[0].end_line if False else primary.end_line
    )
    patterns = _cwe_family_tokens(finding.cwe)
    if patterns:
        if _token_match(window, patterns):
            finding.evidence.append(
                Evidence(
                    kind="snippet_match",
                    check="pass",
                    detail=f"matched CWE-family tokens for {finding.cwe}",
                )
            )
            finding.grounded = True
            # Capture the window snippet so the report can show it without
            # the operator having to open the file. Truncate aggressively.
            primary.snippet = (primary.snippet or "")[:500] or window[:500]
        else:
            finding.evidence.append(
                Evidence(
                    kind="snippet_match",
                    check="fail",
                    detail=f"no CWE-family tokens for {finding.cwe} found within +/-5 lines",
                )
            )
            finding.tags.append("weak-evidence")
    else:
        # No token catalog for this CWE -- treat as soft pass.
        finding.evidence.append(
            Evidence(
                kind="snippet_match",
                check="unknown",
                detail=f"no token catalog for {finding.cwe or 'unknown CWE'}",
            )
        )
        finding.tags.append("weak-evidence")

    return finding


def ground_findings(
    *,
    findings: list[Finding],
    target: Path,
    strict: bool = False,
) -> tuple[list[Finding], list[Finding], GroundingReport]:
    """Run the grounding pass over ``findings``.

    Returns ``(kept, dropped, report)``. In ``strict`` mode, hallucinated
    findings are dropped from ``kept``; otherwise all findings survive but
    are tagged.
    """
    report = GroundingReport()
    kept: list[Finding] = []
    dropped: list[Finding] = []

    for f in findings:
        ground_one(finding=f, target=target)
        if "hallucinated:bad-path" in f.tags:
            report.hallucinated_path += 1
            if strict:
                report.dropped += 1
                dropped.append(f)
                continue
        elif "hallucinated:bad-line" in f.tags or "hallucinated:no-location" in f.tags:
            report.hallucinated_line += 1
            if strict:
                report.dropped += 1
                dropped.append(f)
                continue
        if "weak-evidence" in f.tags:
            report.weak_evidence += 1
            # Cap confidence so adversarial review knows to be skeptical.
            f.confidence = min(f.confidence, 0.5)
        if f.grounded:
            report.grounded += 1
        kept.append(f)
    return kept, dropped, report
