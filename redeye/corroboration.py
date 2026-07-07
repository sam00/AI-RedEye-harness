"""External-scanner corroboration (improvement #2).

RedEye already ingests third-party scanner output (Semgrep / CodeQL / Bandit
/ Trivy / SARIF) into the S1b structural inventory as candidate hotspots
(see :mod:`redeye.external`). This module turns that same signal into a
*verification* signal: when one of RedEye's own findings lands on the same
file / line-neighbourhood / CWE that an independent tool also flagged, that
agreement is one of the strongest true-positive predictors available -- and
it costs zero LLM tokens.

The matcher is deliberately conservative and pure (no pydantic, no schema
import) so it can be unit-tested in isolation and reused anywhere. It matches
on:

- **path** (normalised, basename-tolerant), AND
- **line proximity** (within ``line_tol`` lines), AND
- **CWE** when both sides declare one (a mismatched CWE at the same line is
  treated as *not* corroborating; a missing CWE on either side is tolerated).
"""

from __future__ import annotations

from dataclasses import dataclass


def _norm_path(p: str) -> str:
    return (p or "").replace("\\", "/").lstrip("./").lower()


def _norm_cwe(c: str | None) -> str:
    return (c or "").upper().strip()


@dataclass(frozen=True)
class CorroborationHit:
    """Describes which external finding corroborated a RedEye finding."""

    tool: str
    rule_id: str
    path: str
    line: int
    line_delta: int


def match_one(
    *,
    path: str,
    line: int,
    cwe: str | None,
    externals: list,
    line_tol: int = 3,
) -> CorroborationHit | None:
    """Return the closest corroborating external finding, or ``None``.

    ``externals`` is any iterable of objects exposing ``.path``,
    ``.start_line``, ``.cwe``, ``.tool`` and ``.rule_id`` (e.g.
    :class:`redeye.external.ExternalFinding`). Basename matching is allowed so
    a scanner that reports ``src/app/users.py`` still corroborates a finding
    citing ``app/users.py`` when the tails agree.
    """
    fp = _norm_path(path)
    fp_base = fp.rsplit("/", 1)[-1]
    fcwe = _norm_cwe(cwe)
    best: CorroborationHit | None = None
    for ext in externals:
        ep = _norm_path(getattr(ext, "path", ""))
        if not ep:
            continue
        same_file = ep == fp or ep.rsplit("/", 1)[-1] == fp_base
        if not same_file:
            continue
        eline = int(getattr(ext, "start_line", 0) or 0)
        delta = abs(eline - int(line or 0))
        if delta > line_tol:
            continue
        ecwe = _norm_cwe(getattr(ext, "cwe", None))
        if fcwe and ecwe and fcwe != ecwe:
            continue  # same spot, different bug class -> not corroboration
        if best is None or delta < best.line_delta:
            best = CorroborationHit(
                tool=str(getattr(ext, "tool", "external")),
                rule_id=str(getattr(ext, "rule_id", "")),
                path=getattr(ext, "path", path),
                line=eline,
                line_delta=delta,
            )
    return best


def annotate_findings(findings: list, externals: list, *, line_tol: int = 3) -> int:
    """Mark each finding that an independent scanner also flagged (improvement #2).

    Sets ``externally_corroborated`` / ``corroborating_tools`` and appends a
    passing ``external_corroboration`` Evidence row (imported lazily so this
    module stays schema-free for isolated testing). Returns the number of
    findings corroborated. Findings without a primary location are skipped.
    """
    if not externals:
        return 0
    from redeye.schema import Evidence  # local import: keep module schema-free

    hits = 0
    for f in findings:
        loc = f.locations[0] if getattr(f, "locations", None) else None
        if loc is None:
            continue
        hit = match_one(
            path=loc.path, line=loc.start_line, cwe=f.cwe, externals=externals, line_tol=line_tol
        )
        if hit is None:
            continue
        f.externally_corroborated = True
        if hit.tool not in f.corroborating_tools:
            f.corroborating_tools.append(hit.tool)
        f.evidence.append(
            Evidence(
                kind="external_corroboration",
                check="pass",
                detail=f"{hit.tool}:{hit.rule_id} at {hit.path}:{hit.line} (Δ{hit.line_delta})",
            )
        )
        if "corroborated" not in f.tags:
            f.tags.append("corroborated")
        hits += 1
    return hits
