"""CVSS:3.1 vector + base score auto-computation.

The lens may emit a CVSS vector, but most don't bother. This module
fills the gap by computing a defensible vector + score from:

- **CWE family** -- determines the C/I/A impact and Scope.
- **Reachability** -- HTTP route exposure makes AV:N (Network); no route
  (local-only script, CLI tool) makes AV:L (Local).
- **Auth status** -- a route guarded by ``@require_auth`` etc. takes
  PR:L (Low privileges); an unguarded route takes PR:N (None).

The math is the standard CVSS v3.1 base-score formula. Keeping it
deterministic and self-contained avoids a heavy dependency.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# CVSS v3.1 metric weights (from the spec)
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Unchanged scope
_PR_WEIGHTS_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # Changed scope
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}


@dataclass(frozen=True)
class CvssMetrics:
    """The eight base-metric values that go into a CVSS:3.1 vector."""

    av: str = "N"  # Attack Vector: N|A|L|P
    ac: str = "L"  # Attack Complexity: L|H
    pr: str = "N"  # Privileges Required: N|L|H
    ui: str = "N"  # User Interaction: N|R
    s: str = "U"  # Scope: U|C
    c: str = "H"  # Confidentiality: N|L|H
    i: str = "H"  # Integrity: N|L|H
    a: str = "N"  # Availability: N|L|H

    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}"
            f"/S:{self.s}/C:{self.c}/I:{self.i}/A:{self.a}"
        )


# Per-CWE impact + scope defaults. These are starting points; the
# reachability adjustment refines AV/PR.
_CWE_DEFAULTS: dict[str, CvssMetrics] = {
    # SQL injection -- full DB compromise typical
    "CWE-89": CvssMetrics(c="H", i="H", a="L"),
    # OS command injection -- full host compromise
    "CWE-78": CvssMetrics(c="H", i="H", a="H"),
    # Code injection / eval
    "CWE-95": CvssMetrics(c="H", i="H", a="H"),
    "CWE-94": CvssMetrics(c="H", i="H", a="H"),
    # Deserialization -- RCE
    "CWE-502": CvssMetrics(c="H", i="H", a="H"),
    # Path traversal -- file read/write
    "CWE-22": CvssMetrics(c="H", i="L", a="N"),
    # SSRF -- can pivot to internal services (scope change)
    "CWE-918": CvssMetrics(s="C", c="L", i="L", a="N"),
    # XSS -- session takeover
    "CWE-79": CvssMetrics(ui="R", s="C", c="L", i="L", a="N"),
    # CSRF -- state-changing operations
    "CWE-352": CvssMetrics(ui="R", c="N", i="L", a="N"),
    # Hardcoded credentials -- local; high impact if leaked
    "CWE-798": CvssMetrics(av="L", c="H", i="H", a="N"),
    # Weak crypto -- depends; assume L/L
    "CWE-327": CvssMetrics(c="L", i="L", a="N"),
    "CWE-329": CvssMetrics(c="L", i="L", a="N"),
    # TLS verify disabled -- MitM
    "CWE-295": CvssMetrics(c="L", i="L", a="N"),
    # Weak RNG used for security
    "CWE-338": CvssMetrics(c="L", i="L", a="N"),
    # JWT verify off / alg none -- full session bypass
    "CWE-347": CvssMetrics(c="H", i="H", a="N"),
    # XXE -- file read + SSRF + DoS
    "CWE-611": CvssMetrics(c="H", i="L", a="L"),
    # Server-side template injection -- RCE in most templating engines
    "CWE-1336": CvssMetrics(c="H", i="H", a="H"),
    # Information disclosure
    "CWE-200": CvssMetrics(c="L", i="N", a="N"),
    # IDOR / missing object-level authz
    "CWE-639": CvssMetrics(c="H", i="L", a="N"),
    # Missing authentication on a critical resource
    "CWE-306": CvssMetrics(c="H", i="H", a="N"),
    # Missing authorization
    "CWE-862": CvssMetrics(c="H", i="H", a="N"),
}


def _impact_subscore(c: str, i: str, a: str, scope_changed: bool) -> float:
    """CVSS v3.1 impact subscore (ISC_Base then scope-adjusted ISC)."""
    isc_base = 1 - ((1 - _CIA_WEIGHTS[c]) * (1 - _CIA_WEIGHTS[i]) * (1 - _CIA_WEIGHTS[a]))
    if scope_changed:
        return 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
    return 6.42 * isc_base


def _exploitability(metrics: CvssMetrics) -> float:
    pr_table = _PR_WEIGHTS_C if metrics.s == "C" else _PR_WEIGHTS_U
    return (
        8.22
        * _AV_WEIGHTS[metrics.av]
        * _AC_WEIGHTS[metrics.ac]
        * pr_table[metrics.pr]
        * _UI_WEIGHTS[metrics.ui]
    )


def _round_up(x: float, places: int = 1) -> float:
    """CVSS spec: round up to one decimal place."""
    factor = 10**places
    return math.ceil(x * factor) / factor


def base_score(metrics: CvssMetrics) -> float:
    """Compute the CVSS v3.1 base score (0.0 - 10.0)."""
    impact = _impact_subscore(metrics.c, metrics.i, metrics.a, metrics.s == "C")
    if impact <= 0:
        return 0.0
    exploitability = _exploitability(metrics)
    if metrics.s == "C":
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    return _round_up(raw, 1)


def compute_cvss(
    *,
    cwe: str | None,
    has_http_route: bool = False,
    authenticated: bool = False,
    user_interaction: bool = False,
) -> tuple[str, float]:
    """Compute (vector, score) for a finding given its CWE + context.

    Parameters
    ----------
    cwe :
        The CWE-NNN identifier. Falls back to a medium default if unknown.
    has_http_route :
        If True, set AV:N (Network). If False, AV:L (Local).
    authenticated :
        If True, set PR:L (the attacker must authenticate first).
    user_interaction :
        If True, set UI:R (e.g. stored XSS, reflected XSS in user-pasted link).
    """
    base = _CWE_DEFAULTS.get((cwe or "").upper(), CvssMetrics(c="L", i="L", a="N"))

    # Reachability adjustment.
    av = "N" if has_http_route else base.av if base.av != "N" else "L"
    pr = "L" if authenticated else base.pr
    ui = "R" if user_interaction else base.ui

    final = CvssMetrics(av=av, ac=base.ac, pr=pr, ui=ui, s=base.s, c=base.c, i=base.i, a=base.a)
    score = base_score(final)
    return final.vector(), score
