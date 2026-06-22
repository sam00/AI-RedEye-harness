"""Mock backend -- deterministic, no network, no credentials.

The mock backend returns a *structured* placeholder response that mimics what
real skills emit, so the rest of the pipeline (parsers, voters, dedupe,
SARIF) can run end-to-end. This is invaluable for CI smoke tests and for
demos where no API key is available.

The output is deterministic per (system, user) pair -- same inputs produce
the same output -- so tests can assert on it without flakiness.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from redeye.backends.base import BackendBase, CompletionResult


def _hash(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8"))
        h.update(b"|")
    return h.hexdigest()[:8]


# ---------------------------------------------------------------------------
# Per-skill stub payloads. Each helper returns a JSON-serialisable dict.
# Adding a new skill is two lines: one `_stub_*` function and one dispatch row.
# ---------------------------------------------------------------------------


def _stub_attack_surface(digest: str) -> dict[str, Any]:
    return {
        "entrypoints": [
            {"path": "src/api/main.py", "kind": "http", "framework": "fastapi"},
            {"path": "src/cli.py", "kind": "cli", "framework": "argparse"},
        ],
        "auth_boundaries": ["JWT middleware", "API key header"],
        "sensitive_sinks": ["sqlalchemy.text", "subprocess.run", "yaml.load"],
        "summary": f"Mock attack surface map (digest={digest}).",
    }


def _stub_threat_model(digest: str) -> dict[str, Any]:
    return {
        "actors": [
            "unauthenticated user",
            "authenticated low-privilege user",
            "compromised dependency",
        ],
        "trust_boundaries": ["http edge", "db connection", "subprocess fork"],
        "stride": [
            {"category": "Tampering", "asset": "request body", "score": "M"},
            {"category": "Information Disclosure", "asset": "logs", "score": "M"},
        ],
        "top_risks": [
            "SQL injection at /api/users/lookup",
            "secret leakage via default config",
        ],
        "summary": f"Mock threat model (digest={digest}).",
    }


def _stub_research_plan(digest: str) -> dict[str, Any]:
    return {
        "strategies": [
            {
                "name": "taint trace from /api/* to db.execute",
                "why": "raw SQL is present at the api/users handler",
                "where": "src/api/*.py",
            },
            {
                "name": "audit Dockerfile USER stanza",
                "why": "container may run as root",
                "where": "Dockerfile",
            },
        ],
        "summary": f"Mock research plan (digest={digest}).",
    }


def _stub_lens_findings(digest: str) -> dict[str, Any]:
    """Mock lens findings now include a fully populated taint block and an
    explicit evidence list, matching the 0.3 lens contract.

    These findings deliberately cite paths that may not exist in the target
    so the grounding pass (S4b) has something to reject -- it's how we test
    the hallucination-killer on every mock run.
    """
    return {
        "findings": [
            {
                "title": "SQL injection in user lookup",
                "severity": "high",
                "cwe": "CWE-89",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "cvss_score": 8.8,
                "path": "src/api/users.py",
                "start_line": 42,
                "end_line": 48,
                "description": (
                    f"Mock finding (digest={digest}). The lookup concatenates the "
                    "request-supplied `username` into a raw SQL string with no parameter binding."
                ),
                "remediation": (
                    "Use a parameterised query: "
                    "`db.execute(text('SELECT * FROM users WHERE name = :u'), {'u': username})`."
                ),
                "confidence": 0.7,
                "taint": {
                    "source": "request.json['username']",
                    "source_location": {"path": "src/api/users.py", "start_line": 38},
                    "sink": "cursor.execute(query)",
                    "sink_location": {"path": "src/api/users.py", "start_line": 46},
                    "sanitizer_missing": True,
                    "sanitizers_observed": [],
                    "taint_path": [
                        {"path": "src/api/users.py", "start_line": 38},
                        {"path": "src/api/users.py", "start_line": 42},
                        {"path": "src/api/users.py", "start_line": 46},
                    ],
                },
                "evidence": [
                    {
                        "kind": "structural_hit",
                        "check": "pass",
                        "detail": "Inventory lists sql_execute_fstring at this line.",
                    },
                    {
                        "kind": "negative_observation",
                        "check": "pass",
                        "detail": "No bindparams / parameterised marker in path.",
                    },
                ],
            },
            {
                "title": "Hardcoded API key in default config",
                "severity": "medium",
                "cwe": "CWE-798",
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N",
                "cvss_score": 4.4,
                "path": "config/defaults.yaml",
                "start_line": 12,
                "end_line": 12,
                "description": (
                    f"Mock finding (digest={digest}). Default config ships with a "
                    "non-empty `api_key` literal."
                ),
                "remediation": "Read the secret from $API_KEY at runtime; ship the file with an empty string.",
                "confidence": 0.85,
                "taint": {
                    "source": "config file literal",
                    "source_location": {"path": "config/defaults.yaml", "start_line": 12},
                    "sink": "deployed default value",
                    "sink_location": {"path": "config/defaults.yaml", "start_line": 12},
                    "sanitizer_missing": True,
                    "sanitizers_observed": [],
                    "taint_path": [{"path": "config/defaults.yaml", "start_line": 12}],
                },
                "evidence": [
                    {
                        "kind": "structural_hit",
                        "check": "pass",
                        "detail": "Inventory lists generic_secret_assignment at this line.",
                    }
                ],
            },
        ]
    }


def _stub_adversarial_review(digest: str) -> dict[str, Any]:
    return {
        "confirm": True,
        "attack_chain": [
            "Unauthenticated POST /api/v1/users/lookup",
            "username field passed unsanitised into raw SQL",
            "Database executes attacker-controlled WHERE clause",
        ],
        "notes": (
            f"Mock adversarial verification (digest={digest}). The reachability "
            "trace from entrypoint to sink is plausible."
        ),
        "confidence": 0.8,
    }


def _stub_exploit_polish(digest: str) -> dict[str, Any]:
    return {
        "attack_chain": [
            "Attacker sends crafted username payload to /api/v1/users/lookup",
            "Backend interpolates the value directly into SQL",
            "Backend executes the attacker-controlled query",
            "Attacker reads or modifies adjacent rows in the users table",
        ],
        "remediation": (
            "Replace the f-string interpolation with a parameterised query: "
            "`db.execute(text('SELECT * FROM users WHERE name = :u'), {'u': username})`."
        ),
    }


def _stub_voter(digest: str) -> dict[str, Any]:
    return {
        "verdict": "confirm",
        "rationale": (
            f"Mock voter (digest={digest}). The reachability claim is plausible "
            "given the location and CWE."
        ),
    }


def _stub_poc(digest: str) -> dict[str, Any]:
    return {
        "payload": "username=admin' OR 1=1 --",
        "invocation": (
            "curl -X POST http://localhost:8000/api/v1/users/lookup "
            "-H 'Content-Type: application/json' "
            "-d '{\"username\": \"admin\\u0027 OR 1=1 --\"}'"
        ),
        "expected_effect": (
            f"Mock PoC (digest={digest}). The malformed quote breaks out of the "
            "string literal in the SQL template, returning all rows from the users table."
        ),
    }


def _stub_response(system: str, user: str) -> str:
    """Return a stable JSON-shaped reply the skills know how to parse.

    Dispatch order matters: more specific cues first, since one stage's
    user prompt often quotes an artifact from an earlier stage.
    """
    digest = _hash(system, user)
    sys_l = system.lower()
    user_l = user.lower()

    payload: dict[str, Any]
    # --- S8b PoC gate -------------------------------------------------------
    # Detect the PoC prompt by the rare combination of "payload" + "invocation"
    # + "expected_effect" tokens in the system instructions.
    if (
        "payload" in sys_l
        and "invocation" in sys_l
        and "expected_effect" in sys_l
    ):
        payload = _stub_poc(digest)
    # --- voter (S6 multi-agent vote) ----------------------------------------
    elif "verdict" in sys_l and "confirm" in sys_l and "reject" in sys_l:
        payload = _stub_voter(digest)
    # --- S6 adversarial review (per finding) --------------------------------
    elif "adversarial reviewer" in sys_l or "reachability trace" in sys_l:
        payload = _stub_adversarial_review(digest)
    # --- S8 exploit strategist polish ---------------------------------------
    elif "polish the candidate" in sys_l or ("attack chain is a numbered list" in sys_l):
        payload = _stub_exploit_polish(digest)
    # --- S4 research lenses -------------------------------------------------
    elif (
        "lens" in sys_l
        or "lens" in user_l
        or "language-level vulnerabilities" in sys_l
        or "cryptographic weaknesses" in sys_l
        or "logic flaws" in sys_l
        or "access-control" in sys_l
        or "infrastructure-as-code" in sys_l
    ):
        payload = _stub_lens_findings(digest)
    # --- S2 threat modeler --------------------------------------------------
    elif "stride" in sys_l or "threat modeling" in sys_l:
        payload = _stub_threat_model(digest)
    # --- S3 research strategist --------------------------------------------
    elif "vulnerability research strategist" in sys_l:
        payload = _stub_research_plan(digest)
    # --- S1 attack-surface mapper ------------------------------------------
    elif "attack surface" in sys_l or "produce the attack surface" in user_l:
        payload = _stub_attack_surface(digest)
    else:
        payload = {
            "summary": f"Mock response for unrecognised prompt (digest={digest}).",
            "echo": user[:200],
        }

    return f"```json\n{json.dumps(payload, indent=2)}\n```"


class MockBackend(BackendBase):
    """Deterministic, no-network LLM stand-in. Always available."""

    name = "mock"

    def has_credential(self) -> bool:
        return True

    def health_check(self) -> bool:
        return True

    def complete(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int,
        temperature: float | None,
    ) -> CompletionResult:
        text = _stub_response(system, user)
        return CompletionResult(
            text=text,
            tokens_in=len(system.split()) + len(user.split()),
            tokens_out=len(text.split()),
            cost_usd=0.0,
            model=model or "mock-fast",
        )
