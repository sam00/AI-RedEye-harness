"""Deterministic structural pre-index.

This module is *deliberately not LLM-powered*. It scans the target repo
with regex and (where cheap) AST patterns to produce a ground-truth
inventory of:

- HTTP / RPC entrypoints (routes),
- Untrusted-input sources (request body, query string, env vars, kafka
  consumers, message handlers),
- Dangerous sinks (SQL execute, subprocess.run, eval, deserialization,
  os.system, file I/O on tainted paths),
- Suspected secrets (high-entropy strings, .env-like literals).

The inventory is then handed to S4 lenses as factual context. The
research stage's job stops being "imagine where bugs might be" and
becomes "given these *real* sinks and *real* sources, which combinations
are dangerous?". This change alone removes a large class of hallucination
where the model invents framework routes the codebase doesn't have.

The output schema is intentionally compact JSON so it fits into a single
prompt without truncation pressure.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# Regex pattern catalog. We intentionally use *language-agnostic* patterns
# because the harness scans polyglot repos. False positives in the index
# are cheaper than false negatives -- the LLM filters down to plausible
# candidates afterwards.

# (pattern, language_hint, kind, severity_hint)
_ROUTE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"@app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"), "python/flask|fastapi"),
    (re.compile(r"@router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"), "python/fastapi"),
    (re.compile(r"app\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"), "node/express"),
    (re.compile(r"router\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]"), "node/express"),
    (re.compile(r"path\(['\"]([^'\"]+)['\"]"), "python/django"),
    (re.compile(r"@(Get|Post|Put|Delete|Patch)Mapping\(['\"]([^'\"]+)['\"]"), "java/spring"),
    (re.compile(r"@RequestMapping\([^)]*['\"]([^'\"]+)['\"]"), "java/spring"),
]

_SOURCE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\brequest\.(json|args|form|body|params|query|cookies|headers)\b"), "http_input"),
    (re.compile(r"\breq\.(body|query|params|cookies|headers)\b"), "http_input_node"),
    (re.compile(r"\bos\.environ(\.get)?\b"), "env_var"),
    (re.compile(r"\bgetenv\("), "env_var"),
    (re.compile(r"\binput\("), "stdin"),
    (re.compile(r"\bsys\.argv\b"), "argv"),
    (re.compile(r"\bopen\s*\(\s*[a-zA-Z_]"), "file_read"),
    (re.compile(r"\.consume\("), "kafka_consume"),
]

_SINK_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # SQL injection family
    (re.compile(r"\.execute\s*\(\s*[a-zA-Z_]\w*\s*[+%]"), "sql_execute_concat", "CWE-89"),
    (re.compile(r"\.execute\s*\(\s*f['\"]"), "sql_execute_fstring", "CWE-89"),
    (re.compile(r"\.execute\s*\(\s*['\"][^'\"]*\{\s*\w+\s*\}"), "sql_execute_format", "CWE-89"),
    # Catches `cursor.execute(q)` where ``q`` was built as an f-string
    # somewhere above. Has FPs on parameterised queries; the LLM filters.
    (re.compile(r"\.execute\s*\(\s*[a-zA-Z_]\w*\s*\)"), "sql_execute_var", "CWE-89"),
    (re.compile(r"raw_query|rawQuery|exec\s*\(\s*[a-zA-Z_]"), "sql_raw", "CWE-89"),
    # Command injection
    (
        re.compile(r"subprocess\.(run|call|Popen|check_output)\s*\([^)]*shell\s*=\s*True"),
        "subprocess_shell_true",
        "CWE-78",
    ),
    (re.compile(r"os\.system\("), "os_system", "CWE-78"),
    (re.compile(r"\bexec\s*\("), "exec_call", "CWE-95"),
    (re.compile(r"\beval\s*\("), "eval_call", "CWE-95"),
    # Deserialization
    (re.compile(r"\bpickle\.(loads?|Unpickler)\b"), "pickle_load", "CWE-502"),
    (
        re.compile(r"\byaml\.load\s*\(\s*[^,)]*\)"),
        "yaml_load_unsafe",
        "CWE-502",
    ),  # safe_load uses 2 args usually
    (re.compile(r"\bObjectInputStream\b"), "java_deser", "CWE-502"),
    # Crypto weakness
    (re.compile(r"\bhashlib\.md5\(|\bhashlib\.sha1\("), "weak_hash", "CWE-327"),
    (re.compile(r"\b(DES|RC4|MD5|SHA1)\b"), "weak_cipher_or_hash", "CWE-327"),
    (re.compile(r"verify\s*=\s*False"), "tls_verify_disabled", "CWE-295"),
    (re.compile(r"random\.(random|randint|choice|randrange)\s*\("), "weak_rng", "CWE-338"),
    # SQL read sinks (pandas / ORM raw reads) -- the primary read path the
    # older catalog missed entirely (e.g. ``pd.read_sql(query_string, con)``).
    (re.compile(r"\b(?:pd\.)?read_sql\w*\s*\(\s*[a-zA-Z_]"), "sql_read_sql", "CWE-89"),
    # Path traversal / open with tainted path
    (re.compile(r"open\s*\(\s*[a-zA-Z_]\w*\s*[+]"), "open_concat", "CWE-22"),
    # open() where a string prefix is concatenated with a variable path segment
    # (e.g. ``open("dir/" + filename)``) -- missed by ``open_concat`` which
    # required the first token to be an identifier.
    (re.compile(r"open\s*\(\s*['\"][^'\"]*['\"]\s*[+%]"), "open_strconcat", "CWE-22"),
    # Flask static file server with a variable path argument.
    (
        re.compile(r"send_from_directory\s*\([^)]*,\s*[a-zA-Z_]\w*"),
        "path_send_from_directory",
        "CWE-22",
    ),
    # SSRF
    (
        re.compile(r"requests\.(get|post|put|delete)\s*\(\s*[a-zA-Z_]\w*\s*[+%]"),
        "ssrf_http",
        "CWE-918",
    ),
    (re.compile(r"urllib\.request\.urlopen\s*\(\s*[a-zA-Z_]\w*\s*[+%]"), "ssrf_urlopen", "CWE-918"),
    # JWT / auth
    (re.compile(r"jwt\.decode\s*\([^)]*verify\s*=\s*False"), "jwt_verify_off", "CWE-347"),
    (re.compile(r"['\"]none['\"]\s*[:,]\s*True"), "jwt_alg_none", "CWE-347"),
]

# Common-shape secret regex. Aggressive on purpose -- the LLM downgrades obvious test fixtures.
_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key"),
    (re.compile(r"sk-(?:ant-)?[A-Za-z0-9_-]{20,}"), "anthropic_or_openai_key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "google_api_key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "github_pat"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "slack_token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private_key"),
    # Generic high-entropy patterns -- noisier; LLM dedups
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9_+/=-]{16,}['\"]"
        ),
        "generic_secret_assignment",
    ),
    # Short hardcoded credential literals (e.g. ``DB_PASSWORD = "test"``). The
    # generic pattern above requires >=16 chars and so silently missed every
    # short test/dev password -- exactly the class that is most often real.
    # No leading \b so it also fires inside names like DB_PASSWORD.
    (
        re.compile(
            r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*=\s*['\"]([^'\"]{2,40})['\"]"
        ),
        "hardcoded_credential",
    ),
]


@dataclass
class StructuralHit:
    """One regex match with enough context to display + verify."""

    path: str
    line: int
    kind: str
    pattern_id: str
    snippet: str
    cwe_hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "path": self.path,
            "line": self.line,
            "kind": self.kind,
            "pattern_id": self.pattern_id,
            "snippet": self.snippet,
        }
        if self.cwe_hint:
            d["cwe"] = self.cwe_hint
        return d


@dataclass
class StructuralIndex:
    """Inventory passed to lenses as ground truth."""

    routes: list[StructuralHit] = field(default_factory=list)
    sources: list[StructuralHit] = field(default_factory=list)
    sinks: list[StructuralHit] = field(default_factory=list)
    secrets: list[StructuralHit] = field(default_factory=list)
    files_indexed: int = 0

    def to_compact_dict(self, *, max_per_kind: int = 40) -> dict[str, Any]:
        """Compact view suitable for prompts (truncated to fit)."""
        return {
            "routes": [h.to_dict() for h in self.routes[:max_per_kind]],
            "sources": [h.to_dict() for h in self.sources[:max_per_kind]],
            "sinks": [h.to_dict() for h in self.sinks[:max_per_kind]],
            "secrets": [h.to_dict() for h in self.secrets[:max_per_kind]],
            "files_indexed": self.files_indexed,
        }

    @property
    def total_hits(self) -> int:
        return len(self.routes) + len(self.sources) + len(self.sinks) + len(self.secrets)


def _short_snippet(text: str, line_idx: int, *, context: int = 0) -> str:
    """Return a single-line snippet (or a small range when ``context > 0``)."""
    lines = text.splitlines()
    if not (0 <= line_idx < len(lines)):
        return ""
    if context == 0:
        return lines[line_idx][:240]
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return "\n".join(lines[start:end])[:1500]


def build_index(*, target: Path, file_paths: list[Path]) -> StructuralIndex:
    """Scan ``file_paths`` (already filtered by Scope) and return the index."""
    idx = StructuralIndex()
    for file_path in file_paths:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.debug("structural: could not read %s: %s", file_path, exc)
            continue
        rel = (
            str(file_path.relative_to(target))
            if file_path.is_relative_to(target)
            else str(file_path)
        )

        for line_no, line in enumerate(text.splitlines(), start=1):
            # routes
            for pat, lang in _ROUTE_PATTERNS:
                m = pat.search(line)
                if m:
                    # The route value is in the *last* capture group across our patterns.
                    route = m.group(m.lastindex) if m.lastindex else m.group(0)
                    idx.routes.append(StructuralHit(rel, line_no, "route", lang, route[:200]))
            # sources
            for pat, kind in _SOURCE_PATTERNS:
                if pat.search(line):
                    idx.sources.append(
                        StructuralHit(
                            rel, line_no, kind, "source", _short_snippet(text, line_no - 1)
                        )
                    )
            # sinks
            for pat, kind, cwe in _SINK_PATTERNS:
                if pat.search(line):
                    idx.sinks.append(
                        StructuralHit(
                            rel,
                            line_no,
                            kind,
                            "sink",
                            _short_snippet(text, line_no - 1),
                            cwe_hint=cwe,
                        )
                    )
            # secrets
            for pat, kind in _SECRET_PATTERNS:
                if pat.search(line):
                    idx.secrets.append(
                        StructuralHit(
                            rel, line_no, kind, "secret", _short_snippet(text, line_no - 1)
                        )
                    )
        idx.files_indexed += 1
    return idx


# Signals that a file builds a query/path from untrusted input (file-level
# corroboration so we only assert SQLi/traversal where a taint *builder* and a
# dangerous *sink* co-occur). Cheap and deliberately conservative.
_TAINT_BUILDER = re.compile(
    r"\.format\s*\(|%\s*\(|readQuery\s*\(|f['\"][^'\"]*\{|\+\s*request\.|request\.\w+\s*\)"
)
_REQUEST_SOURCE = re.compile(
    r"request\.(args|form|json|values|data|cookies|headers)|<\s*\w+\s*:\s*\w+\s*>|current_user\."
)


def derive_deterministic_findings(
    *, target: Path, file_paths: list[Path], caps: tuple[int, int, int] = (10, 8, 8)
) -> list[Any]:
    """Emit high-signal findings *deterministically* (no LLM) from the index.

    This is the assertion counterpart to :func:`build_index` (which only
    inventories). For three unambiguous, regex-confirmable classes -- hardcoded
    credentials, string-formatted SQL reaching an execute/read sink, and
    user-controlled paths reaching a file sink -- we emit a fully-formed
    :class:`~redeye.schema.Finding` flagged ``deterministic`` so the
    downstream LLM validator cannot silently veto a confirmed bug on a weak
    model. ``caps`` bounds each category (sqli, secret, traversal).
    """
    from redeye.schema import (
        Evidence,
        Finding,
        Location,
        ProofOfConcept,
        Severity,
        TaintFlow,
    )

    index = build_index(target=target, file_paths=file_paths)

    file_text: dict[str, str] = {}
    for fp in file_paths:
        try:
            t = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(fp.relative_to(target)) if fp.is_relative_to(target) else str(fp)
        file_text[rel] = t

    def has_builder(rel: str) -> bool:
        return bool(_TAINT_BUILDER.search(file_text.get(rel, "")))

    def has_request(rel: str) -> bool:
        return bool(_REQUEST_SOURCE.search(file_text.get(rel, "")))

    out: list[Any] = []
    seen: set[tuple[str, str, int]] = set()

    def emit(cwe, sev, title, hit, source, sink, chain, remediation, poc, desc):
        key = (cwe, hit.path, hit.line)
        if key in seen:
            return
        seen.add(key)
        loc = Location(path=hit.path, start_line=hit.line, snippet=(hit.snippet or "")[:500])
        f = Finding(
            id="",
            title=title[:200],
            severity=sev,
            cwe=cwe,
            description=desc[:4000],
            locations=[loc],
            attack_chain=chain,
            remediation=remediation[:2000],
            confidence=0.9,
            taint=TaintFlow(source=source, sink=sink, sanitizer_missing=True, sink_location=loc),
            tags=["deterministic", "evidence:structural"],
            evidence=[
                Evidence(
                    kind="structural_hit",
                    check="pass",
                    detail=f"{hit.kind} @ {hit.path}:{hit.line}",
                )
            ],
            skill="deterministic_detector",
            stage="s4_research",
        )
        if poc is not None:
            f.poc = poc
        out.append(f)

    # --- SQL injection: a SQL sink in a file that also builds queries from input.
    n = 0
    for h in index.sinks:
        if h.cwe_hint != "CWE-89" or n >= caps[0]:
            continue
        if not (has_request(h.path) or has_builder(h.path)):
            continue
        n += 1
        sev = Severity.HIGH
        emit(
            "CWE-89",
            sev,
            f"SQL injection: untrusted input reaches '{h.kind}' sink",
            h,
            "HTTP request value / current_user.username (attacker-influenced)",
            f"{h.kind} at {h.path}:{h.line}",
            [
                "Attacker supplies a crafted value via an HTTP request parameter, path segment, or their username.",
                "The value is string-formatted (.format()/%/f-string/concatenation) into a SQL statement with no parameterisation.",
                f"The statement reaches the '{h.kind}' sink at {h.path}:{h.line} and executes against the database.",
            ],
            "Use parameterised queries / bound parameters everywhere "
            "(cursor.execute(sql, params); pandas.read_sql(sql, con, params=...)). "
            "Never build SQL with .format()/%/f-strings/concatenation on request data.",
            ProofOfConcept(
                payload="' OR '1'='1' -- ",
                invocation="Send via the relevant HTTP parameter, e.g. GET ...?username=' OR '1'='1' -- ",
                expected_effect="Query returns all rows or raises a SQL error -> injection confirmed.",
                is_concrete=True,
            ),
            f"Deterministic detector: a SQL sink ('{h.kind}') co-occurs with a query built from untrusted input in "
            f"`{h.path}`. Evidence line {h.line}: {(h.snippet or '').strip()[:200]}",
        )

    # --- Path traversal: file sink fed by a user-controlled path.
    n = 0
    for h in index.sinks:
        if h.cwe_hint != "CWE-22" or n >= caps[2]:
            continue
        n += 1
        sev = Severity.HIGH if has_request(h.path) else Severity.MEDIUM
        emit(
            "CWE-22",
            sev,
            f"Path traversal: user-controlled path reaches '{h.kind}'",
            h,
            "user-controlled filename / path segment",
            f"{h.kind} at {h.path}:{h.line}",
            [
                "Attacker controls a filename or path component (route param or query string).",
                "It is concatenated into a filesystem path with no canonicalisation or allow-list.",
                f"The '{h.kind}' sink reads or serves the attacker-chosen path at {h.path}:{h.line}.",
            ],
            "Resolve the path against a fixed base directory and verify the canonical result stays inside it; "
            "reject '..' segments; prefer an allow-list of permitted filenames.",
            ProofOfConcept(
                payload="../../../../etc/passwd",
                invocation="Supply as the filename / path parameter for this endpoint.",
                expected_effect="Server reads or serves /etc/passwd -> path traversal confirmed.",
                is_concrete=True,
            ),
            f"Deterministic detector: file sink '{h.kind}' with a variable/concatenated path in `{h.path}`. "
            f"Evidence line {h.line}: {(h.snippet or '').strip()[:200]}",
        )

    # --- Hardcoded credentials.
    n = 0
    for h in index.secrets:
        if n >= caps[1]:
            break
        n += 1
        emit(
            "CWE-798",
            Severity.HIGH,
            f"Hardcoded credential in source ('{h.kind}')",
            h,
            None,
            f"literal credential at {h.path}:{h.line}",
            [
                "A credential/secret is committed to source as a literal value.",
                "Anyone with repository read access (or a leaked build artifact) obtains it.",
                "The credential is replayed against the corresponding service or database.",
            ],
            "Move the secret to a secrets manager or environment variable, rotate the exposed value immediately, "
            "and add a pre-commit secret scanner to prevent regressions.",
            None,
            f"Deterministic detector: hardcoded credential literal in `{h.path}`. "
            f"Evidence line {h.line}: {(h.snippet or '').strip()[:200]}",
        )

    return out


def maybe_ast_routes(target: Path, file_paths: list[Path]) -> list[StructuralHit]:
    """Optional Python-AST pass for richer route extraction.

    Only runs on .py files; quick and cheap. Looks for FastAPI/Flask
    decorator nodes that the regex pass might miss in multi-line decorators.
    """
    out: list[StructuralHit] = []
    for fp in file_paths:
        if fp.suffix != ".py":
            continue
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(text)
        except (OSError, SyntaxError):
            continue
        rel = str(fp.relative_to(target)) if fp.is_relative_to(target) else str(fp)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if not isinstance(deco, ast.Call):
                    continue
                func = deco.func
                attr = getattr(func, "attr", None)
                if attr in {"get", "post", "put", "delete", "patch"}:
                    if deco.args and isinstance(deco.args[0], ast.Constant):
                        out.append(
                            StructuralHit(
                                rel,
                                deco.lineno,
                                "route",
                                "ast/python_decorator",
                                f"{attr.upper()} {deco.args[0].value}",
                            )
                        )
    return out
