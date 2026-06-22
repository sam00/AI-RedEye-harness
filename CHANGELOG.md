# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] -- 2026-06-19 -- hallucination-reduction layer

The 0.3 release is focused entirely on **less noise, more valid results,
and concrete attack paths**. The deepest design choice is that nothing
reaches the operator without surviving every cheap deterministic check
the harness knows how to run.

### Added

- **Structural pre-index (S1b)** -- a deterministic regex+AST pass that
  extracts real routes / sources / sinks / secrets before any LLM call.
  Module: ``redeye/structural.py``.
- **Grounding pass (S4b)** -- verifies every finding's cited file:line
  exists and contains tokens consistent with the claimed CWE family.
  Module: ``redeye/grounding.py``.
- **PoC gate (S8b)** -- demands a concrete exploit string per finding;
  placeholder PoCs trigger a one-notch severity demotion (or drop with
  ``--require-poc``). Module: ``redeye/skills/poc_gate.py``.
- **Taint flow schema** -- ``Finding.taint`` carries explicit ``source``,
  ``sink``, ``sanitizer_missing``, ``sanitizers_observed``,
  ``taint_path``. Lens prompts now demand this shape; findings without
  source + sink are rejected at parse time.
- **Evidence list** -- ``Finding.evidence`` accumulates pass/fail rows
  produced by the grounding pass and other checks. Surfaced in the
  Markdown report and SARIF properties.
- **Hallucination metrics** -- ``RunManifest.hallucination_metrics``
  carries ``raw_lens``, ``ungrounded_dropped``, ``ungrounded_downgraded``,
  ``validator_rejected``, ``voted_out``, ``missing_poc``. Surfaced in
  the Markdown report header and the manifest JSON.
- **SARIF codeFlows** -- when a finding has a taint path, SARIF emits
  it as ``codeFlows`` / ``threadFlows`` so GitHub Code Scanning renders
  the trace inline.
- **CLI flags** -- ``--strict-grounding`` (drop findings with
  fictional paths), ``--require-poc`` (drop findings without a real PoC).
- ``redeye/skills/lens_*.py`` rewritten with explicit rules
  about what to flag, what NOT to flag, and what negative observations
  to record.
- ``redeye/skills/validator.py`` upgraded to consult the
  grounding artifact and auto-reject ungrounded findings without
  spending a token.

### Changed

- ``mock`` and ``full`` profiles wire the new stages by default
  (deterministic stages cost zero tokens, so this is safe).
- Mock backend produces realistic taint-shaped findings + a concrete
  PoC stub so the new path is exercised in tests.
- Markdown report layout: per-finding sections now include taint flow,
  PoC, and evidence blocks; the header carries the quality-metrics
  table.

## [0.2.0] -- 2026-06-19

Renamed from `agenticsec-harness` to `redeye`. The package is
`redeye`; the CLI is `redeye` (with short alias `redeye`).
Pipeline architecture and existing API are unchanged for the core 9 stages.

### Added (operational layer)

- **PR-scan mode** -- `--diff-only` / `--pr-base` scopes the scan to files
  changed against a base branch (uses `git diff --name-only`).
- **DoS protection** -- `--max-files`, `--max-file-bytes`, `--max-total-bytes`.
- **Path exclusion** -- `--exclude-path` (repeatable substring match).
- **Custom prompt extension** -- `--custom-prompt-file` appended to every
  S4 lens system prompt.
- **Validator stage S6.5** -- new optional `s6b_validator` stage. Cheap
  single-pass TP/FP gate distinct from multi-agent voting. Findings get
  `validator_verdict` and `validator_rationale` fields.
- **PR comment writer** -- `--pr-comment PATH` emits a Markdown comment
  with `[ ] True Positive` / `[ ] False Positive` checkboxes and
  `<!-- vuln-id: ... scan-id: ... -->` markers for round-trip parsing.
- **Feedback loop** --
  - `--store-findings` persists scan + findings to SQLite at
    `~/.redteam-harness/scans.db` (override with `REDEYE_DB_PATH`).
  - `--use-feedback` loads prior reviewer TP/FP marks for the same repo
    and injects a compact summary into the S4 lens system prompt.
  - New `redeye collect-feedback` subcommand parses a PR
    comment body and writes verdicts back to the store.
- **Webhook notifications** -- `--webhook-url` + `--webhook-type
  slack|teams|discord|generic`, optional HMAC via `REDEYE_WEBHOOK_SECRET`.
- **GitHub Actions workflow** -- `.github/workflows/redteam-scan.yml`
  runs PR scan + full scan + feedback collection out of the box.
- **CVSS** -- `Finding` schema gained `cvss_vector` and `cvss_score`;
  SARIF emits both, plus a `security-severity` property override for
  GitHub Code Scanning.

### Added (multi-cloud LLM)

- **Bedrock backend** (`via: bedrock`) -- AWS Bedrock with the Claude
  Messages API shape. Lazy boto3 import; falls back to mock if missing.
- **Vertex / Gemini backend** (`via: vertex`) -- Google Cloud Vertex AI
  Gemini. Lazy `google-cloud-aiplatform` import.
- **Ollama backend** (`via: ollama`) -- plain HTTP to a local Ollama
  server for air-gapped / regulated environments.

### Changed

- CLI command renamed from `agenticsec` to `redeye` (alias `redeye`).
- Python package renamed from `agenticsec` to `redeye`.
- All env vars renamed `AGENTICSEC_*` -> `REDEYE_*`.
- Default profile `full.yaml` adds an opt-in S6.5 validator role.

### Roadmap (not yet implemented)

- Jira historical-context loader.
- Databricks feedback backend.
- "Update same comment" behavior for multi-commit PRs.
- Vector / SIEM log aggregation integration.

## [0.1.0] -- 2026-06-19

Initial release as `agenticsec-harness`. See
[the original release notes](#) for details.

[Unreleased]: https://github.com/example/redeye/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/example/redeye/releases/tag/v0.2.0
[0.1.0]: https://github.com/example/redeye/releases/tag/v0.1.0
