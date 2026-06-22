# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] -- 2026-06-19

Initial public release.

### Pipeline

13-stage agentic SAST pipeline grouped into three phases (Discovery &
Modeling -> Deep Dive & Verification -> Synthesis & Reporting). Five of
the stages are fully deterministic and never call an LLM (S1b structural
pre-index, S4b grounding pass, S5 policy gate, S7 dedupe, S6 voting
tally). The deterministic layers carry the precision burden so the
LLM-driven stages can be aggressive about discovery.

### Hallucination-reduction layer

- **Structural pre-index (S1b)** -- regex + AST extracts the real
  routes / sources / sinks / secrets before any LLM call.
- **Grounding pass (S4b)** -- verifies every cited file:line exists and
  contains tokens consistent with the claimed CWE family.
- **Validator (S6.5)** -- single-pass TP/FP gate; auto-rejects findings
  already tagged hallucinated by S4b without spending tokens.
- **PoC gate (S8b)** -- demands a concrete exploit payload; placeholder
  PoCs demote severity by one notch (or drop with `--require-poc`).
- **Taint flow schema** -- every finding ships with explicit `source`,
  `sink`, `sanitizer_missing`, and a step-by-step taint path.
- **Hallucination metrics** -- the run manifest carries counts of
  raw-lens findings, ungrounded drops, validator rejects, voted-out
  findings, and missing-PoC demotes so operators can see exactly what
  the pipeline pruned.

### Operational layer

- **PR-scan mode** -- `--diff-only --pr-base REF` scopes to files
  changed against a base branch.
- **DoS protection** -- `--max-files`, `--max-file-bytes`, `--max-total-bytes`.
- **Path exclusion** -- `--exclude-path` (repeatable substring match).
- **Custom prompt extension** -- `--custom-prompt-file` appended to every
  S4 lens system prompt.
- **PR comment writer** -- emits a Markdown comment with TP/FP
  checkboxes and machine-readable markers for the feedback loop.
- **Feedback loop** -- SQLite store at `~/.redeye/scans.db`. The
  `collect-feedback` subcommand parses checked PR comments and writes
  verdicts back; subsequent scans inject prior marks into lens prompts
  as calibration context.
- **Webhook notifications** -- Slack / Teams / Discord / generic, with
  optional HMAC signing.
- **CVSS** -- findings carry `cvss_vector` and `cvss_score` properties
  that flow into the SARIF `security-severity` field.

### First-run UX

- **`redeye init`** -- interactive wizard that detects available LLM
  credentials, recommends a profile, and writes a tailored `.env`.
- **`scan --preset {pr,ci,deep,quick}`** -- one flag substitutes for
  the common scan-flag combinations. Explicit CLI flags always win.
- **Makefile shortcuts** -- `make install`, `make demo`, `make scan-pr`,
  `make scan-ci`, `make scan-deep`.

### Backends

The same harness can route stages through any of:

- the local `claude` CLI (no API keys needed),
- the Anthropic SDK,
- OpenAI / OpenAI-compatible endpoints,
- AWS Bedrock,
- Google Vertex AI (Gemini),
- a local Ollama server,
- or the deterministic `mock` backend (zero LLM cost, used for CI and
  demos).

### Output

- SARIF 2.1.0 (with `codeFlows` for taint paths)
- Markdown report (taint flow, evidence, PoC, quality metrics)
- `run_manifest.json` (immutable audit trail)
- PR-comment Markdown (with TP/FP checkboxes)
- GitHub Actions workflow for PR scan + full scan + feedback collection

[Unreleased]: https://github.com/sam00/AI-Redteam/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/sam00/AI-Redteam/releases/tag/v0.3.0
