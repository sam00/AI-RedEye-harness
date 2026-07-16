# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Verification surfaced in every report.** The deterministic S8c outcome
  verdict (K-of-N over grounding, taint, PoC, reachability, voting, external
  corroboration) — already computed per finding — is now rendered in the
  Markdown (per-finding block + report-level *Verification summary*), the
  interactive HTML (verdict badge + signal chips), the PDF, and SARIF
  (`properties.verification`). Makes "validated & verified" auditable rather
  than asserted. Quality-metrics table now also reports `outcome_unverified`,
  `outcome_unverified_dropped`, and `baseline_filtered`.
- **Richer, triage-first HTML report.** The self-contained HTML now reaches
  Markdown parity (taint flow, PoC, evidence trail, votes, CVSS, verification
  signals), adds **Verified** and **Corroborated** filters, sorts
  verified+corroborated findings first, and includes a per-stage cost/timing
  table. Still zero external assets.
- **`redeye report <manifest>` command.** Regenerate any output format
  (`--format html|pdf|md|json|csv|all`) from an existing `run_manifest.json`
  with **no rescan** ($0, offline); `--open` launches the HTML in a browser.
  New module `redeye/commands/report.py`.
- **Flat `findings.json` / `findings.csv` export.** One-row-per-finding view
  (severity, CWE, CVSS, confidence, verified/corroborated flags, location,
  remediation) for dashboards, ticketing, and run-to-run diffs. Emitted by
  every `scan` and by `report`. New module `redeye/output/findings_export.py`.
- **Opt-in LLM response cache (`--cache` / `REDEYE_LLM_CACHE`).** Caches
  *deterministic* (temperature 0/None) completions on disk and reuses them on
  re-runs; stochastic sampling (voting/self-consistency) is never cached, so
  diversity is preserved. Cache hits report `$0` new spend. Off by default.
  New module `redeye/llm_cache.py`.
- **Labeled eval gate in CI.** The `ci` workflow now runs `redeye eval`
  against the bundled benchmark (uploading precision/recall/hallucination
  metrics) and exercises `redeye report --format all` in the smoke job.

- **Claude Fable 5 support.** New bundled `fable` profile routes the heavy
  research and adversarial stages through `claude-fable-5` on the `sdk`
  backend (cheap stages stay Haiku-class). Fable 5 pricing ($10/$50 per
  MTok in/out) added to the SDK cost table, and `REDEYE_PREFER_QUALITY=1`
  now upgrades the auto profile's SDK model to `claude-fable-5`. `fable` is
  now offered by the `init` wizard and listed in every profile enumeration.
- **Claude Opus 4.8 support.** `claude-opus-4-8` added to the SDK price
  table (Opus tier, $15/$75 per MTok in/out); selectable per-role in any
  `sdk` profile.
- **External-scanner corroboration signal (#2).** Findings that an
  independent tool (Semgrep/CodeQL/Bandit/Trivy/SARIF) also flagged now earn
  a distinct `externally_corroborated` signal in the S8c K-of-N verdict.
  Zero LLM cost. New module `redeye/corroboration.py`.
- **Graph/AST-backed grounding (#1).** S4b now confirms Python findings cite
  a real *call* to a sink-family function (AST), not just a nearby token,
  and can rescue findings the token catalog missed. New module
  `redeye/ast_grounding.py`.
- **Behavioral PoC oracle (#6).** S8b now proves a PoC payload would actually
  subvert the sink (SQLi/cmd-injection/path-traversal/SSRF/XSS/code-exec)
  instead of only checking that it *looks* concrete. New module
  `redeye/poc_oracle.py`; sets `poc_demonstrated`.
- **Two-key HIGH/CRITICAL promotion (#9).** Optional policy-gate rule: a
  finding may only report at HIGH/CRITICAL with a model confirmation AND
  (corroboration OR a demonstrated PoC); otherwise it is capped at MEDIUM.
- **Labeled-benchmark evaluation (#3).** New `redeye eval` command +
  `redeye/eval_harness.py` compute precision / recall / F1 / hallucination
  rate against a bundled benchmark (`redeye/eval/benchmark`), with CI gates
  (`--min-precision`, `--min-recall`, `--max-hallucination`).
- **Closed-set citation, self-consistency, evidence-quoting verdicts
  (#4/#5/#7).** Deterministic cores in `redeye/precision.py`: lenses may only
  cite inventory locations; recurring-across-samples aggregation; judge
  verdicts must quote real source (`unquoted-verdict` tag).
- **Calibrated confidence + abstention (#8).** `redeye/abstention.py` adds
  Platt scaling over reviewer history plus a confirm/uncertain/reject band
  that routes borderline findings to a human.
- **Per-finding provenance (#10).** Every finding is stamped with model,
  prompt hash, sampling params, and structural-index hash
  (`redeye/provenance.py`) for reproducibility and audit.
- **HTML + PDF reports.** Opt-in `--html` renders a self-contained
  interactive report (filter by severity/CWE/grounded); opt-in `--pdf`
  renders a styled PDF (needs `reportlab`). Markdown + SARIF remain the
  defaults. Modules `redeye/output/html.py` and `redeye/output/pdf.py`.
- **More first-class LLM models.** OpenAI `gpt-5.5`, `gpt-5.5-cyber`,
  `gpt-5.6`, and `gpt-5.6-sol` are now priced in the OpenAI cost table
  (best-effort 2026 premium-tier estimates, overridable per profile); any
  model an OpenAI-compatible endpoint accepts still works. `claude-opus-4-8`
  ("claude 4.8") remains in the SDK known-set and price table. Guarded by
  `tests/test_new_models.py`.

### Changed
- **Anthropic model-id refresh.** Bundled profiles and auto-detection now use
  `claude-sonnet-5` (was `claude-sonnet-4-6`) and the pinned
  `claude-haiku-4-5-20251001` (was `claude-haiku-4`); the stale
  `claude-opus-4-7` price row was dropped. A new `KNOWN_MODEL_IDS` guard warns
  before an unrecognized id 400s, and `tests/test_model_ids.py` asserts every
  `claude-*` id in a bundled profile is real.
- **Loud, truthful backend degradation.** When the SDK/CLI backend can't run
  (missing creds, bad id, error after retries) it now logs an error and labels
  the result `model="mock"`, so the manifest never claims a real model produced
  mock output. SDK calls retry transient failures (timeouts/429/5xx) via
  tenacity — never 400s/auth.
- **Two-key HIGH/CRITICAL policy moved S5 → S8c.** Its keys (validator/vote,
  PoC, corroboration) only exist after later stages, so applying it at the S5
  policy gate capped *every* HIGH/CRITICAL finding. Now evaluated at S8c;
  `tests/test_two_key.py` covers it. (A flag still set on S5 is honored.)
- **Profile referential-integrity validation.** `load_profile` rejects a
  profile routing a role via an unknown backend, or wiring a stage to an
  undefined role, with an actionable message — instead of failing deep in the
  pipeline.
- **Defense-in-depth redaction.** Secrets are redacted before the LLM cache
  and SARIF are written to disk; redaction also covers `UPPER_SNAKE` compounds,
  `Authorization: Bearer` tokens, and `scheme://user:pass@host` URLs. Cache
  files/dirs are created `0600`/`0700`.
- **`REDEYE_NO_NETWORK=1` kill-switch** is enforced at backend construction
  (only `mock` allowed), and webhook URLs are validated against an SSRF guard
  (blocks loopback/link-local/metadata addresses).
- **`--dry-run` truly skips paid stages** (a report is still emitted), and a
  voter crash degrades to "unvoted" instead of aborting the run.

### Fixed
- **Structural pre-index flagged comment-only lines.** The S1b scanner matched
  sink/source/secret regexes anywhere on a line, so security patterns appearing
  inside comments (example code in docstrings, commented-out code, or the
  detector's own rule comments when the harness scans itself) produced false
  positives. Comment-only lines (`#`, `//`, `/*`, `<!--`) are now skipped before
  matching; trailing comments are deliberately *not* stripped so a `#`/`//`
  inside a string literal (e.g. a URL in an SSRF sink) is still detected.
  Regression test added.
- **`redeye eval` crash.** The command constructed `Orchestrator` without the
  required `application_id`; now passed through, with a regression test.
- **AST grounding proximity window.** `sink_call_on_line` now defaults to a
  ±1-line window (was ±2), so a finding cited two lines away from the real
  sink is correctly rejected instead of spuriously grounded.

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

[Unreleased]: https://github.com/sam00/AI-RedEye-harness/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/sam00/AI-RedEye-harness/releases/tag/v0.3.0
