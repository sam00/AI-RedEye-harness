# RedEye

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen.svg)](pyproject.toml)
[![Output](https://img.shields.io/badge/output-SARIF%202.1.0-orange.svg)](docs/architecture.md)

`redeye` is an open-source agentic SAST harness for autonomous vulnerability discovery using frontier AI models. It pairs the deep multi-stage pipeline of an offline research harness with the operational layer of a CI/CD scanner — so the same tool runs as a researcher's deep-dive on Monday and as a PR gate on Tuesday.

Three design choices drive finding quality:

1. **Threat modeling before analysis** — focuses the attack surface so research lenses don't waste budget on low-impact areas.
2. **Multi-agent voting + a single-pass validator** — N-of-M voting kills correlated false positives; a cheap precision-filter validator drops the obvious garbage.
3. **Feedback loop** — reviewer TP / FP marks from PR comments persist to a local SQLite store and are fed back into the next scan as in-context calibration.

Multi-cloud LLM by design: Anthropic (CLI / SDK), OpenAI / OpenAI-compatible, **AWS Bedrock**, **Google Vertex (Gemini)**, **Ollama (local)**. No single provider is a dependency.

> **Authorized use only.** Run scans only against code you own or have explicit permission to test. Findings are LLM-generated triage candidates that require human review — see [Limitations](#limitations).

**Docs:** [`SETUP_GUIDE.md`](docs/SETUP_GUIDE.md) · [`USER_GUIDE.md`](docs/USER_GUIDE.md) · [`architecture.md`](docs/architecture.md) · [`SKILLS.md`](docs/SKILLS.md) · [`configuration.md`](docs/configuration.md).

---

## Quickstart (60 seconds, zero LLM cost)

```bash
git clone https://github.com/sam00/AI-RedEye-harness.git redeye
cd redeye
make install           # python3 -m venv + pip install -e ".[dev]"
make demo              # mock-backend scan against ./, writes ./out/*.md + .sarif
```

That's it -- you have a working install and a complete sample report in
`./out/`. The mock backend is deterministic, needs no API keys, and exercises
all 13 pipeline stages.

When you're ready to run with a real LLM:

```bash
make init              # interactive wizard: detects creds, writes .env, recommends profile
make scan-pr           # diff-only PR scan with strict grounding
make scan-ci           # bounded full-repo CI scan
make scan-deep         # research mode (no DoS limits, keep weakly-grounded triage candidates)
```

Or use the CLI directly with the same shortcuts:

```bash
redeye init                                # interactive setup
redeye scan --repo . --preset pr           # PR scan
redeye scan --repo . --preset ci           # CI scan
redeye scan --repo . --preset deep         # deep research
redeye scan --repo . --preset quick        # mock demo
```

Each `--preset` is just a default-overlay for the standard scan flags --
**any explicit flag you pass on the command line still wins**. So
`redeye scan --preset pr --max-files 200` keeps the PR-preset's strict
grounding and exclusions but bumps the file cap to 200.

| Preset | Backend | Scope | Grounding | Use when |
|---|---|---|---|---|
| `quick` | mock (no LLM cost) | small | lenient | trying the tool, CI smoke tests |
| `pr` | active profile | files changed vs `origin/main` | strict | every PR (mirrors the bundled GHA workflow) |
| `ci` | active profile | whole repo, DoS-capped | strict | nightly cron / `workflow_dispatch` |
| `deep` | active profile | unlimited | lenient (keeps weak-evidence) | research deep-dive |

---

## What's new in 0.3 -- the hallucination-reduction layer

Six new filters in front of the report, designed so a finding can't reach
the operator without surviving every cheap deterministic check the harness
knows how to run. See [`docs/REDUCING_HALLUCINATIONS.md`](docs/REDUCING_HALLUCINATIONS.md)
for the long-form rationale.

- **Structural pre-index (S1b, deterministic).** Regex/AST scan extracts
  the *real* routes / sources / sinks / secrets from the target before
  any LLM call. Lenses cite this inventory; they no longer get to invent
  paths.
- **Taint flow schema.** Every finding ships with explicit ``source``,
  ``sink``, ``sanitizer_missing``, and a step-by-step ``taint_path``.
  Hand-wavy findings without source + sink are dropped at parse time.
- **Grounding pass (S4b, deterministic).** Opens every cited file,
  verifies the line range, looks for CWE-family tokens in a +/-5 line
  window. Findings citing fictional code are tagged or (with
  ``--strict-grounding``) dropped.
- **Validator auto-reject (S6.5).** Skips the LLM call entirely for
  findings already tagged as hallucinated by S4b -- no point asking a
  model to confirm a bug that cites code which doesn't exist.
- **PoC gate (S8b).** Forces the model to write a concrete exploit
  payload -- syntactic checks reject placeholders. Findings without a
  real PoC get demoted by one severity notch (or dropped with
  ``--require-poc``).
- **Quality metrics in the manifest and report.** Counters for
  ``raw_lens``, ``ungrounded_dropped``, ``ungrounded_downgraded``,
  ``validator_rejected``, ``voted_out``, ``missing_poc``. Operators see
  exactly how much noise the harness pruned before they read anything.
- **Per-finding evidence list.** Every survivor carries a list of
  ``[PASS]`` / ``[FAIL]`` rows showing which checks it passed. The
  Markdown report renders this so reviewers can audit the harness's
  reasoning.
- **CodeFlows in SARIF.** When a taint path is present, SARIF emits it
  as a proper ``codeFlows`` / ``threadFlows`` block. GitHub Code
  Scanning renders this as an inline taint trace.

CLI additions:

```bash
redeye scan --repo .  --strict-grounding         # drop findings with bad paths
redeye scan --repo .  --require-poc              # drop findings without a runnable PoC
```

## Highlights -- the operational layer

Operational layer (CI/CD + feedback):

- **PR-scan mode** — `--diff-only --pr-base origin/main` only scans files changed in a PR.
- **DoS limits** — `--max-files`, `--max-file-bytes`, `--max-total-bytes`.
- **Path exclusion** — `--exclude-path` (repeatable).
- **Custom prompts** — `--custom-prompt-file` appended to every system prompt; useful for "focus on payment paths" or "ignore CWE-200 in /admin".
- **Validator stage (S6.5)** — single-pass TP/FP gate, distinct from voting; cheap on Haiku / Gemini Flash.
- **PR comment writer** — `--pr-comment ./out/comment.md` produces a Markdown comment with `[ ] True Positive` / `[ ] False Positive` checkboxes.
- **Feedback loop** — `--store-findings` persists to SQLite (`~/.redeye/scans.db`); `--use-feedback` injects prior TP / FP marks into the next scan's lens prompts.
- **`collect-feedback` subcommand** — parses a PR comment, writes verdicts to the store. Triggered by the `issue_comment.edited` GHA event.
- **Webhooks** — `--webhook-url` + `--webhook-type slack|teams|discord|generic` with optional HMAC signing via `REDEYE_WEBHOOK_SECRET`.
- **GitHub Actions workflow** — PR scan + full scan + feedback collection in one drop-in YAML at `.github/workflows/redeye-scan.yml`.
- **CVSS** — every finding can carry a `cvss_vector` and `cvss_score`; SARIF emits both, plus `security-severity` for GitHub Code Scanning.
- **New backends** — `bedrock` (AWS Claude), `vertex` (Gemini), `ollama` (local).

Agentic pipeline (from the 0.1 / 0.2 base):

- 3 phases / 9 stages (now 10 with optional validator).
- Multi-agent voting for FP suppression at S6.
- Per-stage budget caps.
- Skill-based extensibility.
- AGENTS.md / CLAUDE.md operating files.
- SARIF 2.1.0 + Markdown + run manifest.
- Multi-target batch scan.

Roadmap (not yet implemented; PRs welcome):

- Jira historical-context loader (pull prior vuln tickets for a service into the prompt).
- Databricks feedback backend (alternative to local SQLite).
- Update-same-comment behavior for multi-commit PRs.
- Vector / SIEM log aggregation.

---

## Pipeline

Three phases, ten stages (S6.5 is opt-in).

| Phase | Stages | Purpose |
|---|---|---|
| Discovery & Modeling | S1 – S3 | Attack surface mapping, threat modeling, hunting plan |
| Deep Dive & Verification | S4 – S6 (+ S6.5) | Multi-lens research, policy gate, adversarial review, multi-agent voting, optional validator |
| Synthesis, Chaining & Reporting | S7 – S9 | Deduplication, chain construction, SARIF emission |

See [`docs/architecture.md`](docs/architecture.md) for stage-by-stage detail.

---

## Skills

| Stage | Skill |
|---|---|
| S1 | Attack-surface mapper |
| S2 | AppSec threat modeler (STRIDE) |
| S3 | Vulnerability research strategist |
| S4 | Language / Crypto / Logic / Access-control / IaC research lenses |
| S6 | Adversarial reviewer |
| S6.5 | Single-pass validator (optional) |
| S8 | Exploit strategist |

See [`docs/SKILLS.md`](docs/SKILLS.md).

---

## Requirements

- **Python ≥ 3.10**
- An LLM credential — pick one:
  - Claude Code login (`claude login`) for the default `cli` profile
  - `ANTHROPIC_SDK_API_KEY` for `via: sdk`
  - `OPENAI_API_KEY` for `via: openai`
  - AWS creds + `bedrock` extra for `via: bedrock`
  - GCP creds + `vertex` extra for `via: vertex`
  - A running Ollama server for `via: ollama`
  - **Nothing** for `via: mock` — fully offline, deterministic, perfect for CI smoke tests.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install .                  # core
pip install ".[bedrock]"       # + AWS
pip install ".[vertex]"        # + GCP
pip install ".[all]"           # all optional backends
```

The package installs two console scripts: `redeye` (long form) and `redeye` (short alias).

## Configure

```bash
cp .env.example .env
```

Edit `.env` and fill in only what your active profile needs. The harness loads `.env` automatically by walking up parent directories from the working directory; shell-exported variables take precedence.

See [`docs/configuration.md`](docs/configuration.md) for the full env-var matrix and profile syntax.

## Run

```bash
# Health check
redeye doctor

# Scope and cost preview (no LLM calls)
redeye estimate --repo /path/to/target

# Full scan
redeye scan --repo /path/to/target --application-id 12345

# PR scan (only files changed vs origin/main)
redeye scan --repo . --diff-only --pr-base origin/main \
         --max-files 100 --max-file-bytes 500000 --max-total-bytes 5242880 \
         --exclude-path test --exclude-path vendor \
         --pr-comment ./out/comment.md \
         --store-findings --use-feedback

# Notify Slack on completion
redeye scan --repo . --webhook-url "$SLACK_URL" --webhook-type slack

# Ingest reviewer marks from a PR comment
echo "$COMMENT_BODY" | redeye collect-feedback
```

## GitHub Actions

Drop the prebuilt workflow into your repo:

```bash
mkdir -p .github/workflows
cp /path/to/redeye/.github/workflows/redeye-scan.yml .github/workflows/
```

It runs:

- **PR scan** on every pull request — diff-only, posts a Markdown comment with TP/FP checkboxes, uploads SARIF as an artifact.
- **Full scan** on `workflow_dispatch` — manual button in the Actions UI.
- **collect-feedback** on `issue_comment.edited` — when a reviewer ticks a TP/FP box, the verdict is persisted.

Configure repo Secrets / Variables: `ANTHROPIC_SDK_API_KEY`, `OPENAI_API_KEY`, `AWS_*`, `GOOGLE_CREDENTIALS`, `REDEYE_WEBHOOK_URL`, `REDEYE_PROFILE` (variable).

## Output

Per target, under `<output_dir>`:

- `<module>_<ts>_report.md` — Markdown report
- `<module>_<ts>_report.sarif` — SARIF 2.1.0
- `pr-comment.md` — (only with `--pr-comment`) Markdown shaped for `gh pr comment`
- `run_manifest.json` + `run_manifest_<ts>.json` — audit record (tool version, profile, config hash, target SHA, per-stage costs)

## Limitations

- **LLM-generated, non-deterministic.** Findings are triage candidates, not confirmed vulns. Two runs can differ.
- **Token-hungry.** Caps are per-stage. Use `redeye estimate` and the DoS limits.
- **Elevated privilege.** Run only against trusted repositories by authorized operators.
- **Feedback loop is local-first.** SQLite at `~/.redeye/scans.db` (configurable via `REDEYE_DB_PATH`). Databricks backend is on the roadmap.

See `docs/` for the full reference.

---

## Security

See [`SECURITY.md`](SECURITY.md). Don't open security issues in a public tracker.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
