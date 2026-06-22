# User guide

Complete reference for every CLI command and flag.

## Global flags

```text
redeye [-v|-vv] [--version] <command> [<args>]
```

| Flag | Effect |
|---|---|
| `-v`, `-vv` | Increase log verbosity (INFO, then DEBUG). |
| `--version` | Print version and exit. |
| `-h`, `--help` | Show help for any command. |

Environment variables:

| Var | Effect |
|---|---|
| `REDEYE_PROFILE` | Default profile name when `--profile` is absent. |
| `REDEYE_LOG_LEVEL` | Override log level (DEBUG/INFO/WARNING/ERROR). |
| `REDEYE_NO_NETWORK` | If `1`, refuse any backend that needs network. |

## `redeye setup`

Interactive setup helper.

```bash
redeye setup
redeye setup --install-agents
redeye setup --profile full
```

| Flag | Effect |
|---|---|
| `--install-agents` | Drop AI-agent operating instructions into the cwd. Existing files are not overwritten. |
| `--profile NAME` | Validate the named profile rather than the default. |

Output: a credential-status table and a 3-step "next steps" hint.

## `redeye doctor`

Verify the active profile is operable.

```bash
redeye doctor
redeye doctor --profile full
redeye doctor --no-network
```

| Flag | Effect |
|---|---|
| `--profile NAME` | Probe the named profile (default: active). |
| `--no-network` | Skip live backend probes; check credentials only. |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | All required backends are operable. |
| 1 | One or more backends failed. |

## `redeye estimate`

Print scope and rough cost ceiling. Makes no LLM calls.

```bash
redeye estimate --repo /path/to/target
redeye estimate --repo . --profile full
```

| Flag | Effect |
|---|---|
| `--repo PATH` | (required) Path to the target repo. |
| `--profile NAME` | Cost-model profile (default: active). |

The cost number is the worst-case sum of all `stages.*.max_budget_usd`
caps. Real spend is usually 30-60% lower.

## `redeye collect-feedback`

Ingest reviewer TP/FP marks from a PR comment body.

```bash
# from a file
redeye collect-feedback --comment-file /tmp/comment.md

# from stdin
gh issue comment view --json body | jq -r .body | redeye collect-feedback
```

| Flag | Effect |
|---|---|
| `--comment-file PATH` | Read the comment body from a file (default: stdin). |

Writes verdicts to the SQLite store at `$REDEYE_DB_PATH` or
`~/.redeye/scans.db`. The next scan that runs with `--use-feedback`
will pick them up.

See [`CI_AND_FEEDBACK.md`](CI_AND_FEEDBACK.md) for the full feedback-loop walkthrough.

## `redeye scan`

Run the full 9-stage pipeline.

```bash
# Single repo
redeye scan --repo /path/to/target --application-id 12345

# Batch
redeye scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones

# Custom output dir + dry run
redeye scan --repo . --output-dir ./out --dry-run
```

| Flag | Effect |
|---|---|
| `--repo PATH` | Single repo to scan. Mutually exclusive with `--repo-file`. |
| `--repo-file PATH` | CSV with columns `path[,application_id]` for batch. |
| `--profile NAME` | Profile to run with. |
| `--application-id ID` | Tag the scan with an external app id. |
| `--workspace PATH` | Root for batch scan output. |
| `--output-dir PATH` | Override output directory (single-repo only). |
| `--group-by-app` | Emit one report per app id in batch mode. |
| `--keep-clones` | Don't delete cloned repos after scanning. |
| `--dry-run` | Plan but do not execute LLM calls. |
| `--diff-only` | Only files changed vs `--pr-base` (PR-scan mode). |
| `--pr-base REF` | Base ref for `--diff-only` (default `main`). |
| `--exclude-path SUBSTR` | Drop files whose path contains this substring (repeatable). |
| `--max-files N` | Cap files scanned (0 = unlimited). |
| `--max-file-bytes N` | Skip files larger than N bytes. |
| `--max-total-bytes N` | Stop scanning once cumulative bytes exceed N. |
| `--custom-prompt-file PATH` | Markdown / text appended to every system prompt. |
| `--store-findings` | Persist scan + findings to the SQLite store. |
| `--use-feedback` | Inject prior TP/FP marks into S4 lens system prompts. |
| `--pr-comment PATH` | Write a PR-comment-shaped Markdown to PATH. |
| `--webhook-url URL` | POST a scan summary to this webhook. |
| `--webhook-type T` | Payload format: `slack` / `teams` / `discord` / `generic`. |

### CSV format

```csv
path,application_id
/repos/checkout-service,APP-001
/repos/billing-api,APP-002
```

Columns:

| Column | Required? | Notes |
|---|---|---|
| `path` (or `repo`) | yes | Absolute or repo-relative path. |
| `application_id` (or `app_id`) | no | Used for grouping with `--group-by-app`. |

### Output layout

For each target, under `<output_dir>/`:

```text
<module>_<timestamp>_report.md       # Markdown, human-readable
<module>_<timestamp>_report.sarif    # SARIF 2.1.0
<module>_<timestamp>_errors.jsonl    # one error per line, if any
run_manifest.json                    # canonical run record
run_manifest_<timestamp>.json        # archived copy of the same
```

The manifest contains, at minimum:

- tool name + version,
- profile name + config hash,
- target repo path + git SHA,
- start / end timestamps,
- per-stage results with token counts and dollar costs,
- overall finding count + dropped count.

Use it as the audit trail for any compliance program that asks "what
exactly did you scan, with which model, when, and at what cost".

## Running with an AI agent

After `redeye setup --install-agents`, an agent (Claude Code, Copilot,
Gemini CLI) reads its operating instructions from the dropped files and
will invoke the harness on your behalf rather than editing its source. See
[`../AGENTS.md`](../AGENTS.md) for the full operating contract.

## Limitations

See the **Limitations** section in [`../README.md`](../README.md) -- short
version: findings are LLM-generated triage candidates, runs are not
deterministic on temperature-capable backends, and budget caps are
per-stage rather than global.
