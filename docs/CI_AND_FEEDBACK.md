# CI/CD integration & feedback loop

This document covers everything that's `redeye` 0.2 and isn't
strictly part of the agentic pipeline:

- PR scan vs full scan
- The PR comment + reviewer feedback round-trip
- Findings persistence (SQLite, with Databricks on the roadmap)
- Webhook notifications
- GitHub Actions workflow

If you only care about the AI side of things, [`architecture.md`](architecture.md)
is the right place to start.

## PR scan vs full scan

| Mode | Trigger | What it scans | When to use |
|---|---|---|---|
| **PR scan** | `--diff-only --pr-base origin/main` | Only files changed in the PR | On every PR (small, fast, cheap). Default in the bundled GHA workflow. |
| **Full scan** | (no `--diff-only`) | Whole repo (subject to DoS limits) | On `workflow_dispatch`, on a schedule, or for a research deep-dive. |

PR scan uses `git diff --name-only --diff-filter=ACMRT $pr_base...HEAD` to
build the file list, then applies the same `--exclude-path` /
`--max-files` / `--max-file-bytes` / `--max-total-bytes` limits as a full
scan. If the working copy isn't a git repo, the harness falls back to a
full walk and logs a warning.

## DoS limits

These exist because LLM calls cost real money and a malicious or
accidentally-massive PR could otherwise nuke your token budget.

| Flag | Default | Purpose |
|---|---|---|
| `--max-files` | 0 (unlimited) | Cap files scanned. Once reached, remaining files are skipped. |
| `--max-file-bytes` | 0 (unlimited) | Skip individual files larger than this. |
| `--max-total-bytes` | 0 (unlimited) | Stop scanning once cumulative bytes exceeds. |

The PR-scan defaults baked into the GHA workflow are **100 / 500 KB / 5 MB**.
These keep the cost ceiling on every PR comfortably small.

## PR comment writer

`--pr-comment PATH` produces a Markdown file shaped for `gh pr comment
--body-file`. Each finding gets:

```markdown
<!-- vuln-id: F-0001 scan-id: <sha>--<iso8601> -->
- [ ] :white_check_mark: True Positive
- [ ] :x: False Positive

**ID**: `F-0001`
**Severity**: :fire: High
**CWE**: CWE-89
...
```

The HTML comment markers are deliberate -- they're how
`collect-feedback` maps a checked box back to a stored finding.

## Feedback loop

```text
                          (1) PR scan
   PR open  --->  redeye scan --diff-only --pr-comment ...
                          |
                          v
                  out/pr-comment.md           SQLite: scans + findings rows
                          |                          ^
                          v                          |
                  gh pr comment --body-file          | (3) collect-feedback
                          |                          | parses comment body
                          v                          |
   PR comment with TP/FP boxes  ----- (2) reviewer ticks a box, edits comment
                                       \
                                        \---> issue_comment.edited event
                                              redeye collect-feedback

   (4) next PR scan with --use-feedback loads marks from SQLite and
       prepends a compact context block to S4 lens system prompts:

       # Prior reviewer feedback (use to calibrate confidence)
       - [TP] CWE-89 SQL injection in user lookup (src/api/users.py)
       - [FP] CWE-200 Information disclosure in test fixture (tests/...)
```

The store is local-first SQLite at `~/.redeye/scans.db` (override
with `REDEYE_DB_PATH`). It has two tables, `scans` and `findings`, both
keyed on a deterministic `scan_id = "<target_sha>--<started_at>"`.

A Databricks backend is on the roadmap; it will plug into a
`DatabricksStore` class that satisfies the same interface as
`FindingsStore`.

## Webhook notifications

`--webhook-url URL --webhook-type slack|teams|discord|generic` posts a
compact summary on scan completion. Set `REDEYE_WEBHOOK_SECRET` to add
an `X-Redteam-Signature: sha256=<hmac>` header so receivers can verify
the sender.

The `slack` payload uses Block Kit; `teams` uses MessageCard; `discord`
uses plain `content`; `generic` is a flat JSON.

## The GitHub Actions workflow

`.github/workflows/redeye-scan.yml` packages all three modes:

```yaml
on:
  pull_request: ...        # PR scan
  workflow_dispatch: ...   # full scan
  issue_comment: ...       # collect-feedback
```

Required repo secrets / variables:

| Name | Required for | Notes |
|---|---|---|
| `REDEYE_PROFILE` (var) | choosing default profile | `mock` if you have no LLM creds |
| `ANTHROPIC_SDK_API_KEY` | sdk backend | |
| `OPENAI_API_KEY` | openai backend | |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | bedrock backend | |
| `AWS_REGION` (var) | bedrock backend | default `us-east-1` |
| `GOOGLE_CLOUD_PROJECT` (var) | vertex backend | |
| `GOOGLE_CREDENTIALS` (secret) | vertex backend | service account JSON, written to `$GOOGLE_APPLICATION_CREDENTIALS` |
| `REDEYE_WEBHOOK_URL` | optional | Slack/Teams/Discord URL |
| `REDEYE_WEBHOOK_TYPE` (var) | optional | default `slack` |

The workflow runs on **your** runners and on **your** code -- nothing
ships to a `redeye`-controlled service. `runs-on: self-hosted`
works fine if you want full network isolation.
