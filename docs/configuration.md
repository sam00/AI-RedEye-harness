# Configuration

How profiles and environment variables compose, and how to write your own.

## Profile resolution order

When a command needs a profile, the loader walks this list and uses the
first hit:

1. `--profile <path-to.yaml>` -- treated literally if the file exists.
2. `--profile <name>` -- resolved against `redeye/config/profiles/<name>.yaml`.
3. `$REDEYE_PROFILE` (only if `--profile` is absent).
4. `./config.yaml` in the current working directory.
5. Bundled `default.yaml`.

Use `redeye doctor --profile NAME` to confirm which profile actually
loaded -- the printed `source_path` is the file the loader picked.

## Profile schema

```yaml
name: my-profile               # arbitrary string

roles:                          # logical role -> backend assignment
  surveyor:
    via: cli                    # cli | sdk | openai | mock
    model: claude-sonnet-4-6
    temperature: 0.0            # optional; some backends ignore
    max_tokens: 4096
    extra: { tools: [Read, Bash] }   # backend-specific options

  researcher:
    via: sdk
    model: claude-sonnet-4-6
    temperature: 0.2

  adversary:
    via: openai
    model: gpt-4o
    temperature: 0.2

  reporter:
    via: cli
    model: claude-sonnet-4-6

stages:                         # stage_id -> stage config
  s1_attack_surface:
    skill: attack_surface_mapper
    role: surveyor
    max_budget_usd: 0.50
  s4_research:
    skill: research_lenses
    role: researcher
    max_budget_usd: 4.00
    params:
      lenses: [language, crypto, logic, access_control, iac]
  # ... s2, s3, s5, s6, s7, s8, s9 ...

voting:
  enabled: true
  quorum: 2
  voters: [adversary, researcher]
```

### Required keys

- `name` -- string, used in logs and the manifest.
- `roles` -- at least one role must be present. Stages reference them by
  name.
- `stages` -- at least the 9 stage ids: `s1_attack_surface`,
  `s2_threat_model`, `s3_strategize`, `s4_research`, `s5_policy_gate`,
  `s6_adversarial`, `s7_dedupe`, `s8_chain`, `s9_emit`.
- `voting` -- optional. Defaults to enabled with quorum=2 if any voters
  are listed.

## Environment variables

The harness reads `.env` automatically (walking up parent directories
from the current working directory). Variables already exported in the
shell take precedence.

| Var | Used by | Required for |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `cli` backend | gateway-token auth (alternative to `claude login`) |
| `ANTHROPIC_BASE_URL` | `cli` backend | private gateway routing |
| `NODE_EXTRA_CA_CERTS` | `cli` backend | private CA for the gateway |
| `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS` | `cli` backend | older gateways |
| `ANTHROPIC_SDK_API_KEY` | `sdk` backend | always |
| `ANTHROPIC_SDK_BASE_URL` | `sdk` backend | private gateway |
| `ANTHROPIC_SDK_CA_CERT` | `sdk` backend | mTLS |
| `ANTHROPIC_SDK_CLIENT_CERT` | `sdk` backend | mTLS |
| `OPENAI_API_KEY` | `openai` backend | always |
| `OPENAI_BASE_URL` | `openai` backend | OpenAI-compatible endpoints (vLLM, OpenRouter, Azure) |
| `REDEYE_PROFILE` | loader | default profile when `--profile` is absent |
| `REDEYE_LOG_LEVEL` | logger | overrides `-v` / `-vv` |
| `REDEYE_NO_NETWORK` | safety | `1` -> refuse network-using backends |

## Setting up your config

The recommended workflow is **copy then edit**:

```bash
cp redeye/config/profiles/full.yaml ./config.yaml
$EDITOR ./config.yaml
```

The CLI will pick up `./config.yaml` ahead of the bundled defaults. This
keeps your customizations out of the package directory and easy to commit
to your team's internal repo.

### S1 repo intake / file-inventory knobs

The `s1_attack_surface` stage owns repo intake. Set these under its `params`
in `config.yaml`; the equivalent CLI flags still override when passed.

```yaml
stages:
  s1_attack_surface:
    skill: attack_surface_mapper
    role: surveyor
    params:
      exclude_dirs: [migrations, generated]   # directory names to skip
      exclude_exts: [.min.js, .lock, .map]    # extensions to drop (dot optional)
      exclude_globs: ["**/*.snap", "**/testdata/**"]  # fnmatch globs on rel path
      max_file_kb: 512        # skip files larger than 512 KB (combined with --max-file-bytes; smaller wins)
      follow_symlinks: false  # if false, symlinked files are skipped
      dedupe_configs: true    # drop byte-identical config files (.yaml/.json/.toml/.ini/.env/...)
```

Scope reports `skipped_excluded`, `skipped_oversize`, `skipped_symlinks`,
`skipped_dupe_configs` and `skipped_truncated` counts in its summary.

Each knob also has a matching `scan` CLI flag. Scalar flags override config;
list flags are merged (union) with the config baseline:

```bash
redeye scan --repo . \
  --exclude-dir migrations --exclude-ext .min.js --exclude-glob '**/*.snap' \
  --max-file-kb 512 --follow-symlinks --dedupe-configs
```

### S2 threat-model knobs

The `s2_threat_model` stage accepts:

```yaml
stages:
  s2_threat_model:
    skill: threat_modeler
    role: surveyor
    params:
      enabled: true             # false -> skip S2 entirely (no LLM call)
      max_threats: 25           # cap the emitted STRIDE list
      baseline: ./threats.yaml  # accepted threats (category|asset) to subtract
      max_document_chars: 6000  # cap the attack-surface doc fed to the model
      max_modules: 40           # evidence caps -- how much structural context
      max_entry_points: 40      #   is injected into the prompt
      max_config_reps: 20
      max_api_artifacts: 40
```

The threat baseline file lists accepted threats so they're filtered from
future models:

```yaml
accepted:
  - {category: Spoofing, asset: login}
```

### External scanner ingestion (mapping enrichment)

Fold third-party scanner output into the structural map so the lenses and
threat model treat already-flagged locations as real hotspots. Accepts
**SARIF 2.1.0**, **Semgrep JSON**, and **generic JSON** (a list, or
`{"findings": [...]}` / `{"results": [...]}`).

```yaml
stages:
  s1b_structural:
    skill: structural_index
    role: surveyor
    params:
      external_scanners: [./reports/semgrep.json, ./reports/codeql.sarif]
```

Or on the command line (repeatable):

```bash
redeye scan --repo . --external-scan reports/semgrep.json --external-scan reports/codeql.sarif
```

Imported findings become candidate `sink` hits in the structural index and
are summarised in `run_manifest.json` (`s1b_structural.artifacts.external_summary`).
**They are mapping enrichment, not blind trust** -- each still has to clear
grounding (S4b), voting (S6) and outcome verification (S8c) before it can
reach the report.

### Secret redaction (Markdown + PDF + manifest)

Obvious secret material is masked before output is written to disk (so reports
are safer to paste into tickets / PRs). It targets well-known credential shapes
-- PEM private keys, JWTs, `sk-`/`sk-ant-` keys, GitHub/Slack/Google/AWS tokens
-- and `key = value` / `key: value` pairs for sensitive key names (`api_key`,
`secret`, `token`, `password`, ...), replacing the value with `***REDACTED***`.
Redaction is applied to the **Markdown report and the `run_manifest.json`**;
because the styled **PDF** is built from the manifest, it inherits the
redaction. It's defence-in-depth, not a guarantee; always review before
publishing.

### External scanner importers

`--external-scan PATH` (repeatable) and `s1b_structural.params.external_scanners`
auto-detect and ingest **SARIF 2.1.0** (incl. CodeQL: `ruleIndex`,
`relationships` CWE taxa, `region.snippet`, suppressions/`baselineState`,
multi-run + extension rules), **Semgrep**, **Trivy**, **Bandit**, **Gitleaks**,
**Grype**, and a permissive generic JSON shape. Imported locations are folded
into the structural map and **deduped against native sinks at the same
`file:line`** (the native hit is corroborated instead). A sink co-located with
an untrusted-input source is flagged `reachable_from_source` so it enters S4b
grounding with a head start. Counts (`hits_added`, `deduped`, `reachable`,
`corroborated`) land in the manifest's `external_summary`.

### Cross-file taint (lightweight call graph)

S1b builds a cheap Python call graph: a *source-bearing* function in one file
calling a *sink-bearing* function in another emits a `cross_file_flows` entry
(`source`, `sink`, `via_call`, `cwe`) that the S4 lenses see as context. Cap
with `s1b_structural.params.max_cross_file_flows` (default 50). It's
approximate context for the lenses, never auto-promoted to a finding.

### Confidence calibration from feedback

When `--use-feedback` is set, reviewer TP/FP marks (per CWE and per lens) are
turned into a numeric prior: historically-noisy categories have their
`confidence` nudged down (and may fall below the voting threshold) while
reliable ones are boosted. Smoothed and bounded; deterministic findings are
never re-weighted. Metrics surface under `s4_research.artifacts.calibration`.

### Incremental scans

`--incremental` records a per-file content hash in the manifest
(`file_hashes`) and, on the next run, restricts the scope to files that are new
or changed since a prior `run_manifest.json` (use `--incremental-from` to point
at a specific one). Content-based, so it's robust to mtime churn and rebases --
a big speedup for CI re-runs.

### Global cost guardrail

`--max-cost USD` sets a hard per-run ceiling. Once cumulative spend hits it,
remaining *paid* (LLM) stages are skipped while zero-cost deterministic stages
and `s9_emit` still run, so a report is always produced. The manifest records
`max_budget_usd` and `budget_exceeded`.

### Extra report formats

- `--html` writes a single self-contained `report.html` (inline CSS + JS) with
  client-side filtering by severity / CWE / grounded. No external assets.
- `--pdf` writes a styled `report.pdf` (needs `reportlab`; skipped gracefully
  if it isn't installed).

Both are built from the (redacted) manifest, alongside the always-on Markdown +
SARIF. A JSON Schema for the manifest is emitted next to it as
`run_manifest.schema.json` for downstream validation.

### Threat baseline

`redeye threat-baseline accept --category Spoofing --asset login` records an
accepted STRIDE threat into `.redeye-threat-baseline.yaml` (`list` / `remove`
too; `--manifest X --all` accepts a whole run's STRIDE list). Point
`s2_threat_model.params.baseline` at the file and accepted threats are
subtracted from future threat models.

### CI integration

The repo ships a composite **GitHub Action** (`action.yml`) that installs
RedEye, runs a scan, and uploads SARIF to code scanning, plus
**`.pre-commit-hooks.yaml`** with a `redeye-diff-scan` (pre-push) hook.

### Adjusting cost ceilings

Each stage has `max_budget_usd`. The sum is the worst-case spend per scan.
Lower these on cheap models, raise them on expensive ones. For most teams,
`s4_research` and `s6_adversarial` are the dominant lines.

### Picking voters

If you only have access to one model family, voting won't help much --
identical models tend to make identical mistakes. Voting works best when
voters disagree on what is "obviously" suspicious. Common patterns:

| Goal | Voter set |
|---|---|
| Cheap FP suppression | `[researcher, adversary]` (same backend, different temperatures) |
| Cross-vendor independence | `[adversary_anthropic, adversary_openai, researcher]` |
| Local LLM second opinion | `[adversary, openai_local]` (`openai_local` pointing at a self-hosted vLLM) |

### Disabling voting

Set `voting.enabled: false`. All findings from S6 will pass through to S7
untouched. This is the right setting for `cli`-only profiles, since the
`claude` CLI does not expose a `temperature` knob.
