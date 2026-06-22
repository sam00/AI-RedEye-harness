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
