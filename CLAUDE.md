# CLAUDE.md — instructions for Claude Code when working in this repo

> Claude Code reads this file automatically when starting a session in this
> repository's working directory.

## What this repo is

`redeye` is a CLI tool for autonomous SAST. It is not a library.
Read [`README.md`](README.md) for orientation and [`AGENTS.md`](AGENTS.md) for
the cross-tool operating rules — both apply to you.

## Your default behavior in this repo

- Treat the harness as **black-box operational software**. Run it; don't
  rewrite it.
- When the user asks "scan this repo", follow the five-step recipe in
  [`AGENTS.md`](AGENTS.md) — `--version` ? `doctor` ? `estimate` ? `scan` ? summarize.
- When the user asks "fix the harness", first ask which symptom they are
  seeing. Most "harness bugs" are config gaps that `doctor` already named.

## Common tasks

### "Add a new research lens"

1. Create `redeye/skills/lens_<your_lens>.py` following the pattern of
   `lens_language.py`.
2. Register it in `redeye/pipeline/stages/s4_research.py`.
3. Add a config block to all profiles under `stages.s4.lenses`.
4. Document it in [`docs/SKILLS.md`](docs/SKILLS.md).
5. Add a smoke test in `tests/test_pipeline.py`.

### "Wire a new backend"

1. Add `redeye/backends/<your_backend>.py` implementing
   `BackendBase` from `redeye/backends/base.py`.
2. Register it in `redeye/backends/__init__.py`'s factory.
3. Add the credential vars to `.env.example` and document them in
   [`docs/configuration.md`](docs/configuration.md).
4. Update `redeye doctor` so it reports the new backend's status.

### "Run a smoke test"

```bash
redeye scan --repo . --profile mock --output-dir ./out
```

The `mock` profile runs all 9 stages without any network or API calls and
produces a deterministic report. Use this for CI and demos.

## What not to do

- Don't add hidden commands or change CLI behavior without updating
  [`AGENTS.md`](AGENTS.md), [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md), and
  the `--help` output. The agent recipe depends on those being truthful.
- Don't pin a specific model snapshot in code — model identifiers belong in
  YAML profiles so users can override them.
- Don't `print()` to stdout from library code. Use the `rich.console`
  exposed by `redeye/cli.py`. Other tools may parse stdout.

## House style

- Type hints on every public function.
- `pydantic` for schemas, `dataclasses` for plain records.
- Public errors are subclasses of `redeye.errors.RedEyeError`.
- Tests live under `tests/`, mirror the package layout, and never hit a
  live LLM endpoint — use the `mock` backend.
