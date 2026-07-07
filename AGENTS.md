# AGENTS.md — operating instructions for AI agents using `redeye`

This file tells any AI coding agent (Claude Code, Copilot, Gemini CLI,
custom MCP-driven agents) how to **invoke** the harness — not how to edit it.

If you are a human, you can ignore this file and read [`README.md`](README.md)
or [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) instead.

---

## Core rule

`redeye` is a **CLI tool**, not a library to be patched. Run it
through its own `redeye` command. Do not edit its source to make a scan
work. If a scan fails, fix the *config* or the *target*, not the harness.

## Five-step recipe

1. **Check the environment** — confirm the harness is installed:
   ```bash
   redeye --version
   ```
   If the command is missing, install it: `pipx install redeye`.

2. **Verify credentials** for the profile you intend to use:
   ```bash
   redeye doctor
   ```
   `doctor` prints exactly which env vars / CLI logins are missing for *the
   active profile*. Do not invent credentials — surface the gap to the user.

3. **Estimate scope** before spending tokens:
   ```bash
   redeye estimate --repo /path/to/target
   ```
   This produces a no-spend dry run with file counts, language mix, and a
   rough USD budget per stage. Show this to the user before running `scan`.

4. **Run the scan**:
   ```bash
   redeye scan --repo /path/to/target --application-id <id>
   ```
   Or, for batch:
   ```bash
   redeye scan --repo-file repos.csv --workspace ./scans --group-by-app
   ```

5. **Read the report** — open `<target>/security-scan/*_report.md` and
   summarize the top findings. Do not modify SARIF files.

## Things you must not do

- **Do not** edit files under `redeye/` to make a scan succeed. That is a
  bug in the config, the target, or the harness — not work for you.
- **Do not** invent API keys or paste user secrets into prompts. If
  `redeye doctor` says a credential is missing, ask the user.
- **Do not** run `scan` against repositories the user has not explicitly
  named. The tool runs with elevated privilege.
- **Do not** treat findings as ground truth. Every finding is an LLM
  triage candidate. Mention this when summarizing.
- **Do not** commit `.env`, `*_report.sarif`, or `*_report.md` to a public
  repository unless the user has told you the target is public.

## Things you should do

- **Always** prefer the `mock` profile when demonstrating the tool to a
  user who has not configured credentials yet — it produces a deterministic
  run end-to-end with no network calls.
- **Always** run `doctor` before `scan` if the user reports an error.
- **Always** report `run_manifest.json` (tool version, model roles, config
  hash, target SHA, timing) when summarizing a scan — it is the audit
  trail.
- **Always** quote findings with their CWE and the file path + line
  range from the SARIF locations array.

## Commands reference

| Command | What it does | Side effects |
|---|---|---|
| `redeye --version` | Print version. | None. |
| `redeye setup` | Interactive setup — prints what's missing. | None. |
| `redeye setup --install-agents` | Drop AI-agent operating instructions into the cwd. | Creates `AGENTS.md`, `CLAUDE.md`, etc. (only if absent). |
| `redeye doctor` | Verify credentials + backend reachability for active profile. | Network probe per backend. |
| `redeye estimate --repo PATH` | Cost / scope estimate. | No LLM calls. |
| `redeye scan --repo PATH ...` | Full pipeline run. | Writes report + SARIF + manifest (`--html`/`--pdf` add those formats). |
| `redeye eval [--profile P]` | Score a scan against a labeled benchmark (precision/recall/F1/hallucination). | Runs the pipeline over the benchmark; no writes unless `--output-json`. |

## When the user asks for a scan

1. Run `doctor`. If it fails, surface the failure.
2. Run `estimate`. Show the budget. Wait for user confirmation if budget > $5.
3. Run `scan`. Wait for completion.
4. Open the Markdown report. Summarize top 3–5 findings with severity, CWE,
   file:line, and remediation hypothesis. Link the full report path.
5. Mention the dropped-findings appendix exists, in case the user wants to
   reconsider any.
