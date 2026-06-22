# Setup guide

This guide walks you from a clean machine to your first scan in about 10
minutes. If anything is unclear after reading it, the answer is probably in
[`USER_GUIDE.md`](USER_GUIDE.md) (commands) or
[`configuration.md`](configuration.md) (profiles & secrets).

## 1. Prerequisites

| Thing | Why |
|---|---|
| Python 3.10 or newer | The harness uses pattern matching and `|`-typed unions. |
| `git` on PATH | Used to read the target repo's HEAD SHA for the manifest. |
| One of: Claude Code, Anthropic SDK key, OpenAI key, or **nothing** (mock) | Pick the backend you can use today. |

Verify:

```bash
python3 --version    # >= 3.10
git --version
```

## 2. Install

Recommended -- isolated virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .\.venv\Scripts\Activate.ps1     # Windows PowerShell
pip install .
```

Or globally, via `pipx`:

```bash
pipx install .
```

Either way you should now have one command on PATH:

```bash
redeye --version
```

To install the optional `[sdk]` and `[openai]` extras (if you'll use those
backends):

```bash
pip install ".[all]"
```

## 3. Pick a profile

The harness ships with four profiles in `redeye/config/profiles/`:

| Profile | Backends | When to use |
|---|---|---|
| `default` | `cli` (Claude Code) | Most users on a laptop with `claude login`. |
| `cli` | `cli` + `Bash` tool | Same as default but the model can shell out. |
| `full` | `sdk` + `cli` + `openai` | Multi-vendor voting; best FP rate. |
| `mock` | `mock` (no network) | CI smoke tests, demos with no creds. |

You don't need to choose at install time. The CLI defaults to `default`;
override with `--profile <name>` per command, or set
`REDEYE_PROFILE=<name>` in your shell.

## 4. Configure credentials

Copy the example file:

```bash
cp .env.example .env
```

Edit `.env` and fill in **only what your chosen profile needs**:

- `default` / `cli` -> run `claude login` interactively, OR set
  `CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`).
- `full` -> `ANTHROPIC_SDK_API_KEY` and `OPENAI_API_KEY`.
- `mock` -> nothing.

The harness loads `.env` automatically by walking up parent directories
from the current working directory.

### Behind a private LLM gateway

If your org routes Claude through an internal gateway:

```bash
ANTHROPIC_BASE_URL=https://your-gateway.example.com
NODE_EXTRA_CA_CERTS=/path/to/private-ca.pem
CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1   # if the gateway requires it
```

For the SDK backend, also:

```bash
ANTHROPIC_SDK_API_KEY=...
ANTHROPIC_SDK_BASE_URL=https://your-gateway.example.com
ANTHROPIC_SDK_CA_CERT=/path/to/ca.pem        # optional, for mTLS
ANTHROPIC_SDK_CLIENT_CERT=/path/to/client.pem # optional, for mTLS
```

## 5. Verify

```bash
redeye doctor
```

You should see one row per backend your profile uses, with both
**Credential** and **Reachable** columns marked `OK`. If anything is red,
`doctor` will print the env var or login it expects.

## 6. First scan

```bash
redeye estimate --repo /path/to/your-repo
redeye scan --repo /path/to/your-repo --application-id 12345
```

The output lands under `<repo>/security-scan/`:

- `<module>_<ts>_report.md`
- `<module>_<ts>_report.sarif`
- `run_manifest.json`

## 7. Install agent operating instructions (optional)

If you use Claude Code, GitHub Copilot, or Gemini CLI, drop the operating
instructions where each tool reads them:

```bash
redeye setup --install-agents
```

This writes:

- `AGENTS.md` -- cross-tool entry point.
- `CLAUDE.md` -- read by Claude Code on session start.
- `.github/copilot-instructions.md` -- read by Copilot Chat.
- `GEMINI.md` -- read by Gemini CLI.

Existing files are never overwritten.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `redeye: command not found` | Virtualenv not activated, or `pipx` shim path missing. | `source .venv/bin/activate` or `pipx ensurepath`. |
| `doctor` says cli `Reachable: false` | `claude` CLI not installed, or `claude login` not done. | `npm i -g @anthropic-ai/claude-code` (or whatever your distro recommends), then `claude login`. |
| `doctor` says sdk `Credential: false` | `ANTHROPIC_SDK_API_KEY` not in env. | Edit `.env` and reload your shell, or `export` directly. |
| `scan` falls back to mock backend | Backend errored mid-run. | Re-run with `-vv` to get the underlying exception. |
| `pip install` fails on `pydantic` | Python < 3.10. | `python3 --version` -- upgrade Python. |
