"""`redeye init` -- interactive first-run wizard.

What this command does, in order:

1. Looks at the user's environment and detects which LLM backends are
   already usable (Claude Code CLI logged in, Anthropic SDK key, OpenAI
   key, AWS credentials, GCP project, Ollama server reachable, mock).
2. Recommends a *profile* based on what was detected and explains why.
3. Asks the operator a handful of questions (defaults wherever sensible).
4. Writes a tailored ``.env`` next to the project root with only the
   variables relevant to the chosen profile -- so the user isn't staring
   at a 70-line example with most lines irrelevant to them.
5. Prints the exact next commands to run, with copy-pastable example
   invocations using the new ``--preset`` flag.

The wizard is intentionally additive and never destructive:

- Existing ``.env`` and ``config.yaml`` files are NEVER overwritten
  without a confirmation prompt.
- No global state is changed. No keychain, no ``~/.gitconfig``.
- The wizard works fully offline; no telemetry, no network calls.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table


@dataclass
class Detection:
    """One row in the credential / backend detection table."""

    backend: str
    detected: bool
    note: str
    sample_env: list[str]  # env-var lines to put in the rendered .env


def _detect() -> list[Detection]:
    """Inspect the runtime environment, return what's already available."""
    rows: list[Detection] = []

    # cli (Claude Code)
    claude_path = shutil.which("claude")
    has_cli_token = bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"))
    rows.append(
        Detection(
            backend="cli",
            detected=bool(claude_path) or has_cli_token,
            note=(
                "Claude Code CLI on PATH"
                if claude_path
                else "CLAUDE_CODE_OAUTH_TOKEN env var set"
                if has_cli_token
                else "not detected -- install Claude Code or set CLAUDE_CODE_OAUTH_TOKEN"
            ),
            sample_env=[
                "# Backend: cli (Claude Code CLI) -- the default profile uses this.",
                "# Either run `claude login` interactively, OR set an OAuth token:",
                "# CLAUDE_CODE_OAUTH_TOKEN=",
            ],
        )
    )

    # sdk (Anthropic SDK)
    has_sdk = bool(os.environ.get("ANTHROPIC_SDK_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))
    rows.append(
        Detection(
            backend="sdk",
            detected=has_sdk,
            note=(
                "ANTHROPIC_SDK_API_KEY set"
                if has_sdk
                else "set ANTHROPIC_SDK_API_KEY=sk-ant-..."
            ),
            sample_env=[
                "# Backend: sdk (Anthropic SDK)",
                "# ANTHROPIC_SDK_API_KEY=sk-ant-...",
                "# ANTHROPIC_SDK_BASE_URL=                       # private gateway (optional)",
            ],
        )
    )

    # openai
    has_openai = bool(os.environ.get("OPENAI_API_KEY"))
    rows.append(
        Detection(
            backend="openai",
            detected=has_openai,
            note="OPENAI_API_KEY set" if has_openai else "set OPENAI_API_KEY=sk-...",
            sample_env=[
                "# Backend: openai (OpenAI / OpenAI-compatible)",
                "# OPENAI_API_KEY=sk-...",
                "# OPENAI_BASE_URL=https://api.openai.com/v1     # or your gateway",
            ],
        )
    )

    # bedrock
    has_aws = bool(
        os.environ.get("AWS_ACCESS_KEY_ID")
        or os.environ.get("AWS_PROFILE")
        or os.path.exists(os.path.expanduser("~/.aws/credentials"))
    )
    rows.append(
        Detection(
            backend="bedrock",
            detected=has_aws,
            note=(
                "AWS credentials available via env / SSO / profile"
                if has_aws
                else "configure AWS credentials (env, profile, or ~/.aws)"
            ),
            sample_env=[
                "# Backend: bedrock (AWS Bedrock)",
                "# AWS_ACCESS_KEY_ID=...",
                "# AWS_SECRET_ACCESS_KEY=...",
                "# AWS_REGION=us-east-1",
                "# BEDROCK_MODEL_ID=anthropic.claude-opus-4-5-20251101-v1:0",
            ],
        )
    )

    # vertex
    has_vertex = bool(os.environ.get("GOOGLE_CLOUD_PROJECT")) and bool(
        os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        or os.path.exists(
            os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
        )
    )
    rows.append(
        Detection(
            backend="vertex",
            detected=has_vertex,
            note=(
                "GCP project + ADC available"
                if has_vertex
                else "set GOOGLE_CLOUD_PROJECT + GOOGLE_APPLICATION_CREDENTIALS"
            ),
            sample_env=[
                "# Backend: vertex (Google Cloud Vertex AI -- Gemini)",
                "# GOOGLE_CLOUD_PROJECT=your-project-id",
                "# GOOGLE_LOCATION=us-central1",
                "# GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json",
            ],
        )
    )

    # ollama
    rows.append(
        Detection(
            backend="ollama",
            detected=True,  # always potentially available; doctor confirms server
            note=(
                f"server at {os.environ.get('OLLAMA_BASE_URL', 'http://localhost:11434')} "
                "(doctor will probe)"
            ),
            sample_env=[
                "# Backend: ollama (local Ollama server)",
                "# OLLAMA_BASE_URL=http://localhost:11434",
                "# OLLAMA_MODEL=qwen2.5-coder:14b",
            ],
        )
    )

    # mock
    rows.append(
        Detection(
            backend="mock",
            detected=True,
            note="always available; deterministic; zero LLM cost",
            sample_env=[],
        )
    )

    return rows


def _recommend(rows: list[Detection]) -> tuple[str, str]:
    """Pick a profile based on what we detected. Returns (profile_name, why)."""
    by_name = {r.backend: r for r in rows}
    if by_name["sdk"].detected and by_name["openai"].detected:
        return (
            "full",
            "Anthropic SDK + OpenAI both available -- the `full` profile uses "
            "cross-vendor multi-agent voting which gives the best FP filtering.",
        )
    if by_name["cli"].detected:
        return (
            "default",
            "Claude Code CLI is available -- the `default` profile uses it for "
            "every stage with zero API-key configuration.",
        )
    if by_name["sdk"].detected:
        return (
            "full",
            "Anthropic SDK key available -- the `full` profile uses it for the "
            "research and adversarial stages.",
        )
    if by_name["bedrock"].detected:
        return (
            "full",
            "AWS credentials available; the `full` profile can be edited to route "
            "stages through Bedrock (copy full.yaml to ./config.yaml first).",
        )
    return (
        "mock",
        "No LLM credentials detected. The `mock` profile is deterministic and "
        "free -- great for trying out the harness before configuring credentials.",
    )


def _render_env(rows: list[Detection], chosen_profile: str) -> str:
    """Render a tailored .env body for the chosen profile."""
    out: list[str] = [
        "# Red Eye -- environment variables (generated by `redeye init`)",
        "#",
        "# Copy or move this file to .env when you're ready. The harness loads",
        "# .env automatically by walking up parent directories from $PWD.",
        "#",
        f"# Recommended profile: {chosen_profile}",
        "",
    ]
    profile_to_backends = {
        "default": {"cli"},
        "cli": {"cli"},
        "full": {"sdk", "openai", "cli"},
        "mock": set(),
    }
    relevant = profile_to_backends.get(chosen_profile, {chosen_profile})

    # Always include cli, sdk, openai blocks if their backend is in `relevant`.
    for row in rows:
        if row.backend == "mock":
            continue
        if row.backend in relevant or chosen_profile not in profile_to_backends:
            out.extend(row.sample_env)
            out.append("")

    out.extend(
        [
            "# --- Harness behavior (rarely changed) ---",
            f"REDEYE_PROFILE={chosen_profile}",
            "# REDEYE_LOG_LEVEL=INFO",
            "# REDEYE_NO_NETWORK=0",
            "# REDEYE_DB_PATH=~/.redeye/scans.db",
            "",
        ]
    )
    return "\n".join(out)


def run(
    *,
    console: Console,
    output_env: Path | None = None,
    write_config: bool = False,
    non_interactive: bool = False,
) -> int:
    """Drive the wizard. Returns 0 on success."""
    cwd = Path.cwd()
    env_path = output_env or (cwd / ".env")
    config_path = cwd / "config.yaml"

    console.print(
        Panel.fit(
            "[bold]redeye init[/bold] -- interactive setup",
            border_style="cyan",
        )
    )
    console.print(
        "This will look at what credentials you have, recommend a profile,\n"
        "and (optionally) write a tailored [bold].env[/bold] file in this directory.\n"
        "[dim]No global state is touched. No telemetry. No network calls.[/dim]\n"
    )

    # 1. Detect.
    rows = _detect()

    table = Table(title="Credential detection")
    table.add_column("Backend")
    table.add_column("Detected?")
    table.add_column("Note")
    for r in rows:
        table.add_row(
            r.backend,
            "[green]YES[/green]" if r.detected else "[yellow]NO[/yellow]",
            r.note,
        )
    console.print(table)

    # 2. Recommend.
    rec_profile, rec_why = _recommend(rows)
    console.print(
        f"\n[bold]Recommended profile:[/bold] [cyan]{rec_profile}[/cyan]\n[dim]{rec_why}[/dim]\n"
    )

    if non_interactive:
        profile = rec_profile
    else:
        profile = Prompt.ask(
            "Profile to use",
            choices=["default", "cli", "full", "mock"],
            default=rec_profile,
        )

    # 3. Confirm .env write.
    if env_path.exists():
        if non_interactive:
            write_env = False
            console.print(f"[yellow]{env_path} already exists -- leaving it untouched.[/yellow]")
        else:
            write_env = Confirm.ask(
                f"[yellow]{env_path}[/yellow] already exists. Overwrite?",
                default=False,
            )
    else:
        if non_interactive:
            write_env = True
        else:
            write_env = Confirm.ask(f"Write a new [bold]{env_path}[/bold]?", default=True)

    if write_env:
        body = _render_env(rows, profile)
        env_path.write_text(body, encoding="utf-8")
        console.print(f"[green]wrote[/green] {env_path}")

    # 4. Optional config.yaml.
    if write_config or (
        not non_interactive
        and Confirm.ask(
            "Also write a [bold]./config.yaml[/bold] you can customise? "
            "(starts as a copy of the chosen profile)",
            default=False,
        )
    ):
        from redeye.config.loader import _BUILTIN_PROFILES_DIR

        src = _BUILTIN_PROFILES_DIR / f"{profile}.yaml"
        if src.is_file() and not config_path.exists():
            config_path.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
            console.print(f"[green]wrote[/green] {config_path}")
        elif config_path.exists():
            console.print(
                f"[yellow]{config_path}[/yellow] already exists -- not overwriting."
            )

    # 5. Next steps.
    console.print(
        Panel.fit(
            "[bold]Next steps[/bold]\n\n"
            "1. [cyan]redeye doctor[/cyan] -- verify the chosen backend works.\n"
            "2. [cyan]redeye scan --preset quick[/cyan] -- 60-second mock demo.\n"
            "3. [cyan]redeye scan --repo . --preset pr[/cyan] -- PR-scan against current dir.\n"
            "4. [cyan]redeye scan --repo . --preset deep[/cyan] -- full research run.\n",
            border_style="green",
        )
    )
    return 0
