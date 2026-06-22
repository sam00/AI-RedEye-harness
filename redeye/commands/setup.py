"""`redeye setup` — interactive setup helper.

Two modes:

* Plain ``setup`` ? diagnose what's missing for the active profile and print
  a remediation checklist.
* ``setup --install-agents`` ? drop operating instructions for installed AI
  coding agents into the current working directory. Existing files are left
  untouched.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redeye.config import load_profile

# Files we know how to install. The dict value is a relative source path
# *inside the package* — bundled at install time via package_data.
_AGENT_FILES: dict[str, str] = {
    "AGENTS.md": "AGENTS.md",
    "CLAUDE.md": "CLAUDE.md",
    ".github/copilot-instructions.md": "AGENTS.md",
    "GEMINI.md": "AGENTS.md",
}


def _installed_agents(cwd: Path) -> list[str]:
    """Best-effort detection of which AI coding agents are configured here."""
    detected = []
    if shutil.which("claude"):
        detected.append("Claude Code")
    if (cwd / ".github").is_dir():
        detected.append("GitHub Copilot")
    if shutil.which("gemini"):
        detected.append("Gemini CLI")
    return detected


def _install_agent_files(cwd: Path, console: Console) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    for dest_rel, src_rel in _AGENT_FILES.items():
        dest = cwd / dest_rel
        src = repo_root / src_rel
        if dest.exists():
            console.print(f"  [yellow]skip[/yellow]  {dest_rel} (already exists)")
            continue
        if not src.exists():
            console.print(f"  [red]miss[/red]  {dest_rel} (source {src_rel} not found)")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        console.print(f"  [green]wrote[/green] {dest_rel}")


def _credential_status() -> list[tuple[str, str, str, bool]]:
    """Return rows of (backend, env_var, value_summary, ok)."""
    import os

    rows: list[tuple[str, str, str, bool]] = []
    rows.append(
        (
            "cli (Claude Code)",
            "CLAUDE_CODE_OAUTH_TOKEN or `claude login`",
            "set" if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") else "unset",
            bool(os.environ.get("CLAUDE_CODE_OAUTH_TOKEN") or shutil.which("claude")),
        )
    )
    rows.append(
        (
            "sdk (Anthropic)",
            "ANTHROPIC_SDK_API_KEY",
            "set" if os.environ.get("ANTHROPIC_SDK_API_KEY") else "unset",
            bool(os.environ.get("ANTHROPIC_SDK_API_KEY")),
        )
    )
    rows.append(
        (
            "openai",
            "OPENAI_API_KEY",
            "set" if os.environ.get("OPENAI_API_KEY") else "unset",
            bool(os.environ.get("OPENAI_API_KEY")),
        )
    )
    rows.append(
        (
            "bedrock (AWS)",
            "AWS_ACCESS_KEY_ID / AWS_PROFILE",
            "set"
            if (os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"))
            else "unset",
            bool(os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE")),
        )
    )
    rows.append(
        (
            "vertex (GCP)",
            "GOOGLE_CLOUD_PROJECT + GOOGLE_APPLICATION_CREDENTIALS",
            "set" if os.environ.get("GOOGLE_CLOUD_PROJECT") else "unset",
            bool(
                os.environ.get("GOOGLE_CLOUD_PROJECT")
                and (
                    os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                    or os.path.exists(
                        os.path.expanduser("~/.config/gcloud/application_default_credentials.json")
                    )
                )
            ),
        )
    )
    rows.append(
        (
            "ollama (local)",
            "OLLAMA_BASE_URL (server reachability)",
            os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            True,  # always "potentially available"; doctor confirms reachability
        )
    )
    rows.append(("mock", "(none)", "always available", True))
    return rows


def run(*, console: Console, install_agents: bool, profile: str | None) -> None:
    cwd = Path.cwd()

    if install_agents:
        console.print(Panel.fit("Installing AI-agent operating instructions"))
        agents = _installed_agents(cwd)
        if agents:
            console.print(f"Detected agents: {', '.join(agents)}")
        else:
            console.print("[yellow]No AI coding agents detected — installing anyway.[/yellow]")
        _install_agent_files(cwd, console)
        console.print("\nDone. The next time an agent opens this repo it will read these files.")
        return

    console.print(Panel.fit("redeye setup"))

    cfg: Any = load_profile(profile)
    console.print(f"Active profile: [bold]{cfg.name}[/bold] (file: {cfg.source_path})")

    table = Table(title="Credential status", show_lines=False)
    table.add_column("Backend")
    table.add_column("Required")
    table.add_column("State")
    table.add_column("OK?")
    for backend, var, value, ok in _credential_status():
        table.add_row(backend, var, value, "[green]OK[/green]" if ok else "[red]MISSING[/red]")
    console.print(table)

    console.print(
        "\nNext steps:\n"
        "  1. [cyan]redeye doctor[/cyan]                 — verify reachability of backends.\n"
        "  2. [cyan]redeye estimate --repo PATH[/cyan]   — preview cost without spending.\n"
        "  3. [cyan]redeye scan --repo PATH[/cyan]       — full pipeline run.\n"
    )
