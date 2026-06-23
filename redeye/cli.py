"""Top-level CLI for redeye.

This file intentionally stays thin. Each subcommand lives in its own module
under :mod:`redeye.commands` so they can be unit-tested without going
through ``click``.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import click
from dotenv import load_dotenv
from rich.console import Console
from rich.logging import RichHandler

from redeye import __version__
from redeye.errors import RedEyeError

console = Console()


def _load_env() -> None:
    """Walk parent directories from CWD until we find a `.env`, then load it.

    Variables already in ``os.environ`` win — this matches the documented
    precedence behaviour.
    """
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".env"
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return


def _configure_logging(verbose: int) -> None:
    level_env = os.environ.get("REDEYE_LOG_LEVEL")
    if level_env:
        level = getattr(logging, level_env.upper(), logging.INFO)
    else:
        level = {0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    invoke_without_command=False,
)
@click.option("-v", "--verbose", count=True, help="Increase log verbosity (-v, -vv).")
@click.version_option(__version__, "--version", prog_name="redeye")
@click.pass_context
def main(ctx: click.Context, verbose: int) -> None:
    """redeye — agentic SAST harness."""
    _load_env()
    _configure_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["console"] = console


@main.command()
@click.option(
    "--install-agents",
    is_flag=True,
    help="Drop AGENTS.md / CLAUDE.md / GEMINI.md / Copilot instructions into CWD.",
)
@click.option(
    "--profile",
    default=None,
    help="Profile to validate during setup (default: built-in `default`).",
)
@click.pass_context
def setup(ctx: click.Context, install_agents: bool, profile: str | None) -> None:
    """Interactive setup — prints what's missing, optionally installs agent files."""
    from redeye.commands.setup import run as run_setup

    try:
        run_setup(console=ctx.obj["console"], install_agents=install_agents, profile=profile)
    except RedEyeError as exc:
        console.print(f"[red]setup failed:[/red] {exc}")
        sys.exit(2)


@main.command()
@click.option(
    "--profile",
    default=None,
    help="Profile to probe (default: auto-detect the best-available backend).",
)
@click.option("--no-network", is_flag=True, help="Skip live backend probes.")
@click.pass_context
def doctor(ctx: click.Context, profile: str | None, no_network: bool) -> None:
    """Verify credentials and backend reachability for the active profile."""
    from redeye.commands.doctor import run as run_doctor

    rc = run_doctor(console=ctx.obj["console"], profile=profile, no_network=no_network)
    sys.exit(rc)


@main.command()
@click.option(
    "--repo", required=True, type=click.Path(exists=True, file_okay=False), help="Path to repo."
)
@click.option(
    "--profile",
    default=None,
    help="Profile to use for cost model (default: auto-detect best backend).",
)
@click.pass_context
def estimate(ctx: click.Context, repo: str, profile: str | None) -> None:
    """Print scope and approximate USD cost for a scan. No LLM calls."""
    from redeye.commands.estimate import run as run_estimate

    try:
        run_estimate(console=ctx.obj["console"], repo=Path(repo), profile=profile)
    except RedEyeError as exc:
        console.print(f"[red]estimate failed:[/red] {exc}")
        sys.exit(2)


@main.command()
@click.option("--repo", type=click.Path(exists=True, file_okay=False), help="Path to a repo.")
@click.option(
    "--repo-file",
    type=click.Path(exists=True, dir_okay=False),
    help="CSV file of repos for batch scanning.",
)
@click.option(
    "--profile",
    default=None,
    help=(
        "Profile name (default | cli | full | mock | auto) or path to YAML. "
        "When unspecified, RedEye auto-detects the best-available backend "
        "on this machine -- pass --profile default to force the bundled "
        "default profile instead."
    ),
)
@click.option("--application-id", default=None, help="External AppId for traceability.")
@click.option(
    "--workspace",
    type=click.Path(file_okay=False),
    default=None,
    help="Workspace directory for batch scans.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False),
    default=None,
    help="Override output directory.",
)
@click.option("--group-by-app", is_flag=True, help="Emit one report per AppId.")
@click.option("--keep-clones", is_flag=True, help="Retain cloned repos after scanning.")
@click.option("--dry-run", is_flag=True, help="Plan but do not execute LLM calls.")
# --- Scope flags (PR-scan / DoS protection / exclusions) -------------------
@click.option(
    "--diff-only",
    is_flag=True,
    help="Scan only files changed vs --pr-base (useful for PR scans).",
)
@click.option("--pr-base", default="main", show_default=True, help="Base ref for --diff-only.")
@click.option(
    "--exclude-path",
    "exclude_paths",
    multiple=True,
    help="Substring of paths to exclude (repeatable).",
)
@click.option("--max-files", type=int, default=0, help="Cap files scanned (0 = unlimited).")
@click.option(
    "--max-file-bytes", type=int, default=0, help="Skip files larger than this many bytes."
)
@click.option(
    "--max-total-bytes", type=int, default=0, help="Stop scanning once cumulative bytes exceed."
)
# --- Customisation / feedback ----------------------------------------------
@click.option(
    "--custom-prompt-file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Markdown/text file appended to every system prompt.",
)
@click.option(
    "--store-findings",
    is_flag=True,
    help="Persist findings to the SQLite findings DB (~/.redeye/scans.db).",
)
@click.option(
    "--use-feedback",
    is_flag=True,
    help="Inject prior TP/FP feedback (from the DB) into S4 lens prompts.",
)
@click.option(
    "--strict-grounding",
    is_flag=True,
    help=(
        "Drop findings that fail S4b grounding (hallucinated paths, "
        "unresolved line numbers). Default: keep but tag as 'weak-evidence'."
    ),
)
@click.option(
    "--require-poc",
    is_flag=True,
    help=(
        "Drop findings that have no concrete PoC after S8b. Default: keep "
        "but downgrade severity by one notch."
    ),
)
@click.option(
    "--preset",
    type=click.Choice(["pr", "ci", "deep", "quick"]),
    default=None,
    help=(
        "One-flag substitute for common scan-flag combos. "
        "'pr' = diff-only PR scan with strict grounding + DoS limits + standard exclusions. "
        "'ci' = bounded full-repo CI scan. "
        "'deep' = research mode (unlimited scope, keep weak-evidence findings). "
        "'quick' = 60-second mock-backend demo with zero LLM cost. "
        "Explicit CLI flags ALWAYS override the preset's values."
    ),
)
@click.option(
    "--pr-comment",
    type=click.Path(file_okay=True, dir_okay=False),
    default=None,
    help="Write a PR-comment-shaped Markdown to this path (for GitHub Actions).",
)
@click.option(
    "--webhook-url",
    default=None,
    help="POST a scan summary to this webhook URL (Slack/Teams/Discord/generic).",
)
@click.option(
    "--webhook-type",
    type=click.Choice(["slack", "teams", "discord", "generic"]),
    default="generic",
    show_default=True,
    help="Payload format for --webhook-url.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    repo: str | None,
    repo_file: str | None,
    profile: str | None,
    application_id: str | None,
    workspace: str | None,
    output_dir: str | None,
    group_by_app: bool,
    keep_clones: bool,
    dry_run: bool,
    diff_only: bool,
    pr_base: str,
    exclude_paths: tuple[str, ...],
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
    custom_prompt_file: str | None,
    store_findings: bool,
    use_feedback: bool,
    pr_comment: str | None,
    webhook_url: str | None,
    webhook_type: str,
    strict_grounding: bool,
    require_poc: bool,
    preset: str | None,
) -> None:
    """Run the full 9-stage pipeline against one or more repositories."""
    from redeye.commands.scan import run as run_scan

    # --- Preset overlay: fill in any flag the user didn't explicitly pass ---
    # Click's get_parameter_source() lets us distinguish "user typed this" from
    # "default value". Explicit flags always win over the preset.
    if preset is not None:
        from redeye.commands.presets import apply_preset

        # Build a snapshot of the current locals + the set of flags the user
        # actually typed.
        local_flags = {
            "profile": profile,
            "diff_only": diff_only,
            "pr_base": pr_base,
            "exclude_paths": list(exclude_paths),
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_total_bytes": max_total_bytes,
            "strict_grounding": strict_grounding,
            "require_poc": require_poc,
            "store_findings": store_findings,
            "use_feedback": use_feedback,
        }
        explicit = {
            name
            for name in local_flags
            if ctx.get_parameter_source(name) == click.core.ParameterSource.COMMANDLINE
        }
        merged = apply_preset(preset, explicit_flags=explicit, current_kwargs=local_flags)

        # Rebind locals from the merged values (only the keys we manage).
        profile = merged["profile"]
        diff_only = merged["diff_only"]
        pr_base = merged["pr_base"]
        exclude_paths = tuple(merged["exclude_paths"])  # CLI args are tuples
        max_files = merged["max_files"]
        max_file_bytes = merged["max_file_bytes"]
        max_total_bytes = merged["max_total_bytes"]
        strict_grounding = merged["strict_grounding"]
        require_poc = merged["require_poc"]
        store_findings = merged["store_findings"]
        use_feedback = merged["use_feedback"]
        console.print(
            f"[dim]applied preset [bold]{preset}[/bold] "
            f"(explicit flags preserved: {sorted(explicit) or 'none'})[/dim]"
        )

    if not repo and not repo_file:
        raise click.UsageError("Either --repo or --repo-file is required.")

    try:
        rc = run_scan(
            console=ctx.obj["console"],
            repo=Path(repo) if repo else None,
            repo_file=Path(repo_file) if repo_file else None,
            profile=profile,
            application_id=application_id,
            workspace=Path(workspace) if workspace else None,
            output_dir=Path(output_dir) if output_dir else None,
            group_by_app=group_by_app,
            keep_clones=keep_clones,
            dry_run=dry_run,
            diff_only=diff_only,
            pr_base=pr_base,
            exclude_paths=list(exclude_paths),
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
            custom_prompt_file=Path(custom_prompt_file) if custom_prompt_file else None,
            store_findings=store_findings,
            use_feedback=use_feedback,
            pr_comment=Path(pr_comment) if pr_comment else None,
            webhook_url=webhook_url,
            webhook_type=webhook_type,
            strict_grounding=strict_grounding,
            require_poc=require_poc,
        )
        sys.exit(rc)
    except RedEyeError as exc:
        console.print(f"[red]scan failed:[/red] {exc}")
        sys.exit(2)


@main.command("init")
@click.option(
    "--non-interactive",
    is_flag=True,
    help="Accept all recommended defaults without prompting. Useful for CI bootstrap.",
)
@click.option(
    "--write-config",
    is_flag=True,
    help="Also write ./config.yaml seeded from the chosen profile.",
)
@click.option(
    "--env-path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Where to write the rendered .env (default: ./.env).",
)
@click.pass_context
def init(
    ctx: click.Context, non_interactive: bool, write_config: bool, env_path: str | None
) -> None:
    """Interactive setup wizard -- detect creds, pick a profile, write .env."""
    from redeye.commands.init import run as run_init

    rc = run_init(
        console=ctx.obj["console"],
        output_env=Path(env_path) if env_path else None,
        write_config=write_config,
        non_interactive=non_interactive,
    )
    sys.exit(rc)


@main.command("collect-feedback")
@click.option(
    "--comment-file",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a PR comment Markdown body. Falls back to stdin.",
)
@click.pass_context
def collect_feedback(ctx: click.Context, comment_file: str | None) -> None:
    """Ingest TP/FP marks from a PR comment into the local feedback store."""
    from redeye.commands.collect_feedback import run as run_cf

    rc = run_cf(
        console=ctx.obj["console"],
        comment_file=Path(comment_file) if comment_file else None,
    )
    sys.exit(rc)


if __name__ == "__main__":  # pragma: no cover
    main()
