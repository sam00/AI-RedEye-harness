"""`redeye scan` -- run the full 9-stage pipeline.

Single-repo mode and batch mode (``--repo-file``) share the same engine;
batch mode is just a loop with deterministic naming and an option to
``--keep-clones``.

This command is the integration point for the operational add-ons:
- ``--diff-only`` / ``--pr-base`` -- PR-scan scope.
- ``--max-*`` -- DoS protection.
- ``--exclude-path`` -- noise reduction.
- ``--custom-prompt-file`` -- prompt extension.
- ``--store-findings`` / ``--use-feedback`` -- DB-backed feedback loop.
- ``--pr-comment`` -- emit a Markdown comment for GitHub PRs.
- ``--webhook-url`` / ``--webhook-type`` -- post a summary to chat.
"""

from __future__ import annotations

import csv
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console

from redeye.config import load_profile
from redeye.errors import ConfigError
from redeye.pipeline.orchestrator import Orchestrator
from redeye.scope import Scope

log = logging.getLogger(__name__)


def _resolve_targets(repo: Path | None, repo_file: Path | None) -> list[tuple[Path, str | None]]:
    """Return a list of (repo_path, application_id) pairs to scan."""
    if repo is not None:
        return [(repo, None)]
    if repo_file is not None:
        targets: list[tuple[Path, str | None]] = []
        with repo_file.open() as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                path = row.get("path") or row.get("repo")
                if not path:
                    raise ConfigError(f"{repo_file}: row is missing 'path' or 'repo' column")
                app_id = row.get("application_id") or row.get("app_id")
                targets.append((Path(path), app_id))
        return targets
    raise ConfigError("Either --repo or --repo-file must be provided.")


def _load_custom_prompt(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("could not read --custom-prompt-file %s: %s", path, exc)
        return ""


def _load_feedback(target_path: Path, use_feedback: bool) -> list[dict[str, Any]]:
    if not use_feedback:
        return []
    from redeye.feedback.store import FindingsStore

    store = FindingsStore.default()
    return store.load_feedback(repo=str(target_path.resolve()))


def _maybe_persist(target_path: Path, manifest, findings, store_findings: bool) -> None:  # type: ignore[no-untyped-def]
    if not store_findings:
        return
    from redeye.feedback.store import FindingsStore

    store = FindingsStore.default()
    store.record_scan(repo=str(target_path.resolve()), manifest=manifest, findings=findings)


def _maybe_webhook(
    *,
    webhook_url: str | None,
    webhook_type: str,
    target_path: Path,
    manifest,  # type: ignore[no-untyped-def]
    application_id: str | None,
) -> None:
    if not webhook_url:
        return
    from redeye.notify.webhook import post_summary

    post_summary(
        url=webhook_url,
        kind=webhook_type,
        target=str(target_path),
        application_id=application_id,
        manifest=manifest,
    )


def run(
    *,
    console: Console,
    repo: Path | None,
    repo_file: Path | None,
    profile: str | None,
    application_id: str | None,
    workspace: Path | None,
    output_dir: Path | None,
    group_by_app: bool,
    keep_clones: bool,
    dry_run: bool,
    diff_only: bool = False,
    pr_base: str = "main",
    exclude_paths: list[str] | None = None,
    max_files: int = 0,
    max_file_bytes: int = 0,
    max_total_bytes: int = 0,
    custom_prompt_file: Path | None = None,
    store_findings: bool = False,
    use_feedback: bool = False,
    pr_comment: Path | None = None,
    webhook_url: str | None = None,
    webhook_type: str = "generic",
    strict_grounding: bool = False,
    require_poc: bool = False,
) -> int:
    cfg = load_profile(profile)
    # Honor --strict-grounding / --require-poc by patching the stage params
    # at runtime. Profiles can also pre-set these; CLI flags win.
    if strict_grounding and "s4b_grounding" in cfg.stages:
        cfg.stages["s4b_grounding"].params["strict"] = True
    if require_poc and "s8b_poc" in cfg.stages:
        cfg.stages["s8b_poc"].params["strict"] = True
    targets = _resolve_targets(repo, repo_file)
    custom_prompt = _load_custom_prompt(custom_prompt_file)
    console.rule(f"[bold]redeye scan[/bold] -- profile: {cfg.name} -- targets: {len(targets)}")
    if diff_only:
        console.print(f"[dim]Mode: diff-only against {pr_base}[/dim]")
    if exclude_paths:
        console.print(f"[dim]Excluding paths containing: {', '.join(exclude_paths)}[/dim]")

    failures = 0
    overall_started = datetime.now(timezone.utc)

    for idx, (target_path, target_app_id) in enumerate(targets, start=1):
        if not target_path.is_dir():
            console.print(f"[red]skip[/red] {target_path} (not a directory)")
            failures += 1
            continue

        effective_app_id = application_id or target_app_id
        target_out = (
            output_dir
            if output_dir is not None
            else (workspace / target_path.name)
            if workspace is not None
            else target_path / "security-scan"
        )
        target_out.mkdir(parents=True, exist_ok=True)

        console.print(
            f"\n[bold cyan]({idx}/{len(targets)})[/bold cyan] {target_path}"
            + (f"  [dim]appId={effective_app_id}[/dim]" if effective_app_id else "")
        )

        scope = Scope.build(
            target=target_path,
            diff_only=diff_only,
            pr_base=pr_base,
            exclude_paths=exclude_paths or [],
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_total_bytes=max_total_bytes,
        )
        if scope.skipped_oversize or scope.skipped_excluded or scope.skipped_truncated:
            console.print(
                f"  [dim]scope: {len(scope.files)} files, "
                f"{scope.skipped_excluded.__len__()} excluded, "
                f"{len(scope.skipped_oversize)} too large, "
                f"{scope.skipped_truncated} truncated[/dim]"
            )

        feedback = _load_feedback(target_path, use_feedback)
        if feedback:
            console.print(f"  [dim]feedback: loaded {len(feedback)} prior TP/FP marks[/dim]")

        start = time.monotonic()
        orchestrator = Orchestrator(
            config=cfg,
            console=console,
            target=target_path,
            output_dir=target_out,
            application_id=effective_app_id,
            dry_run=dry_run,
            scope=scope,
            custom_prompt=custom_prompt,
            feedback=feedback,
        )
        try:
            manifest = orchestrator.run()
        except Exception as exc:  # noqa: BLE001
            console.print(f"  [red]FAIL pipeline error:[/red] {exc}")
            failures += 1
            continue

        elapsed = time.monotonic() - start
        console.print(
            f"  [green]ok[/green] done in {elapsed:.1f}s | "
            f"findings={manifest.finding_count} dropped={manifest.dropped_count} "
            f"cost=${manifest.total_cost_usd:.3f}"
        )

        # The orchestrator already wrote Markdown + SARIF; we add the PR
        # comment, the optional DB row, and the optional webhook here.
        if pr_comment is not None:
            from redeye.output.pr_comment import write_pr_comment

            # Reload findings list from the last stage's result.
            last_findings = []
            for stage in manifest.stages:
                if stage.stage_id == "s9_emit":
                    last_findings = stage.findings
            write_pr_comment(
                path=pr_comment,
                target=target_path,
                application_id=effective_app_id,
                findings=last_findings,
                manifest=manifest,
            )
            console.print(f"  [dim]wrote PR comment: {pr_comment}[/dim]")

        # Persist + notify.
        last_findings_for_db = []
        for stage in manifest.stages:
            if stage.stage_id == "s9_emit":
                last_findings_for_db = stage.findings
        _maybe_persist(target_path, manifest, last_findings_for_db, store_findings)
        _maybe_webhook(
            webhook_url=webhook_url,
            webhook_type=webhook_type,
            target_path=target_path,
            manifest=manifest,
            application_id=effective_app_id,
        )

    overall_elapsed = (datetime.now(timezone.utc) - overall_started).total_seconds()
    console.print(
        f"\n[bold]Batch complete:[/bold] "
        f"{len(targets) - failures}/{len(targets)} succeeded in {overall_elapsed:.1f}s"
    )
    return 0 if failures == 0 else 1
