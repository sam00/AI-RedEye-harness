"""Init-wizard tests.

We exercise the non-interactive path (used by CI bootstrap) and confirm:

1. The wizard writes a tailored .env at the requested path.
2. The .env has a REDEYE_PROFILE= line matching the chosen profile.
3. Existing files are NOT overwritten in non-interactive mode.
4. The detection table identifies mock as always-available.
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from redeye.commands.init import _detect, _recommend, _render_env, run


def test_detection_includes_mock_always_available() -> None:
    rows = _detect()
    mock = next(r for r in rows if r.backend == "mock")
    assert mock.detected is True


def test_recommendation_returns_a_known_profile() -> None:
    rows = _detect()
    profile, _why = _recommend(rows)
    assert profile in {"default", "cli", "full", "fable", "mock"}


def test_render_env_contains_redeye_profile_line() -> None:
    rows = _detect()
    body = _render_env(rows, "mock")
    assert "REDEYE_PROFILE=mock" in body


def test_non_interactive_writes_env(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    rc = run(
        console=Console(record=True),
        output_env=env_path,
        write_config=False,
        non_interactive=True,
    )
    assert rc == 0
    assert env_path.is_file()
    body = env_path.read_text(encoding="utf-8")
    assert body.startswith("# Red Eye")
    assert "REDEYE_PROFILE=" in body


def test_non_interactive_does_not_overwrite_existing_env(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("EXISTING=keep_me\n", encoding="utf-8")
    rc = run(
        console=Console(record=True),
        output_env=env_path,
        write_config=False,
        non_interactive=True,
    )
    assert rc == 0
    # In non-interactive mode, we MUST NOT clobber a user's existing .env.
    assert env_path.read_text(encoding="utf-8") == "EXISTING=keep_me\n"
