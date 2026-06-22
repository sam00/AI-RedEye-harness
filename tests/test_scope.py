"""Scope (PR-scan / DoS limits / exclusions) tests."""

from __future__ import annotations

from pathlib import Path

from redeye.scope import Scope


def _seed(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "src" / "big.py").write_text("x = 1\n" * 50000, encoding="utf-8")
    (tmp_path / "tests" / "test_main.py").write_text("y = 1\n", encoding="utf-8")
    (tmp_path / "vendor" / "pkg.py").write_text("z = 1\n", encoding="utf-8")
    return tmp_path


def test_full_walk_includes_everything(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    scope = Scope.build(target=repo)
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "tests/test_main.py" in paths
    # vendor/ is in _DEFAULT_IGNORE_DIRS at the directory level
    assert "vendor/pkg.py" not in paths


def test_exclude_path_drops_tests(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    scope = Scope.build(target=repo, exclude_paths=["tests"])
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "tests/test_main.py" not in paths
    assert len(scope.skipped_excluded) >= 1


def test_max_file_bytes_drops_oversize(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    scope = Scope.build(target=repo, max_file_bytes=1000)
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "src/big.py" not in paths
    assert any("big.py" in str(p) for p in scope.skipped_oversize)


def test_max_files_truncates(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    scope = Scope.build(target=repo, max_files=1)
    assert len(scope.files) == 1
    assert scope.skipped_truncated >= 1
