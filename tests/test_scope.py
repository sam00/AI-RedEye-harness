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


def test_exclude_dirs(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    (repo / "migrations").mkdir()
    (repo / "migrations" / "0001.py").write_text("x = 1\n", encoding="utf-8")
    scope = Scope.build(target=repo, exclude_dirs=["migrations"])
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "migrations/0001.py" not in paths


def test_exclude_exts_normalises_without_dot(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    (repo / "src" / "config.json").write_text("{}\n", encoding="utf-8")
    scope = Scope.build(target=repo, exclude_exts=["json"])  # no leading dot
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "src/config.json" not in paths


def test_exclude_globs(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    (repo / "src" / "thing.min.js").write_text("var x=1\n", encoding="utf-8")
    scope = Scope.build(target=repo, exclude_globs=["**/*.min.js"])
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/thing.min.js" not in paths


def test_max_file_kb_combines_with_bytes(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    # big.py is ~300KB; cap at 1 KB drops it.
    scope = Scope.build(target=repo, max_file_kb=1)
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/main.py" in paths
    assert "src/big.py" not in paths
    assert any("big.py" in str(p) for p in scope.skipped_oversize)


def test_dedupe_configs(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    (repo / "a.yaml").write_text("key: value\n", encoding="utf-8")
    (repo / "b.yaml").write_text("key: value\n", encoding="utf-8")  # identical
    (repo / "c.yaml").write_text("key: other\n", encoding="utf-8")
    scope = Scope.build(target=repo, dedupe_configs=True)
    names = {p.name for p in scope.files}
    # One of the identical pair is dropped; the distinct one is kept.
    assert "c.yaml" in names
    assert len(scope.skipped_dupe_configs) == 1


def test_symlink_skipped_by_default(tmp_path: Path) -> None:
    repo = _seed(tmp_path)
    link = repo / "src" / "link.py"
    try:
        link.symlink_to(repo / "src" / "main.py")
    except (OSError, NotImplementedError):
        return  # platform without symlink support
    scope = Scope.build(target=repo)
    paths = {p.relative_to(repo).as_posix() for p in scope.files}
    assert "src/link.py" not in paths
    assert any("link.py" in str(p) for p in scope.skipped_symlinks)
