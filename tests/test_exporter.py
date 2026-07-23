"""Tests for the export bundle and its path safety."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yagtha.errors import ExportError
from yagtha.exporter import (
    ANALYSIS,
    IMPROVED_RULE,
    REGRESSION_TEST_SOURCE,
    REPORT,
    bundle_name,
    resolve_output_dir,
    write_bundle,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    path = tmp_path / "output"
    path.mkdir()
    return path


def test_bundle_name() -> None:
    assert bundle_name(Path("data/rules/mimikatz.yml")) == "mimikatz"
    assert bundle_name(Path("My Rule (v2).yml")) == "my_rule_v2"
    assert bundle_name(Path("../../..yml")) == "rule"
    assert len(bundle_name(Path("a" * 200 + ".yml"))) == 64


def test_output_dir_must_be_inside_root(root: Path) -> None:
    assert resolve_output_dir(root, root) == root.resolve()
    assert resolve_output_dir(root / "sub", root) == (root / "sub").resolve()
    for bad in (root.parent, root / ".." / "elsewhere", Path(root.anchor), root.parent / "output2"):
        with pytest.raises(ExportError, match="must be inside"):
            resolve_output_dir(bad, root)


def test_write_bundle(root: Path) -> None:
    bundle = write_bundle(root, "mimikatz", {REPORT: "# r\n", ANALYSIS: "{}\n"}, root)
    assert bundle == (root / "mimikatz").resolve()
    assert sorted(p.name for p in bundle.iterdir()) == [ANALYSIS, REPORT]
    assert (bundle / REPORT).read_text(encoding="utf-8") == "# r\n"


def test_rewrite_removes_files_of_an_earlier_run(root: Path) -> None:
    write_bundle(root, "rule", {REPORT: "a", IMPROVED_RULE: "b"}, root)
    bundle = write_bundle(root, "rule", {REPORT: "c"}, root)
    assert [p.name for p in bundle.iterdir()] == [REPORT]


def test_bad_names_and_files_are_rejected(root: Path) -> None:
    for name in ("../x", "x/y", "", "UPPER", "-x"):
        with pytest.raises(ExportError, match="invalid bundle name"):
            write_bundle(root, name, {REPORT: ""}, root)
    with pytest.raises(ExportError, match="unknown bundle files"):
        write_bundle(root, "rule", {"../evil.py": ""}, root)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symbolic_links_are_refused(root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (root / "linked").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not permitted")
    with pytest.raises(ExportError, match="symbolic link"):
        write_bundle(root, "linked", {REPORT: ""}, root)
    (root / "rule").mkdir()
    (root / "rule" / REPORT).symlink_to(outside / "target.md")
    with pytest.raises(ExportError, match="symbolic link"):
        write_bundle(root, "rule", {REPORT: ""}, root)
    assert not (outside / "target.md").exists()
    with pytest.raises(ExportError, match="must be inside"):
        write_bundle(root / "linked", "rule", {REPORT: ""}, root)


def test_regression_test_source_is_static_python() -> None:
    compile(REGRESSION_TEST_SOURCE, "test_regression.py", "exec")
    assert "{" not in REGRESSION_TEST_SOURCE
