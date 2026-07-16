# Copyright 2026 Visa, Inc.
# Licensed under the Apache License, Version 2.0

"""The first-class complete-suite test command."""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness import cli


def test_test_command_runs_entire_tests_directory(tmp_path, monkeypatch):
    root = tmp_path / "source"
    (root / "tests").mkdir(parents=True)
    (root / "vvaharness").mkdir()
    (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (root / "tests" / "test_one.py").write_text("", encoding="utf-8")
    seen = {}

    def fake_run(command, *, cwd, check):
        seen.update(command=command, cwd=cwd, check=check)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert cli._test(["--root", str(root), "-x"]) == 0
    assert seen["cwd"] == root
    assert seen["command"][:5] == [cli.sys.executable, "-m", "pytest", "-ra", "tests"]
    assert seen["command"][-1] == "-x"
    assert seen["check"] is False


def test_test_command_propagates_pytest_exit_code(tmp_path, monkeypatch):
    root = tmp_path / "source"
    (root / "tests").mkdir(parents=True)
    (root / "vvaharness").mkdir()
    (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(
        cli.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=5),
    )
    assert cli._test(["--root", str(root)]) == 5


def test_test_command_requires_source_checkout(tmp_path):
    assert cli._test(["--root", str(tmp_path)]) == 2
