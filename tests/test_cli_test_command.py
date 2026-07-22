# Copyright 2026 Visa, Inc.
# Licensed under the Apache License, Version 2.0

"""The first-class complete-suite test command."""
from __future__ import annotations

from types import SimpleNamespace

from vvaharness import cli
from vvaharness import config as config_mod
from vvaharness import orchestrator


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
    monkeypatch.setattr(
        cli, "_test_models_online",
        lambda config: seen.update(config=config) or 0,
    )
    config = tmp_path / "profile.yaml"
    assert cli._test([
        "--root", str(root), "--config", str(config), "-x",
    ]) == 0
    assert seen["cwd"] == root
    assert seen["command"][:5] == [cli.sys.executable, "-m", "pytest", "-ra", "tests"]
    assert seen["command"][-1] == "-x"
    assert seen["check"] is False
    assert seen["config"] == str(config)


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


def test_test_command_propagates_model_probe_failure(tmp_path, monkeypatch):
    root = tmp_path / "source"
    (root / "tests").mkdir(parents=True)
    (root / "vvaharness").mkdir()
    (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    monkeypatch.setattr(
        cli.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(cli, "_test_models_online", lambda config: 1)

    assert cli._test(["--root", str(root)]) == 1


def test_test_command_can_explicitly_skip_model_probe(tmp_path, monkeypatch):
    root = tmp_path / "source"
    (root / "tests").mkdir(parents=True)
    (root / "vvaharness").mkdir()
    (root / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    seen = {"probed": False}
    monkeypatch.setattr(
        cli.subprocess, "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0),
    )
    monkeypatch.setattr(
        cli, "_test_models_online",
        lambda config: seen.update(probed=True) or 0,
    )

    assert cli._test(["--root", str(root), "--skip-model-check"]) == 0
    assert seen["probed"] is False


def test_test_command_requires_source_checkout(tmp_path):
    assert cli._test(["--root", str(tmp_path)]) == 2


def test_model_check_loads_configures_and_probes_selected_profile(
        tmp_path, monkeypatch):
    profile = tmp_path / "profile.yaml"
    profile.write_text("models: {}\n", encoding="utf-8")
    cfg = SimpleNamespace(models=SimpleNamespace())
    seen = {}
    monkeypatch.setattr(config_mod, "load", lambda path: seen.update(load=path) or cfg)
    monkeypatch.setattr(
        orchestrator, "configure_backends",
        lambda loaded, base: seen.update(configure=(loaded, base)),
    )
    monkeypatch.setattr(
        orchestrator, "probe_backends",
        lambda loaded: seen.update(probe=loaded) or True,
    )

    assert cli._test_models_online(str(profile)) == 0
    assert seen["load"] == str(profile)
    assert seen["configure"] == (cfg, profile.parent)
    assert seen["probe"] is cfg


def test_model_check_rejects_missing_config(tmp_path):
    assert cli._test_models_online(str(tmp_path / "missing.yaml")) == 2
