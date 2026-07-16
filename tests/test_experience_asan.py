# Copyright 2026 Visa, Inc.
# Licensed under the Apache License, Version 2.0

"""Persistent, human-curated ASAN experience archive."""
from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace

import yaml

from vvaharness.experience import asan as experience
from vvaharness.experience.cli import main as experience_main
from vvaharness.orchestrator.scan import scan_repo
from vvaharness.pipeline.stages import s6_verify


def _finding(artifact_dir: Path, *, crashed: bool = True):
    return SimpleNamespace(
        vuln_class=SimpleNamespace(value="heap_overflow"),
        cwe="CWE-122",
        title="heap overwrite in parser",
        file="src/parser.cpp",
        line_start=40,
        line_end=44,
        source_ref="server.cpp:10",
        sink_ref="src/parser.cpp:42",
        code_snippet="memcpy(dst, src, length);",
        description="attacker length reaches memcpy",
        exploit_scenario="remote request causes an ASAN crash",
        asan_status="crash_confirmed" if crashed else "no_crash",
        asan_evidence="AddressSanitizer: heap-buffer-overflow",
        asan_repro_command="./server --repro request.bin",
        asan_artifacts=[str(artifact_dir)],
    )


def _ctx(repo: Path):
    return SimpleNamespace(repo_root=str(repo), language="c++")


def test_completed_scan_saves_yaml_and_artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_EXPERIENCE_DIR", str(tmp_path / "experience"))
    repo = tmp_path / "repo"
    repo.mkdir()
    artifacts = tmp_path / "repro"
    artifacts.mkdir()
    (artifacts / "asan.log").write_text("crash", encoding="utf-8")
    report = SimpleNamespace(findings=[SimpleNamespace(finding=_finding(artifacts))])

    saved, rejected = experience.save_completed_scan(
        report, _ctx(repo), scan_id="scan-1")

    assert rejected == 0
    assert len(saved) == 1
    assert (saved[0] / "artifacts" / "asan.log").read_text() == "crash"
    data = yaml.safe_load((saved[0] / "experience.yaml").read_text(encoding="utf-8"))
    assert data["active"] is True
    assert data["seen_count"] == 1
    assert data["observations"][0]["scan_id"] == "scan-1"


def test_same_scan_is_idempotent_and_future_scan_increments(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_EXPERIENCE_DIR", str(tmp_path / "experience"))
    repo = tmp_path / "repo"
    repo.mkdir()
    artifacts = tmp_path / "repro"
    artifacts.mkdir()
    finding = _finding(artifacts)
    ctx = _ctx(repo)

    path = experience.save_verified_bug(finding, ctx, scan_id="scan-1")
    experience.save_verified_bug(finding, ctx, scan_id="scan-1")
    experience.save_verified_bug(finding, ctx, scan_id="scan-2")

    record = experience.resolve_experience(path.name)[1]
    assert record.seen_count == 2
    assert [item.scan_id for item in record.observations] == ["scan-1", "scan-2"]


def test_human_remove_prevents_relearning_and_restore_allows_it(tmp_path, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_EXPERIENCE_DIR", str(tmp_path / "experience"))
    repo = tmp_path / "repo"
    repo.mkdir()
    artifacts = tmp_path / "repro"
    artifacts.mkdir()
    finding = _finding(artifacts)
    ctx = _ctx(repo)
    path = experience.save_verified_bug(finding, ctx, scan_id="scan-1")

    rejected = experience.reject_experience(path.name[:12], "not remotely reachable")
    assert rejected.parent.name == "rejected"
    assert experience.save_verified_bug(finding, ctx, scan_id="scan-2") is None
    restored = experience.restore_experience(path.name[:12])
    assert restored.parent.name == "active"
    assert experience.save_verified_bug(finding, ctx, scan_id="scan-2") == restored


def test_cli_list_remove_and_validate(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VVAHARNESS_EXPERIENCE_DIR", str(tmp_path / "experience"))
    repo = tmp_path / "repo"
    repo.mkdir()
    artifacts = tmp_path / "repro"
    artifacts.mkdir()
    path = experience.save_verified_bug(_finding(artifacts), _ctx(repo), scan_id="scan-1")

    assert experience_main(["list"]) == 0
    assert path.name[:16] in capsys.readouterr().out
    assert experience_main(["remove", path.name[:12], "--reason", "wrong"]) == 0
    assert experience_main(["validate"]) == 0


def test_only_s9_commits_experience():
    s6_source = inspect.getsource(s6_verify)
    scan_source = inspect.getsource(scan_repo)
    assert "save_completed_scan" not in s6_source
    assert scan_source.index("md_to_sarif") < scan_source.index("save_completed_scan")
