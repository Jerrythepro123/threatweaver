# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for s11 validation SQLite checkpoint/resume (mirrors s10 remediation).

Fully offline: ``VVAHARNESS_STATE_DIR`` points at a tmp dir so the real SQLite
store is exercised, and ``_validate_one`` is monkeypatched so no agent/LLM runs.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from vvaharness.orchestrator import store
from vvaharness.orchestrator.checkpoints import load_ckpt, run_id_for, save_ckpt
from vvaharness.validation.cli import _resolve_selection, _run
from vvaharness.validation.cli._parser import _build_parser
from vvaharness.validation.cli._run import Selection, ValidationRun, run_validation
from vvaharness.validation.constants.artifacts import STATUS_AWAITING_VALIDATION
from vvaharness.validation.models import ValidationResult


@pytest.fixture(autouse=True)
def _state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the SQLite state store at an isolated per-test dir."""
    monkeypatch.setenv("VVAHARNESS_STATE_DIR", str(tmp_path / "state"))


def _result(fid: str) -> ValidationResult:
    """A successful validation-result stand-in (these tests exercise run/checkpoint/resume
    mechanics, not the agent). A non-UNVERIFIABLE verdict keeps the run exit code 0."""
    return ValidationResult(
        finding_number=0, tracking_id=fid, finding_title="t",
        finding_description="", affected_files="",
        fixed="Yes", partially_fixed="No", not_fixed="No",
        files_needing_fixes="", reason_for_decision="Fixed",
        severity="HIGH", pr_merge_readiness="ready", recommendations="",
    )


def _write_report(repo: Path, fid: str, *, dirname: str | None = None, cvss: float = 5.0) -> None:
    d = repo / "security-remediation" / (dirname or fid)
    d.mkdir(parents=True)
    (d / "remediate_report.json").write_text(json.dumps({
        "finding_id": fid,
        "status": STATUS_AWAITING_VALIDATION,
        "finding": {"cvss_score": cvss},
        "patch": {"diff": "", "files_touched": []},
    }))


def _run_args(repo: Path, selection: Selection) -> int:
    return run_validation(
        repo=repo,
        selection=selection,
        workspace_root=repo / "ws",
        config=SimpleNamespace(),
    )


# ---------------------------------------------------------------------------
# checkpoint schema round-trip (validate_ branch in checkpoints._schema_for)
# ---------------------------------------------------------------------------


def test_validate_checkpoint_roundtrip(tmp_path: Path) -> None:
    """A ValidationResult saved under a validate_ step reloads byte-equal."""
    rid = run_id_for(tmp_path)
    res = _result("F-1")
    save_ckpt(tmp_path, rid, "validate_F-1", res)
    assert load_ckpt(tmp_path, rid, "validate_F-1") == res


def test_validate_checkpoint_enum_fields_survive(tmp_path: Path) -> None:
    """make_unverifiable injects Answer.* StrEnums into str fields — round-trip is lossless."""
    rid = run_id_for(tmp_path)
    save_ckpt(tmp_path, rid, "validate_F-2", _result("F-2"))
    loaded = load_ckpt(tmp_path, rid, "validate_F-2")
    assert loaded is not None
    assert loaded.tracking_id == "F-2"
    assert str(loaded.fixed) in {"No", "Yes", "?"}


# ---------------------------------------------------------------------------
# run_validation registers the run (fixes the standalone ghost-row gap)
# ---------------------------------------------------------------------------


def test_run_validation_registers_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """run_validation creates a runs row keyed by run_id_for(repo) with a real repo_root."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_report(repo, "F-1")
    monkeypatch.setattr(_run, "_validate_one", lambda report, run: _result(report.finding_id))

    assert _run_args(repo, Selection()) == 0

    with store.connect() as cx:
        row = cx.execute("SELECT run_id, repo_root FROM runs").fetchone()
    assert row[0] == run_id_for(repo)
    assert row[1] == str(repo.resolve())  # non-empty → no ghost row


def test_run_validation_saves_checkpoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful validation writes a validate_<id> checkpoint."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_report(repo, "F-1")
    monkeypatch.setattr(_run, "_validate_one", lambda report, run: _result(report.finding_id))

    _run_args(repo, Selection())

    assert load_ckpt(repo / "ws", run_id_for(repo), _run._step_key("F-1")) is not None


# ---------------------------------------------------------------------------
# resume semantics
# ---------------------------------------------------------------------------


def test_resume_skips_checkpointed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--resume skips findings with an existing checkpoint, validates the rest."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_report(repo, "F-done")
    _write_report(repo, "F-new")
    save_ckpt(repo / "ws", run_id_for(repo), _run._step_key("F-done"), _result("F-done"))

    seen: list[str] = []
    monkeypatch.setattr(
        _run, "_validate_one",
        lambda report, run: (seen.append(report.finding_id), _result(report.finding_id))[1],
    )
    _run_args(repo, Selection(resume=True))

    assert "F-done" not in seen   # skipped via checkpoint
    assert "F-new" in seen        # freshly validated


def test_no_resume_revalidates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without --resume, a checkpointed finding is re-validated (today's behavior)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_report(repo, "F-done")
    save_ckpt(repo / "ws", run_id_for(repo), _run._step_key("F-done"), _result("F-done"))

    seen: list[str] = []
    monkeypatch.setattr(
        _run, "_validate_one",
        lambda report, run: (seen.append(report.finding_id), _result(report.finding_id))[1],
    )
    _run_args(repo, Selection(resume=False))

    assert seen == ["F-done"]


def test_resume_unsafe_finding_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The step key hashes the full finding id, so resume matches the persisted key."""
    repo = tmp_path / "repo"
    repo.mkdir()
    fid = "routers/exec.py:49"
    _write_report(repo, fid, dirname="routers_exec")
    save_ckpt(repo / "ws", run_id_for(repo), _run._step_key(fid), _result(fid))

    seen: list[str] = []
    monkeypatch.setattr(
        _run, "_validate_one",
        lambda report, run: (seen.append(report.finding_id), _result(report.finding_id))[1],
    )
    _run_args(repo, Selection(resume=True))

    assert seen == []  # skipped — hashed key matched


def test_step_key_distinguishes_ids_colliding_under_safe() -> None:
    """Two ids that sanitize+truncate to the same _safe name get distinct step keys."""
    long = "a" * 200
    a = long + "/X"
    b = long + "/Y"
    assert _run._safe(a) == _run._safe(b)        # collide once sanitized + 80-char truncated
    assert _run._step_key(a) != _run._step_key(b)  # full-fidelity hash keeps them apart


def test_resume_ignores_foreign_tracking_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A checkpoint whose verdict is for a different finding is re-validated, never reused."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_report(repo, "F-1")
    # Park a result for a *different* finding under F-1's step key.
    save_ckpt(repo / "ws", run_id_for(repo), _run._step_key("F-1"), _result("OTHER"))

    seen: list[str] = []
    monkeypatch.setattr(
        _run, "_validate_one",
        lambda report, run: (seen.append(report.finding_id), _result(report.finding_id))[1],
    )
    _run_args(repo, Selection(resume=True))

    assert seen == ["F-1"]  # identity mismatch → re-validated, foreign verdict not substituted


# ---------------------------------------------------------------------------
# parser + selection wiring for --resume
# ---------------------------------------------------------------------------


def test_parser_resume_flag() -> None:
    """--resume parses to args.resume True; absent defaults False."""
    assert _build_parser().parse_args(["--repo", ".", "--all", "--resume"]).resume is True
    assert _build_parser().parse_args(["--repo", ".", "--all"]).resume is False


@pytest.mark.parametrize("kw", [{"all": True}, {"findings": ["F-1"]}, {}])
def test_resolve_selection_threads_resume(kw: dict) -> None:
    """resume rides through every _resolve_selection precedence branch (all / finding / default)."""
    base = {"all": False, "findings": None, "max_findings": None, "resume": True}
    base.update(kw)
    cfg = SimpleNamespace(max_findings=20)
    assert _resolve_selection(SimpleNamespace(**base), cfg).resume is True


def test_validation_run_resume_default() -> None:
    """ValidationRun defaults resume to False."""
    run = ValidationRun(
        repo=Path("."), workspace_root=Path("ws"),
        config=SimpleNamespace(), run_id="abc",
    )
    assert run.resume is False
