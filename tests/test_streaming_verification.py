# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Offline tests for the opt-in streaming s4/s5/s6 experiment."""
from __future__ import annotations

from threading import Event
from types import SimpleNamespace

import pytest

from vvaharness.models import Chunk, ChunkSize, ContextPackage, Finding, VulnClass
from vvaharness.orchestrator import entry, streaming_verification
from vvaharness.pipeline.stages import asan_verify, s4_deepdive


def _finding(title: str = "heap overflow") -> Finding:
    return Finding(
        chunk_id="chunk-1", file="src/parser.c", line_start=10, line_end=12,
        vuln_class=VulnClass.HEAP_OVERFLOW, title=title,
        description="untrusted length reaches memcpy", code_snippet="memcpy(d,s,n)",
        source_ref="src/parser.c:5", sink_ref="src/parser.c:10", confidence=0.9,
    )


def _ctx() -> ContextPackage:
    return ContextPackage(repo_root="/repo", language="c-cpp",
                          all_files=["src/parser.c"])


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(
        step5_prefilter=SimpleNamespace(
            min_pre_confidence=0.0, require_evidence=False,
            allowed_classes=[VulnClass.HEAP_OVERFLOW]),
        step6_verify=SimpleNamespace(parallel=1, min_confidence=7),
        step7_dedup=SimpleNamespace(
            line_tolerance=10, pre_verify_threshold=0, semantic=False),
    )


def test_verification_starts_before_s4_returns(monkeypatch):
    finding = _finding()
    verifier_started = Event()

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        assert on_findings is not None
        on_findings([finding])
        assert verifier_started.wait(2), "s6 did not overlap the still-running s4"
        return [finding], {"chunk-1": "completed"}

    def fake_verify(_idx, candidate, _ctx, _cfg):
        verifier_started.set()
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "confirmed", "cvss_score": 8.1,
        })

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)

    result = streaming_verification.run([object()], _ctx(), _cfg())

    assert result.findings == [finding]
    assert len(result.static_verified) == 1
    assert result.static_verified[0].verdict == "TRUE_POSITIVE"
    assert result.submitted == 1
    assert result.speculative == 0


def test_saturated_verifier_cannot_block_audit(monkeypatch):
    """Verifier backpressure belongs to the dispatcher, never an s4 worker."""
    findings = [
        _finding(f"bug-{i}").model_copy(update={
            "line_start": 10 + i * 100,
            "line_end": 12 + i * 100,
            "source_ref": f"src/parser.c:{5 + i * 100}",
            "sink_ref": f"src/parser.c:{10 + i * 100}",
        })
        for i in range(3)
    ]
    audit_returned = Event()
    verified_titles: list[str] = []

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        assert on_findings is not None
        for finding in findings:
            on_findings([finding])
        # With the old synchronous semaphore callback, the third emission
        # blocked here because parallel=1 permits only two in-flight futures.
        audit_returned.set()
        return findings, {"chunk-1": "completed"}

    def fake_verify(_idx, candidate, _ctx, _cfg):
        assert audit_returned.wait(2), "s6 backpressure paused the s4 producer"
        verified_titles.append(candidate.title)
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "confirmed",
        })

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)

    result = streaming_verification.run([object()], _ctx(), _cfg())

    assert audit_returned.is_set()
    assert set(verified_titles) == {finding.title for finding in findings}
    assert len(result.static_verified) == 3


def test_s4_emits_only_final_voted_representative(monkeypatch, tmp_path):
    low = _finding().model_copy(update={"confidence": 0.8})
    high = _finding().model_copy(update={"confidence": 0.99})
    run_count = 0
    emitted: list[tuple[int, list[Finding]]] = []

    def fake_single_run(*_args, **_kwargs):
        nonlocal run_count
        run_count += 1
        return [low] if run_count == 1 else [high]

    monkeypatch.setattr(s4_deepdive, "_load_chunk_code", lambda *_a: "")
    monkeypatch.setattr(s4_deepdive, "_neighbor_context", lambda *_a: "")
    monkeypatch.setattr(s4_deepdive, "_single_run", fake_single_run)
    chunk = Chunk(id="chunk-1", size=ChunkSize.SMALL, risk_rank=1,
                  files=[], hypothesis="test")
    cfg = SimpleNamespace(step4=SimpleNamespace(
        line_bucket=10, specialist_runs=1))
    ctx = ContextPackage(repo_root=str(tmp_path), language="c-cpp")

    survivors = s4_deepdive._deepdive_chunk(
        chunk, ctx, tmp_path, cfg, runs_n=2, threshold=1,
        on_findings=lambda batch: emitted.append((run_count, batch)))

    assert emitted == [(2, [high])]
    assert survivors == [high]


def test_asan_starts_before_s4_returns(monkeypatch, capsys):
    """Prove the dynamic verifier overlaps an auditor that is still running."""
    finding = _finding()
    asan_started = Event()
    s4_started = Event()
    s4_returned = Event()
    cfg = _cfg()
    cfg.step6_verify.asan = SimpleNamespace(
        enabled=True, all_classes=True, require_crash=True,
        max_findings="all")

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        assert on_findings is not None
        s4_started.set()
        on_findings([finding])
        assert asan_started.wait(30), (
            "ASAN did not start while the s4 producer was still running")
        s4_returned.set()
        return [finding], {"chunk-1": "completed"}

    def fake_verify(_idx, candidate, _ctx, _cfg):
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "confirmed",
        })

    def fake_build(_ctx, _cfg, *, findings=None):
        assert findings is not None and len(findings) == 1
        assert findings[0].title == finding.title
        assert findings[0].verdict == "TRUE_POSITIVE"
        assert s4_started.wait(30)
        assert not s4_returned.is_set()
        asan_started.set()
        return asan_verify.AsanBuildResult(True, "ASAN_REPO_BUILD_OK")

    def fake_asan_run(candidate, _ctx, _cfg, *, idx, build=None):
        assert build is not None and build.succeeded
        return asan_verify.AsanResult(
            attempted=True, crashed=True, summary="ASAN_CRASH")

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)
    monkeypatch.setattr(streaming_verification.asan_verify, "build_repo", fake_build)
    monkeypatch.setattr(streaming_verification.asan_verify, "run", fake_asan_run)

    result = streaming_verification.run([object()], _ctx(), cfg)

    assert s4_returned.is_set()
    assert len(result.verified) == 1
    assert result.verified[0].asan_status == "crash_confirmed"
    assert "[stage456-progress] DONE findings=1 static_confirmed=1 " \
           "dynamic_confirmed=1" in capsys.readouterr().err


def test_streaming_never_retains_no_crash_even_if_config_disables_gate(
        monkeypatch):
    finding = _finding()
    cfg = _cfg()
    cfg.step6_verify.asan = SimpleNamespace(
        enabled=True, all_classes=True, require_crash=False,
        max_findings="all")

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        assert on_findings is not None
        on_findings([finding])
        return [finding], {"chunk-1": "completed"}

    def fake_verify(_idx, candidate, _ctx, _cfg):
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "provisional static verdict",
        })

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)
    monkeypatch.setattr(
        streaming_verification.asan_verify, "build_repo",
        lambda *_args, **_kwargs: asan_verify.AsanBuildResult(
            True, "ASAN_REPO_BUILD_OK"),
    )
    monkeypatch.setattr(
        streaming_verification.asan_verify, "run",
        lambda *_args, **_kwargs: asan_verify.AsanResult(
            attempted=True, crashed=False, summary="NO_ASAN_CRASH"),
    )

    result = streaming_verification.run([object()], _ctx(), cfg)

    assert result.static_verified[0].verdict == "TRUE_POSITIVE"
    assert result.verified == []
    assert len(result.asan_dropped) == 1
    assert result.asan_dropped[0].reason == "UNCONFIRMED"
    assert result.asan_dropped[0].finding is not None
    assert result.asan_dropped[0].finding.verdict is None


def test_full_s5_selection_is_authoritative(monkeypatch):
    keep = _finding("keep")
    speculative = _finding("later duplicate")
    verified_titles: list[str] = []

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        on_findings([keep, speculative])
        return [keep, speculative], {"chunk-1": "completed"}

    def fake_full_s5(_findings, _ctx, _cfg):
        return [keep], []

    def fake_verify(_idx, candidate, _ctx, _cfg):
        verified_titles.append(candidate.title)
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "confirmed",
        })

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s5_prefilter, "run", fake_full_s5)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)

    result = streaming_verification.run([object()], _ctx(), _cfg())

    assert set(verified_titles) == {"keep", "later duplicate"}
    assert [item.title for item in result.static_verified] == ["keep"]
    assert result.submitted == 2
    assert result.speculative == 1


def test_experimental_flag_is_advertised(capsys):
    with pytest.raises(SystemExit) as exc:
        entry.main(["--help"])
    assert exc.value.code == 0
    assert "--experimental-streaming-verification" in capsys.readouterr().out


def test_streaming_reports_stage5_and_stage6_progress(monkeypatch, capsys):
    finding = _finding()

    def fake_s4(_chunks, _ctx, _cfg, on_findings=None):
        assert on_findings is not None
        on_findings([finding])
        return [finding], {"chunk-1": "completed"}

    def fake_verify(_idx, candidate, _ctx, _cfg):
        return candidate.model_copy(update={
            "verdict": "TRUE_POSITIVE", "verdict_confidence": 9,
            "verdict_reason": "confirmed",
        })

    monkeypatch.setattr(streaming_verification.s4_deepdive, "run", fake_s4)
    monkeypatch.setattr(streaming_verification.s6_verify, "_verify_one", fake_verify)

    streaming_verification.run([object()], _ctx(), _cfg())

    stderr = capsys.readouterr().err
    assert "[s5-progress] STREAM received=1 eligible=1 filtered=0" in stderr
    assert "[s6-progress] STATIC event=submitted" in stderr
    assert "[s6-progress] STATIC event=started" in stderr
    assert "[s6-progress] STATIC event=completed:true_positive" in stderr
    assert "queued=0 running=0 completed=1 tp=1 dropped=0" in stderr
    assert "[s6-progress] DONE static_completed=1 static_tp=1" in stderr
    assert "[stage456-progress] event=findings findings=1 " \
           "static_confirmed=0 dynamic_confirmed=0" in stderr
    assert "[stage456-progress] event=static findings=1 " \
           "static_confirmed=1 dynamic_confirmed=0" in stderr
    assert "[stage456-progress] DONE findings=1 static_confirmed=1 " \
           "dynamic_confirmed=0" in stderr


def test_s4_reports_start_completion_and_summary(monkeypatch, tmp_path, capsys):
    finding = _finding()
    chunk = Chunk(id="chunk-1", size=ChunkSize.SMALL, risk_rank=1,
                  files=["src/parser.c"], hypothesis="test")
    cfg = SimpleNamespace(step4=SimpleNamespace(parallel=1, line_bucket=10))
    ctx = ContextPackage(repo_root=str(tmp_path), language="c-cpp",
                         all_files=["src/parser.c"])

    monkeypatch.setattr(s4_deepdive, "_effective_runs", lambda _cfg: (1, 1))
    monkeypatch.setattr(
        s4_deepdive, "_deepdive_chunk",
        lambda *_args, **_kwargs: [finding])

    findings, outcomes = s4_deepdive.run([chunk], ctx, cfg)

    assert findings == [finding]
    assert outcomes == {"chunk-1": "completed"}
    stderr = capsys.readouterr().err
    assert "[s4-progress] START total=1 parallel=1 runs=1 vote_threshold=1" in stderr
    assert "[s4-progress] 1/1 chunks (100%) outcome=completed" in stderr
    assert "active=0 queued=0" in stderr
    assert "[s4-progress] DONE chunks=1/1 findings=1 coverage_failures=0" in stderr
