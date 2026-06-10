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

"""Unit tests for vvaharness.util.metrics — pure aggregation helpers.

Offline & deterministic: no network, no LLM, no subprocess. The only global
state touched is util.tokens.TOKENS; an autouse fixture resets it so the full
suite is order-independent.
"""
from __future__ import annotations

import re

import pytest

from vvaharness.util import metrics
from vvaharness.util.tokens import TOKENS
from vvaharness.models import (
    ContextPackage,
    TaskManifest,
    Chunk,
    ScanMetrics,
    ScopeEntry,
    FinalReport,
)


# ─────────────────────────────────────────────────────────────────────────────
# Global-state isolation: TOKENS is a process-wide singleton. Reset before AND
# after every test so neither prior token accounting nor our own writes leak
# into sibling test files when the whole suite runs together.
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# now_iso
# ─────────────────────────────────────────────────────────────────────────────
def test_now_iso_matches_utc_zulu_format():
    ts = metrics.now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", ts), ts


def test_now_iso_roundtrips_via_fromisoformat():
    from datetime import datetime, timezone

    ts = metrics.now_iso()
    parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    assert parsed.tzinfo == timezone.utc


# ─────────────────────────────────────────────────────────────────────────────
# _loc — counts non-blank lines, swallows OSError
# ─────────────────────────────────────────────────────────────────────────────
def test_loc_counts_only_nonblank_lines(tmp_path):
    p = tmp_path / "code.py"
    # 3 non-blank lines, 2 blank/whitespace-only lines
    p.write_text("alpha\n\nbeta\n   \ngamma\n", encoding="utf-8")
    assert metrics._loc(p) == 3


def test_loc_empty_file_is_zero(tmp_path):
    p = tmp_path / "empty.py"
    p.write_text("", encoding="utf-8")
    assert metrics._loc(p) == 0


def test_loc_missing_file_returns_zero(tmp_path):
    # OSError path: file does not exist.
    assert metrics._loc(tmp_path / "does-not-exist.py") == 0


def test_loc_directory_returns_zero(tmp_path):
    # Opening a directory raises OSError (IsADirectoryError) -> 0.
    assert metrics._loc(tmp_path) == 0


# ─────────────────────────────────────────────────────────────────────────────
# Helpers to build inputs for build()
# ─────────────────────────────────────────────────────────────────────────────
def _write(repo, rel, text):
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return rel


def _ctx(repo_root, all_files, excluded=None):
    return ContextPackage(
        repo_root=str(repo_root),
        language="python",
        all_files=list(all_files),
        excluded=excluded if excluded is not None else {},
    )


# ─────────────────────────────────────────────────────────────────────────────
# build — chunk classification (risk / catchall / specialist)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_classifies_chunk_kinds(tmp_path):
    repo = tmp_path / "repo"
    f_risk = _write(repo, "src/a.py", "x = 1\n")
    f_catch = _write(repo, "src/b.py", "y = 2\n")
    f_spec = _write(repo, "src/c.py", "z = 3\n")

    manifest = TaskManifest(
        chunks=[
            Chunk(id="chunk-01", files=[f_risk]),
            Chunk(id="catchall-1", files=[f_catch]),
            Chunk(id="chunk-spec", files=[f_spec], specialist="crypto"),
        ],
        rationale="r",
    )
    ctx = _ctx(repo, [f_risk, f_catch, f_spec])

    m = metrics.build(
        ctx, manifest,
        repo_name="repo", start_ts="2026-01-01T00:00:00Z",
        end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )

    assert m.chunks_total == 3
    assert m.chunks_specialist == 1
    assert m.chunks_catchall == 1
    assert m.chunks_risk == 1
    # scope entries carry sorted files + classified kind
    kinds = {e.name: e.kind for e in m.scope}
    assert kinds == {
        "chunk-01": "risk",
        "catchall-1": "catchall",
        "chunk-spec": "specialist",
    }
    assert all(isinstance(e, ScopeEntry) for e in m.scope)


def test_build_specialist_takes_precedence_over_catchall_prefix(tmp_path):
    # A chunk whose id starts with "catchall-" but ALSO has specialist set
    # must be counted as specialist (specialist branch is first).
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x = 1\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="catchall-x", files=[f], specialist="logic-bug")],
        rationale="r",
    )
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_specialist == 1
    assert m.chunks_catchall == 0
    assert m.chunks_risk == 0
    assert m.scope[0].kind == "specialist"


# ─────────────────────────────────────────────────────────────────────────────
# build — analyzed-file coverage (only files that are also in ctx.all_files)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_analyzed_unique_intersects_scope(tmp_path):
    repo = tmp_path / "repo"
    a = _write(repo, "a.py", "x=1\n")
    b = _write(repo, "b.py", "y=2\n")
    # "ghost.py" is referenced by a chunk but NOT in all_files -> excluded.
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[a, b, "ghost.py"])],
        rationale="r",
    )
    ctx = _ctx(repo, [a, b])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.total_files_in_scope == 2
    # ghost.py is analyzed but not in scope -> not counted
    assert m.analyzed_files_unique == 2


def test_build_folders_scanned_includes_dot_and_dirs(tmp_path):
    repo = tmp_path / "repo"
    top = _write(repo, "top.py", "a=1\n")          # no slash -> not a folder
    nested = _write(repo, "pkg/sub/mod.py", "b=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[top, nested])],
        rationale="r",
    )
    ctx = _ctx(repo, [top, nested])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert "." in m.folders_scanned
    assert "pkg/sub" in m.folders_scanned
    # sorted output
    assert m.folders_scanned == sorted(m.folders_scanned)


# ─────────────────────────────────────────────────────────────────────────────
# build — LOC by language (in-scope vs scanned)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_loc_by_language_scope_vs_scanned(tmp_path):
    repo = tmp_path / "repo"
    # 2 python files, only one analyzed; 1 unknown-ext file -> "other"
    py_scanned = _write(repo, "scanned.py", "a\nb\nc\n")     # 3 loc
    py_unscanned = _write(repo, "skipped.py", "x\ny\n")      # 2 loc
    other = _write(repo, "data.unknownext", "k\n")           # 1 loc -> other

    manifest = TaskManifest(
        chunks=[Chunk(id="c1", files=[py_scanned])],
        rationale="r",
    )
    ctx = _ctx(repo, [py_scanned, py_unscanned, other])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.loc_in_scope_by_language["python"] == 5   # 3 + 2
    assert m.loc_scanned_by_language["python"] == 3     # only scanned.py
    assert m.loc_in_scope_by_language["other"] == 1
    # "other" not analyzed -> absent or zero in scanned map
    assert m.loc_scanned_by_language.get("other", 0) == 0


# ─────────────────────────────────────────────────────────────────────────────
# build — duration parsing (happy + malformed timestamps)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_duration_from_valid_timestamps(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:01:30Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.duration_sec == 90.0


def test_build_duration_zero_on_malformed_timestamp(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="not-a-timestamp", end_ts="also-bad",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.duration_sec == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# build — token accounting (available vs unavailable)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_tokens_unavailable_when_no_usage(tmp_path):
    # No TOKENS.add(dict) call -> calls_with_usage == 0 -> token fields None.
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.prompt_tokens is None
    assert m.completion_tokens is None
    assert m.total_tokens is None
    assert m.tokens_by_phase is None


def test_build_tokens_populated_from_usage(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f])

    # Record real usage on the global counter under a labelled phase.
    with TOKENS.phase("s4"):
        TOKENS.add({
            "input_tokens": 100,
            "cache_creation_input_tokens": 20,
            "cache_read_input_tokens": 5,
            "output_tokens": 40,
        })

    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    # prompt = fresh + cache-write = 100 + 20
    assert m.prompt_tokens == 120
    assert m.completion_tokens == 40
    assert m.total_tokens == 160
    assert m.tokens_by_phase is not None
    assert m.tokens_by_phase["s4"]["prompt"] == 120
    assert m.tokens_by_phase["s4"]["completion"] == 40
    assert m.tokens_by_phase["s4"]["cache_read"] == 5


# ─────────────────────────────────────────────────────────────────────────────
# build — identity / passthrough fields
# ─────────────────────────────────────────────────────────────────────────────
def test_build_scan_id_and_counts_and_excluded(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    excluded = {"dirs": {"vendor": 12}, "oversize": 3}
    ctx = _ctx(repo, [f], excluded=excluded)
    m = metrics.build(
        ctx, manifest, repo_name="acme-svc",
        start_ts="2026-03-04T05:06:07Z", end_ts="2026-03-04T05:06:08Z",
        raw_findings=10, true_pos=6, false_pos=3, duplicates=1,
    )
    assert m.scan_id == "2026-03-04T05:06:07Z__acme-svc"
    assert m.module_name == "acme-svc"
    assert m.raw_findings_count == 10
    assert m.true_positive_count == 6
    assert m.false_positive_count == 3
    assert m.duplicate_count == 1
    assert m.excluded == excluded


def test_build_excluded_none_coerced_to_empty_dict(tmp_path):
    # ctx.excluded falsy -> `ctx.excluded or {}` yields {}.
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="c1", files=[f])], rationale="r")
    ctx = _ctx(repo, [f], excluded={})
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.excluded == {}


def test_build_empty_manifest_no_chunks(tmp_path):
    repo = tmp_path / "repo"
    f = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[], rationale="r")
    ctx = _ctx(repo, [f])
    m = metrics.build(
        ctx, manifest, repo_name="r",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_total == 0
    assert m.chunks_risk == 0
    assert m.analyzed_files_unique == 0
    # No analyzed files -> folders is just "."
    assert m.folders_scanned == ["."]
    assert m.scope == []


# ─────────────────────────────────────────────────────────────────────────────
# build — chunk-outcome health tally (a failed/timed-out chunk must surface)
# ─────────────────────────────────────────────────────────────────────────────
def test_build_chunk_outcomes_tally_and_health_render(tmp_path):
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    fb = _write(repo, "b.py", "y=2\n")
    manifest = TaskManifest(
        chunks=[Chunk(id="chunk-01", files=[fa]),
                Chunk(id="chunk-02", files=[fb])],
        rationale="r")
    ctx = _ctx(repo, [fa, fb])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
        chunk_outcomes={"chunk-01": "completed", "chunk-02": "error"},
    )
    assert m.chunks_attempted == 2
    assert m.chunks_failed == 1
    # The degraded-coverage warning is surfaced in the rendered report.
    rep = FinalReport(repo_root=str(repo), findings=[], chains=[],
                      raw_findings_count=0, metrics=m, summary="s")
    md = rep.to_markdown()
    assert "## Scan Health" in md
    assert "1/2" in md and "failed or timed out" in md


def test_build_no_outcomes_reports_zero_failures(tmp_path):
    # A legacy --resume with no outcome data must not raise a false alarm.
    repo = tmp_path / "repo"
    fa = _write(repo, "a.py", "x=1\n")
    manifest = TaskManifest(chunks=[Chunk(id="chunk-01", files=[fa])], rationale="r")
    ctx = _ctx(repo, [fa])
    m = metrics.build(
        ctx, manifest, repo_name="repo",
        start_ts="2026-01-01T00:00:00Z", end_ts="2026-01-01T00:00:00Z",
        raw_findings=0, true_pos=0, false_pos=0, duplicates=0,
    )
    assert m.chunks_failed == 0


# ─────────────────────────────────────────────────────────────────────────────
# ScanMetrics derived properties (pure aggregations)
# ─────────────────────────────────────────────────────────────────────────────
def test_coverage_pct_normal():
    m = ScanMetrics(total_files_in_scope=4, analyzed_files_unique=1)
    assert m.coverage_pct == 25.0


def test_coverage_pct_zero_scope_guard():
    m = ScanMetrics(total_files_in_scope=0, analyzed_files_unique=0)
    assert m.coverage_pct == 0.0


def test_verification_precision_pct_normal():
    m = ScanMetrics(raw_findings_count=10, true_positive_count=7)
    assert m.verification_precision_pct == 70.0


def test_verification_precision_pct_zero_raw_guard():
    m = ScanMetrics(raw_findings_count=0, true_positive_count=0)
    assert m.verification_precision_pct == 0.0
