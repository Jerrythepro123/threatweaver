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

"""Tests for result collection (validation_report.json -> ValidationResult) and
the verdict/effort enum parsers."""
import json
import logging
from collections.abc import Mapping
from pathlib import Path

import pytest
from vvaharness.validation.constants.artifacts import (
    MANIFEST_FILENAME,
    SYNTHESIZED_GATES_FILENAME,
    VALIDATION_REPORT_FILENAME,
)
from vvaharness.validation.enums import EffortLevel
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import Answer, FixVerdict
from vvaharness.validation.io.result_collector import collect_and_enrich, collect_results
from vvaharness.validation.models import FixFindingReport
from vvaharness.validation.scoring import score_fix


def _write_gates(ws: Path, tracking_id: str, gates: list[Mapping[str, object]]) -> None:
    (ws / SYNTHESIZED_GATES_FILENAME).write_text(
        json.dumps([{"tracking_id": tracking_id, "gates": gates}])
    )


_ALL_PASS: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "pass"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "pass"},
    {"gate_name": "security_best_practices", "status": "pass"},
]
_ROOT_FAIL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "fail"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "pass"},
    {"gate_name": "security_best_practices", "status": "pass"},
]
# root_cause + instance_coverage pass (0.43 + 0.2467) → score in [0.50, 0.80) → Partially Fixed.
_PARTIAL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "pass"},
    {"gate_name": "instance_coverage", "status": "pass"},
    {"gate_name": "no_new_vulnerabilities", "status": "fail"},
    {"gate_name": "security_best_practices", "status": "fail"},
]
# Every gate fails: full coverage, score 0.0 → Not Fixed (not UNVERIFIABLE).
_ALL_FAIL: list[Mapping[str, object]] = [
    {"gate_name": "root_cause", "status": "fail"},
    {"gate_name": "instance_coverage", "status": "fail"},
    {"gate_name": "no_new_vulnerabilities", "status": "fail"},
    {"gate_name": "security_best_practices", "status": "fail"},
]


def _write_report(ws: Path, findings: list[dict]) -> None:
    (ws / VALIDATION_REPORT_FILENAME).write_text(json.dumps({"findings": findings}))


# ---------------------------------------------------------------------------
# collect_results — fix_status -> tri-state Answer mapping
# ---------------------------------------------------------------------------


def test_collect_maps_fixed(tmp_path: Path) -> None:
    # All gates pass → host verdict FIXED → tri-state fixed=Yes (host number, not the agent's).
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.91}])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (r,) = collect_results(tmp_path)
    # fields are str-typed; pydantic coerces the Answer StrEnum to its value, so compare with ==
    assert r.fixed == Answer.YES
    assert r.not_fixed == Answer.NO
    assert r.fix_confidence == score_fix(_ALL_PASS).raw_score
    assert FixVerdict.FIXED.value in r.reason_for_decision


def test_collect_maps_partial_and_not_fixed(tmp_path: Path) -> None:
    # Host verdicts drive the tri-state mapping: partial-coverage pass → Partially Fixed,
    # all-fail → Not Fixed.
    _write_report(tmp_path, [
        {"tracking_id": "F-1", "fix_status": "Partially Fixed", "raw_score": 0.6},
        {"tracking_id": "F-2", "fix_status": "Not Fixed", "raw_score": 0.2},
    ])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(json.dumps([
        {"tracking_id": "F-1", "gates": _PARTIAL},
        {"tracking_id": "F-2", "gates": _ALL_FAIL},
    ]))
    a, b = collect_results(tmp_path)
    assert a.partially_fixed == Answer.YES and a.fixed == Answer.NO
    assert b.not_fixed == Answer.YES and b.fixed == Answer.NO


def test_collect_numbers_findings_from_start(tmp_path: Path) -> None:
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed"}])
    (r,) = collect_results(tmp_path, finding_number_start=5)
    assert r.finding_number == 5


def test_collect_missing_report_returns_empty(tmp_path: Path) -> None:
    assert collect_results(tmp_path) == []


def test_collect_invalid_json_returns_empty(tmp_path: Path) -> None:
    (tmp_path / VALIDATION_REPORT_FILENAME).write_text("{ not json")
    assert collect_results(tmp_path) == []


# ---------------------------------------------------------------------------
# collect_and_enrich — blank fields backfilled from manifest.json
# ---------------------------------------------------------------------------


def test_enrich_fills_blank_fields_from_manifest(tmp_path: Path) -> None:
    _write_report(tmp_path, [{"tracking_id": "", "fix_status": "Fixed", "finding_title": ""}])
    (tmp_path / MANIFEST_FILENAME).write_text(json.dumps({
        "jira_key": "JIRA-9",
        "finding_ids": ["JIRA-9"],
        "finding": {
            "tracking_id": "JIRA-9", "title": "SQLi", "category": "CWE-89",
            "severity": "High", "affected_files": ["app/db.py"],
        },
    }))
    (r,) = collect_and_enrich(tmp_path)
    assert r.finding_title == "SQLi"           # backfilled
    assert r.tracking_id == "JIRA-9"           # backfilled from blank
    assert "app/db.py" in r.affected_files


def test_enrich_without_manifest_returns_results(tmp_path: Path) -> None:
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "finding_title": "T"}])
    (r,) = collect_and_enrich(tmp_path)
    assert r.finding_title == "T"


# ---------------------------------------------------------------------------
# host-side scoring — the host recomputes the verdict from synthesized_gates.json
# deterministically, overriding the agent's self-reported number
# ---------------------------------------------------------------------------


def test_host_score_overrides_inflated_agent_number(tmp_path: Path) -> None:
    # Agent claims Fixed/0.99, but root_cause actually FAILED → host caps it at Partially.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.99}])
    _write_gates(tmp_path, "F-1", _ROOT_FAIL)
    (r,) = collect_results(tmp_path)
    expected = score_fix(_ROOT_FAIL)
    assert r.fix_confidence == expected.raw_score          # host number, not 0.99
    assert r.fix_confidence != 0.99
    assert r.fixed == Answer.NO                            # root_cause fail caps below Fixed
    assert expected.fix_status in r.reason_for_decision


def test_host_score_matches_engine_exactly(tmp_path: Path) -> None:
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Not Fixed", "raw_score": 0.0}])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (r,) = collect_results(tmp_path)
    assert r.fix_confidence == score_fix(_ALL_PASS).raw_score   # exact, deterministic
    assert r.fixed == Answer.YES


def test_no_synthesized_gates_fails_closed(tmp_path: Path) -> None:
    # No synthesized_gates.json → host can't recompute → fail closed to UNVERIFIABLE,
    # never the agent's self-reported Fixed/0.88.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.88}])
    (r,) = collect_results(tmp_path)
    assert r.fix_confidence == 0.0
    assert r.fixed == Answer.NO
    assert FixVerdict.UNVERIFIABLE.value in r.reason_for_decision


def test_malformed_gates_non_list_fails_closed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # A present-but-non-array synthesized_gates.json fails closed and warns; the agent's
    # self-reported Fixed is never trusted.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.95}])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(json.dumps({"not": "a list"}))
    with caplog.at_level(logging.WARNING):
        (r,) = collect_results(tmp_path)
    assert r.fix_confidence == 0.0
    assert r.fixed == Answer.NO
    assert any("not a JSON array" in m for m in caplog.messages)


def test_malformed_gates_bad_entry_dropped_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # An entry whose "gates" is not a list is dropped; with no usable gates left the host
    # fails closed and logs the drop.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.95}])
    (tmp_path / SYNTHESIZED_GATES_FILENAME).write_text(
        json.dumps([{"tracking_id": "F-1", "gates": "not-a-list"}])
    )
    with caplog.at_level(logging.WARNING):
        (r,) = collect_results(tmp_path)
    assert r.fix_confidence == 0.0
    assert r.fixed == Answer.NO
    assert any("dropped" in m for m in caplog.messages)


def test_host_score_for_foreign_id_returns_none() -> None:
    # The only synthesized entry is for a DIFFERENT finding; scoring "F-1" must not
    # borrow F-OTHER's gates — it returns None so the caller fails closed.
    from vvaharness.validation.io._host_score import host_score_for
    assert host_score_for("F-1", {"F-OTHER": _ALL_PASS}) is None


def test_foreign_only_gates_fail_closed(tmp_path: Path) -> None:
    # synthesized_gates.json holds only a foreign finding's all-pass gates; the report's
    # F-1 must fail closed to UNVERIFIABLE, never inherit F-OTHER's Fixed verdict.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 0.97}])
    _write_gates(tmp_path, "F-OTHER", _ALL_PASS)
    (r,) = collect_results(tmp_path)
    assert r.fix_confidence == 0.0
    assert r.fixed == Answer.NO
    assert FixVerdict.UNVERIFIABLE.value in r.reason_for_decision


# ---------------------------------------------------------------------------
# FixFindingReport model-boundary defenses — bound the agent-reported numbers
# ---------------------------------------------------------------------------


def test_report_clamps_raw_score_above_one() -> None:
    assert FixFindingReport(raw_score=1.7).raw_score == 1.0


def test_report_clamps_raw_score_below_zero() -> None:
    assert FixFindingReport(raw_score=-0.5).raw_score == 0.0


def test_report_coerces_unknown_merge_readiness() -> None:
    report = FixFindingReport(merge_readiness="bogus")
    assert report.merge_readiness == MergeReadiness.NOT_READY.value


def test_report_redacts_secret_in_narrative() -> None:
    # Agent free-text is redacted at parse; identifiers (title) stay intact for heading matching.
    ff = FixFindingReport.model_validate({
        "finding_title": "Hardcoded AKIAIOSFODNN7EXAMPLE",
        "justification": "the fix still exposes AKIAIOSFODNN7EXAMPLE",
        "recommendations": ["rotate AKIAIOSFODNN7EXAMPLE"],
    })
    assert "[REDACTED-AWS-KEY]" in ff.justification
    assert "AKIAIOSFODNN7EXAMPLE" not in ff.justification
    assert ff.recommendations == ["rotate [REDACTED-AWS-KEY]"]
    assert ff.finding_title == "Hardcoded AKIAIOSFODNN7EXAMPLE"  # identifier untouched


def test_collect_redacts_secret_in_justification(tmp_path: Path) -> None:
    # End-to-end: a secret in the agent justification is masked in the ValidationResult the
    # combined report is rendered from — including the derived reason_for_decision.
    _write_report(tmp_path, [{"tracking_id": "F-1", "fix_status": "Fixed", "raw_score": 1.0,
                              "justification": "still leaks AKIAIOSFODNN7EXAMPLE"}])
    _write_gates(tmp_path, "F-1", _ALL_PASS)
    (r,) = collect_results(tmp_path)
    assert "[REDACTED-AWS-KEY]" in r.justification
    assert "AKIAIOSFODNN7EXAMPLE" not in r.justification
    assert "AKIAIOSFODNN7EXAMPLE" not in r.reason_for_decision


# ---------------------------------------------------------------------------
# enum parsers
# ---------------------------------------------------------------------------


def test_fixverdict_parse() -> None:
    assert FixVerdict.parse("Fixed") is FixVerdict.FIXED
    assert FixVerdict.parse("Partially Fixed") is FixVerdict.PARTIALLY_FIXED
    assert FixVerdict.parse("garbage") is FixVerdict.UNVERIFIABLE   # default


def test_effortlevel_parse() -> None:
    assert EffortLevel.parse("high") is EffortLevel.HIGH
    assert EffortLevel.parse("XHIGH".lower()) is EffortLevel.XHIGH
    assert EffortLevel.parse(None) is None
    assert EffortLevel.parse("bogus") is None
