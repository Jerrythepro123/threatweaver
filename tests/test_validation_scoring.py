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

"""Characterization tests for the pure validation scoring logic.

Locks down exact outputs for the scoring engine, justifier, and __main__
normalizers so later refactors can prove behavioral equivalence.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest
from vvaharness.validation.enums.gates import GateName, GateStatus
from vvaharness.validation.scoring.__main__ import (
    _normalize_input,
    _normalize_list,
    _normalize_mapping,
)
from vvaharness.validation.scoring._engine import (
    RawCriterion,
    RawEvidence,
    ScoreResult,
    ScoringConfig,
    VerdictRule,
    _apply_verdicts,
    parse_raw_criterion,
    score,
)
from vvaharness.validation.scoring._justify import build_fix_justification

# ---------------------------------------------------------------------------
# Fixtures / shared config
# ---------------------------------------------------------------------------

_WEIGHTS = {
    "root_cause": 0.43,
    "instance_coverage": 0.2467,
    "no_new_vulnerabilities": 0.1867,
    "security_best_practices": 0.1366,
}
_MULTIPLIER = {"pass": 1.0, "partial": 0.5, "fail": 0.0, "skip": 0.0}
_VERDICTS = (
    VerdictRule(min_score=0.80, label="Fixed"),
    VerdictRule(min_score=0.50, label="Partially Fixed"),
    VerdictRule(min_score=0.0, label="Not Fixed"),
)

_CFG = ScoringConfig(
    name="fix",
    criterion_name_field="gate_name",
    expected_criteria=frozenset(_WEIGHTS.keys()),
    weights=_WEIGHTS,
    status_multiplier=_MULTIPLIER,
    verdicts=_VERDICTS,
    unverifiable_label="UNVERIFIABLE",
    justify=build_fix_justification,
)

# Same as _CFG, but with no_new_vulnerabilities pinned as a non-skippable critical gate
# (mirrors the shipped FIX_CONFIG) so the fail-closed critical-gate paths are exercised.
_CRIT_CFG = ScoringConfig(
    name="fix",
    criterion_name_field="gate_name",
    expected_criteria=frozenset(_WEIGHTS.keys()),
    weights=_WEIGHTS,
    status_multiplier=_MULTIPLIER,
    verdicts=_VERDICTS,
    unverifiable_label="UNVERIFIABLE",
    justify=build_fix_justification,
    critical_criteria=frozenset({"no_new_vulnerabilities"}),
)

_ALL_PASS = [
    RawCriterion(name="root_cause", status="pass", summary="Root cause addressed"),
    RawCriterion(name="instance_coverage", status="pass", summary="All instances covered"),
    RawCriterion(name="no_new_vulnerabilities", status="pass", summary="No new vulns"),
    RawCriterion(name="security_best_practices", status="pass", summary="Best practices met"),
]

_ALL_FAIL = [
    RawCriterion(name="root_cause", status="fail", summary="Root cause not fixed"),
    RawCriterion(name="instance_coverage", status="fail", summary="Instances missed"),
    RawCriterion(name="no_new_vulnerabilities", status="fail", summary="New vulns introduced"),
    RawCriterion(name="security_best_practices", status="fail", summary="Best practices ignored"),
]

_PARTIAL = [
    RawCriterion(name="root_cause", status="pass", summary="Root cause addressed"),
    RawCriterion(name="instance_coverage", status="partial", summary="Some instances covered"),
    RawCriterion(name="no_new_vulnerabilities", status="pass", summary="No new vulns"),
    RawCriterion(name="security_best_practices", status="fail", summary="Practices missing"),
]


# ---------------------------------------------------------------------------
# parse_raw_criterion
# ---------------------------------------------------------------------------

class TestParseRawCriterion:
    def test_full_entry(self) -> None:
        entry = {
            "gate_name": "root_cause",
            "status": "pass",
            "summary": "Fixed",
            "details": "detail text",
            "evidence": [{"file": "a.py", "line": 10, "snippet": "code"}],
        }
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.name == "root_cause"
        assert rc.status == "pass"
        assert rc.summary == "Fixed"
        assert rc.details == "detail text"
        assert len(rc.evidence) == 1
        assert rc.evidence[0] == RawEvidence(file="a.py", line=10, snippet="code")

    def test_missing_fields_default_to_empty(self) -> None:
        rc = parse_raw_criterion({"gate_name": "x"}, "gate_name")
        # An absent status is out-of-vocabulary, so it canonicalizes to "invalid"
        # (scored 0.0, kept in the denominator) rather than a droppable "skip";
        # summary/evidence still default to empty.
        assert rc.status == "invalid"
        assert rc.summary == ""
        assert rc.evidence == ()

    def test_evidence_ignores_non_mappings(self) -> None:
        entry = {"gate_name": "x", "status": "pass", "evidence": ["not a dict", 42]}
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.evidence == ()

    def test_bool_line_value_becomes_none(self) -> None:
        entry = {"gate_name": "x", "evidence": [{"file": "f.py", "line": True}]}
        rc = parse_raw_criterion(entry, "gate_name")
        assert rc.evidence[0].line is None


# ---------------------------------------------------------------------------
# _apply_verdicts
# ---------------------------------------------------------------------------

class TestApplyVerdicts:
    def test_above_fixed_threshold(self) -> None:
        assert _apply_verdicts(_CFG, 1.0) == "Fixed"
        assert _apply_verdicts(_CFG, 0.80) == "Fixed"

    def test_partial_range(self) -> None:
        assert _apply_verdicts(_CFG, 0.79) == "Partially Fixed"
        assert _apply_verdicts(_CFG, 0.50) == "Partially Fixed"

    def test_below_partial_threshold(self) -> None:
        assert _apply_verdicts(_CFG, 0.49) == "Not Fixed"
        assert _apply_verdicts(_CFG, 0.0) == "Not Fixed"


# ---------------------------------------------------------------------------
# score
# ---------------------------------------------------------------------------

class TestScore:
    def test_all_pass_is_fixed(self) -> None:
        result = score(_CFG, _ALL_PASS)
        assert result.verdict_label == "Fixed"
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)

    def test_all_fail_is_not_fixed(self) -> None:
        result = score(_CFG, _ALL_FAIL)
        assert result.verdict_label == "Not Fixed"
        assert result.raw_score == 0.0

    def test_partial_gates_produce_fractional_score(self) -> None:
        result = score(_CFG, _PARTIAL)
        expected = round(
            0.43 * 1.0 + 0.2467 * 0.5 + 0.1867 * 1.0 + 0.1366 * 0.0, 4
        )
        assert result.raw_score == pytest.approx(expected, abs=1e-4)


# ---------------------------------------------------------------------------
# SKIP earns no credit; raw_score clamped to <= 1.0
# ---------------------------------------------------------------------------

class TestSkipAndClamp:
    def test_skip_gate_is_weight_neutral(self) -> None:
        # A skipped gate is unevaluated — dropped from the denominator, never a
        # failure. Two passes + two skips renormalize to a perfect, Fixed score.
        skipped = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="skip", summary="not evaluated"),
            RawCriterion(name="no_new_vulnerabilities", status="skip", summary="not evaluated"),
            RawCriterion(name="security_best_practices", status="pass", summary="ok"),
        ]
        result = score(_CFG, skipped)
        # active weight 0.43 + 0.1366 = 0.5666 >= floor; both pass → 1.0 / Fixed.
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)
        assert result.verdict_label == "Fixed"

    def test_production_config_treats_skip_as_zero(self) -> None:
        from vvaharness.validation.scoring import score_fix
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "fail"},
            {"gate_name": "instance_coverage", "status": "skip"},
            {"gate_name": "no_new_vulnerabilities", "status": "skip"},
            {"gate_name": "security_best_practices", "status": "skip"},
        ]
        # all non-failing gates are skipped → 0.0, well under "Partially Fixed".
        assert score_fix(gates).raw_score == pytest.approx(0.0, abs=1e-4)

    def test_raw_score_clamped_to_one(self) -> None:
        # A weights-misconfig that sums > 1.0 must not produce a score above 1.0.
        inflated = ScoringConfig(
            name="fix",
            criterion_name_field="gate_name",
            expected_criteria=frozenset({"a", "b"}),
            weights={"a": 0.8, "b": 0.8},
            status_multiplier={"pass": 1.0, "partial": 0.5, "fail": 0.0, "skip": 0.0},
            verdicts=_VERDICTS,
            unverifiable_label="UNVERIFIABLE",
            justify=build_fix_justification,
        )
        result = score(inflated, [
            RawCriterion(name="a", status="pass", summary="x"),
            RawCriterion(name="b", status="pass", summary="y"),
        ])
        assert result.raw_score == 1.0

    def test_missing_criteria_returns_unverifiable(self) -> None:
        incomplete = [RawCriterion(name="root_cause", status="pass")]
        result = score(_CFG, incomplete)
        assert result.verdict_label == "UNVERIFIABLE"
        assert result.raw_score == 0.0
        assert "Missing criterion" in result.justification

    def test_duplicate_criterion_returns_unverifiable(self) -> None:
        dup = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="fail"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CFG, dup)
        assert result.verdict_label == "UNVERIFIABLE"
        assert result.raw_score == 0.0
        assert "Duplicate criterion" in result.justification
        assert "root_cause" in result.justification

    def test_justification_is_populated(self) -> None:
        result = score(_CFG, _ALL_PASS)
        assert result.justification != ""

    def test_extra_none_is_treated_as_empty(self) -> None:
        result = score(_CFG, _ALL_PASS, extra=None)
        assert result.verdict_label == "Fixed"


# ---------------------------------------------------------------------------
# renormalization: skip is weight-neutral; a coverage floor guards thin verdicts
# ---------------------------------------------------------------------------

class TestRenormalization:
    def test_cross_repo_two_skips_still_fixed(self) -> None:
        # Cross-repo persona by design skips no_new_vulnerabilities +
        # security_best_practices; the two passing gates (active 0.6767 >= floor)
        # renormalize to a clean Fixed instead of being deflated by the skips.
        gates = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="pass", summary="ok"),
            RawCriterion(name="no_new_vulnerabilities", status="skip", summary="n/a"),
            RawCriterion(name="security_best_practices", status="skip", summary="n/a"),
        ]
        result = score(_CFG, gates)
        assert result.raw_score == pytest.approx(1.0, abs=1e-4)
        assert result.verdict_label == "Fixed"

    def test_single_gate_below_floor_is_unverifiable(self) -> None:
        # Only root_cause evaluated (active 0.43 < 0.50 floor) → too little coverage.
        gates = [
            RawCriterion(name="root_cause", status="pass", summary="ok"),
            RawCriterion(name="instance_coverage", status="skip"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="skip"),
        ]
        result = score(_CFG, gates)
        assert result.verdict_label == "UNVERIFIABLE"
        assert result.raw_score == 0.0
        assert "insufficient gate coverage" in result.justification

    def test_all_skip_is_unverifiable_no_zero_division(self) -> None:
        # Active weight 0.0 must short-circuit to UNVERIFIABLE, never ZeroDivisionError.
        gates = [
            RawCriterion(name="root_cause", status="skip"),
            RawCriterion(name="instance_coverage", status="skip"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="skip"),
        ]
        result = score(_CFG, gates)
        assert result.verdict_label == "UNVERIFIABLE"
        assert result.raw_score == 0.0

    def test_no_skip_cases_unchanged(self) -> None:
        # Regression: with no skips active_weight == 1.0, so renormalization is a no-op.
        assert score(_CFG, _ALL_PASS).raw_score == pytest.approx(1.0, abs=1e-4)
        expected = round(0.43 * 1.0 + 0.2467 * 0.5 + 0.1867 * 1.0 + 0.1366 * 0.0, 4)
        assert score(_CFG, _PARTIAL).raw_score == pytest.approx(expected, abs=1e-4)


# ---------------------------------------------------------------------------
# critical gate: no_new_vulnerabilities cannot be skipped, garbled, or waived
# ---------------------------------------------------------------------------

class TestCriticalGate:
    def test_critical_skip_is_unverifiable(self) -> None:
        # A skipped critical gate cannot be dropped to inflate the score — fail closed.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="skip"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.verdict_label == "UNVERIFIABLE"
        assert result.raw_score == 0.0

    def test_critical_invalid_is_unverifiable(self) -> None:
        # A garbled critical status canonicalizes to INVALID, which also fails closed.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="invalid"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.verdict_label == "UNVERIFIABLE"

    def test_critical_fail_caps_below_fixed(self) -> None:
        # nnv fails but the other gates pass: raw_score 0.8133 would clear the Fixed
        # threshold, yet a failed critical gate caps the verdict at Partially Fixed.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="fail"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.raw_score == pytest.approx(0.8133, abs=1e-4)
        assert result.verdict_label == "Partially Fixed"

    def test_critical_partial_caps_below_fixed(self) -> None:
        # nnv=partial earns half credit, so the other three passes leave raw_score 0.9066
        # (above the Fixed threshold) — yet a not-clean critical gate still caps to Partially
        # Fixed. partial scores higher than fail (0.8133) but must not out-weight the gate.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="partial"),
            RawCriterion(name="security_best_practices", status="pass"),
        ]
        result = score(_CRIT_CFG, gates)
        assert result.raw_score == pytest.approx(0.9066, abs=1e-4)
        assert result.verdict_label == "Partially Fixed"

    def test_non_critical_invalid_stays_in_denominator(self) -> None:
        # A garbled NON-critical gate is INVALID (scored 0.0, kept in the denominator),
        # so it drags the score down rather than vanishing.
        gates = [
            RawCriterion(name="root_cause", status="pass"),
            RawCriterion(name="instance_coverage", status="pass"),
            RawCriterion(name="no_new_vulnerabilities", status="pass"),
            RawCriterion(name="security_best_practices", status="invalid"),
        ]
        result = score(_CRIT_CFG, gates)
        # 1.0 - 0.1366 weight earns 0.0 → 0.8634, still Fixed but not a perfect 1.0.
        assert result.raw_score == pytest.approx(0.8634, abs=1e-4)

    @pytest.mark.parametrize("nnv,expected", [("fail", True), ("partial", True), ("pass", False)])
    def test_score_fix_sets_has_critical_failure(self, nnv: str, expected: bool) -> None:
        # has_critical_failure tracks a not-clean critical gate (fail OR partial), not just fail.
        from vvaharness.validation.scoring import score_fix
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "pass"},
            {"gate_name": "instance_coverage", "status": "pass"},
            {"gate_name": "no_new_vulnerabilities", "status": nnv},
            {"gate_name": "security_best_practices", "status": "pass"},
        ]
        assert score_fix(gates).has_critical_failure is expected


# ---------------------------------------------------------------------------
# GateStatus.parse: tolerant status coercion
# ---------------------------------------------------------------------------

class TestGateStatusParse:
    def test_canonical_values(self) -> None:
        assert GateStatus.parse("pass") is GateStatus.PASS
        assert GateStatus.parse("skip") is GateStatus.SKIP

    def test_case_and_whitespace_variants(self) -> None:
        assert GateStatus.parse("PASS") is GateStatus.PASS
        assert GateStatus.parse(" Pass ") is GateStatus.PASS

    def test_unknown_token_is_invalid(self) -> None:
        # Out-of-vocabulary tokens fail closed to INVALID (scored 0.0), never SKIP,
        # so a garbled status can't be silently dropped from the denominator.
        assert GateStatus.parse("verified") is GateStatus.INVALID

    def test_non_string_is_invalid(self) -> None:
        assert GateStatus.parse(None) is GateStatus.INVALID
        assert GateStatus.parse(42) is GateStatus.INVALID

    def test_score_fix_tolerates_unknown_status(self) -> None:
        # An out-of-vocabulary status must not raise; it coerces to INVALID
        # (scored 0.0, kept in the denominator) and a full GateResult set is still built.
        from vvaharness.validation.scoring import score_fix
        gates: list[Mapping[str, object]] = [
            {"gate_name": "root_cause", "status": "totally-bogus"},
            {"gate_name": "instance_coverage", "status": "pass"},
            {"gate_name": "no_new_vulnerabilities", "status": "pass"},
            {"gate_name": "security_best_practices", "status": "pass"},
        ]
        result = score_fix(gates)
        assert len(result.gate_results) == len(gates)
        root = next(g for g in result.gate_results if g.gate is GateName.ROOT_CAUSE)
        assert root.status is GateStatus.INVALID


# ---------------------------------------------------------------------------
# build_fix_justification
# ---------------------------------------------------------------------------

class TestBuildFixJustification:
    def _partial_result(self, label: str, score_val: float = 0.65) -> ScoreResult:
        return ScoreResult(raw_score=score_val, verdict_label=label, justification="")

    def test_unverifiable_returns_existing_justification(self) -> None:
        r = ScoreResult(raw_score=0.0, verdict_label="UNVERIFIABLE", justification="pre-set")
        assert build_fix_justification(r, [], {}) == "pre-set"

    def test_unverifiable_empty_justification_returns_empty(self) -> None:
        r = ScoreResult(raw_score=0.0, verdict_label="UNVERIFIABLE", justification="")
        assert build_fix_justification(r, [], {}) == ""

    def test_fixed_contains_confidence_and_pass_gates(self) -> None:
        r = self._partial_result("Fixed", 0.86)
        text = build_fix_justification(r, _ALL_PASS, {})
        assert "Fix verified:" in text
        assert "86%" in text
        assert "Evidence:" in text

    def test_partially_fixed_contains_gaps(self) -> None:
        r = self._partial_result("Partially Fixed", 0.65)
        text = build_fix_justification(r, _PARTIAL, {})
        assert "Partial fix:" in text
        assert "Gaps:" in text
        assert "65%" in text

    def test_not_fixed_contains_failed_gates(self) -> None:
        r = self._partial_result("Not Fixed", 0.0)
        text = build_fix_justification(r, _ALL_FAIL, {})
        assert "Fix insufficient:" in text
        assert "Recommended action:" in text

    def test_evidence_anchors_appear_in_fixed_text(self) -> None:
        gates = [
            RawCriterion(
                name="root_cause",
                status="pass",
                summary="ok",
                evidence=(RawEvidence(file="a.py", line=5, snippet=""),),
            ),
            *_ALL_PASS[1:],
        ]
        r = ScoreResult(raw_score=1.0, verdict_label="Fixed", justification="")
        text = build_fix_justification(r, gates, {})
        assert "a.py:5" in text


# ---------------------------------------------------------------------------
# _normalize_* (scoring/__main__.py)
# ---------------------------------------------------------------------------

_GATE = {"gate_name": "root_cause", "status": "pass"}
_FINDING = {"tracking_id": "abc", "gates": [_GATE]}

class TestNormalizeMapping:
    def test_findings_shape(self) -> None:
        data = {"findings": [_FINDING]}
        result = _normalize_mapping(data)
        assert result == [_FINDING]

    def test_single_finding_with_gates(self) -> None:
        result = _normalize_mapping(_FINDING)
        assert result == [_FINDING]

    def test_unknown_shape_returns_none(self) -> None:
        assert _normalize_mapping({"foo": "bar"}) is None


class TestNormalizeList:
    def test_bare_list_of_gates(self) -> None:
        result = _normalize_list([_GATE])
        assert len(result) == 1
        assert result[0]["gates"] == [_GATE]
        assert result[0]["tracking_id"] == ""

    def test_list_of_findings(self) -> None:
        result = _normalize_list([_FINDING])
        assert result == [_FINDING]

    def test_empty_list(self) -> None:
        assert _normalize_list([]) == []


class TestNormalizeInput:
    def test_findings_mapping(self) -> None:
        result = _normalize_input({"findings": [_FINDING]})
        assert result == [_FINDING]

    def test_single_gate_list(self) -> None:
        result = _normalize_input([_GATE])
        assert result[0]["gates"] == [_GATE]

    def test_raises_on_unknown_shape(self) -> None:
        with pytest.raises(ValueError, match="Unrecognized"):
            _normalize_input({"foo": "bar"})

    def test_raises_on_scalar(self) -> None:
        with pytest.raises(ValueError):
            _normalize_input("not valid")  # type: ignore[arg-type]
