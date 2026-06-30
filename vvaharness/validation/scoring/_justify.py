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

"""Fix-path justification builder; tracker templates embed these phrasings — edit deliberately."""

from vvaharness.validation.constants.scoring import CONFIDENCE_PERCENT_SCALE, MAX_EVIDENCE_ANCHORS
from vvaharness.validation.enums.gates import GateStatus
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.models.scoring import RawCriterion, RawExtra, ScoreResult

_PASS_STATUSES = frozenset({GateStatus.PASS})
_FAIL_STATUSES = frozenset({GateStatus.FAIL, GateStatus.PARTIAL})


def _confidence(result: ScoreResult) -> int:
    """Return raw_score scaled to a 0-100 integer percentage."""
    return round(result.raw_score * CONFIDENCE_PERCENT_SCALE)


def _anchors_str(gates: list[RawCriterion]) -> str:
    """Return up to MAX_EVIDENCE_ANCHORS evidence anchors joined by '; '."""
    return "; ".join(_collect_evidence_anchors(gates)[:MAX_EVIDENCE_ANCHORS])


def _fixed_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    passing = "; ".join(g.summary for g in gates if GateStatus.parse(g.status) == GateStatus.PASS)
    return (
        f"Fix verified: {passing}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Evidence: {_anchors_str(gates)}."
    )


def _partial_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    passing = "; ".join(g.summary for g in gates if GateStatus.parse(g.status) in _PASS_STATUSES)
    gaps = "; ".join(g.summary for g in gates if GateStatus.parse(g.status) in _FAIL_STATUSES)
    files = _files_needing_fixes(gates)
    return (
        f"Partial fix: {passing}. "
        f"Gaps: {gaps}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Files needing fixes: {', '.join(files) if files else 'N/A'}."
    )


def _not_fixed_text(result: ScoreResult, gates: list[RawCriterion]) -> str:
    failed = "; ".join(g.summary for g in gates if GateStatus.parse(g.status) == GateStatus.FAIL)
    files = _files_needing_fixes(gates)
    actions = _recommended_actions(gates)
    return (
        f"Fix insufficient: {failed}. "
        f"Vulnerable pattern remains in {', '.join(files) if files else 'affected files'}. "
        f"Fix confidence: {_confidence(result)}%. "
        f"Recommended action: {'; '.join(actions)}."
    )


_VERDICT_FORMATTERS = {
    FixVerdict.FIXED.value: _fixed_text,
    FixVerdict.PARTIALLY_FIXED.value: _partial_text,
    FixVerdict.NOT_FIXED.value: _not_fixed_text,
}


def build_fix_justification(
    result: ScoreResult,
    gates: list[RawCriterion],
    _extra: RawExtra,
) -> str:
    """Build a tracker-comment justification string for the scored fix verdict."""
    if result.verdict_label == FixVerdict.UNVERIFIABLE:
        return result.justification or ""
    formatter = _VERDICT_FORMATTERS.get(result.verdict_label, _not_fixed_text)
    return formatter(result, gates)


def _collect_evidence_anchors(criteria: list[RawCriterion]) -> list[str]:
    anchors: list[str] = []
    for c in criteria:
        for e in c.evidence:
            loc = f"{e.file}:{e.line}" if e.line is not None else e.file
            anchors.append(loc)
    return anchors


def _files_needing_fixes(criteria: list[RawCriterion]) -> list[str]:
    files: set[str] = set()
    for c in criteria:
        if GateStatus.parse(c.status) in _FAIL_STATUSES:
            for e in c.evidence:
                files.add(e.file)
    return sorted(f for f in files if f)


def _recommended_actions(gates: list[RawCriterion]) -> list[str]:
    actions = [
        f"Address {g.name}: {g.summary}"
        for g in gates if GateStatus.parse(g.status) == GateStatus.FAIL
    ]
    return actions if actions else ["Review all failing gates and apply fixes"]
