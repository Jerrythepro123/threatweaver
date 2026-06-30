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

"""CLI entry: score fix-path gate JSON and emit the result_collector wire shape."""

import json
import sys
from collections.abc import Mapping
from pathlib import Path

from vvaharness.validation.constants.scoring import (
    CRITERION_NAME_FIELD,
    SCORE_FLOOR,
    SCORE_PRECISION,
)
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.models.scoring import ScoredGateEntry, ScoringConfig, ValidationScore

from . import derive_merge_readiness, score_fix
from ._configs import FIX_CONFIG


def _list_of_mappings(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _str_from(entry: Mapping[str, object], key: str, default: str = "") -> str:
    value = entry.get(key, default)
    return value if isinstance(value, str) else default


def _read_file_input(path: str) -> str | None:
    """Return file contents, or None (with stderr error) if not found."""
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        print(json.dumps({"error": f"File not found: {path}"}), file=sys.stderr)
        return None


def _read_raw_input() -> str | None:
    """Return raw JSON text from argv path or stdin, or None on failure."""
    if len(sys.argv) > 1:
        return _read_file_input(sys.argv[1])
    if not sys.stdin.isatty():
        return sys.stdin.read()
    print(
        "Usage: python3 -m scoring <gates.json>  or  cat gates.json | python3 -m scoring",
        file=sys.stderr,
    )
    return None


def _normalize_or_error(data: object) -> list[Mapping[str, object]] | None:
    """Normalize parsed JSON; print error and return None on ValueError."""
    try:
        return _normalize_input(data)
    except ValueError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return None


def _parse_input(raw: str) -> list[Mapping[str, object]] | None:
    """Parse and normalize JSON input, returning None (with stderr error) on failure."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {e}"}), file=sys.stderr)
        return None
    return _normalize_or_error(data)


def main() -> int:
    """Entry point: parse input, score all findings, emit JSON to stdout."""
    raw = _read_raw_input()
    if raw is None:
        return 1
    findings_input = _parse_input(raw)
    if findings_input is None:
        return 1
    output = {"findings": [_score_fix_finding(f) for f in findings_input]}
    print(json.dumps(output, indent=2))
    return 0


def _score_fix_finding(finding: Mapping[str, object]) -> dict[str, object]:
    gates = _list_of_mappings(finding.get("gates", []))
    tracking_id = _str_from(finding, "tracking_id")
    score = score_fix(gates)
    base: dict[str, object] = {
        "tracking_id": tracking_id,
        "fix_status": score.fix_status.value,
        "raw_score": round(score.raw_score, SCORE_PRECISION),
        "justification": score.justification,
        "merge_readiness": _merge_readiness_str(score.fix_status),
        "has_critical_failure": False,
        "gate_scores": _gate_scores_dict(gates, FIX_CONFIG),
    }
    if score.fix_status == FixVerdict.UNVERIFIABLE:
        base["raw_score"] = SCORE_FLOOR
        base["gate_scores"] = {}
    return base


def _gate_scores_dict(
    raw: list[Mapping[str, object]],
    cfg: ScoringConfig,
) -> dict[str, ScoredGateEntry]:
    result: dict[str, ScoredGateEntry] = {}
    for c in raw:
        name = _str_from(c, cfg.criterion_name_field)
        status = _str_from(c, "status")
        weight = cfg.weights.get(name, SCORE_FLOOR)
        multiplier = cfg.status_multiplier.get(status, SCORE_FLOOR)
        result[name] = {
            "status": status,
            "weight": weight,
            "weighted_score": round(weight * multiplier, SCORE_PRECISION),
        }
    return result


def _merge_readiness_str(fix_status: FixVerdict) -> str:
    """Return the MergeReadiness string value for a given FixVerdict."""
    dummy = ValidationScore(
        raw_score=0.0,
        fix_status=fix_status,
        justification="",
        gate_results=[],
        has_critical_failure=False,
    )
    return derive_merge_readiness(dummy).value


def _normalize_mapping(data: Mapping[str, object]) -> list[Mapping[str, object]] | None:
    """Normalize a tagged or flat mapping; return None if neither shape matches."""
    if "findings" in data and isinstance(data["findings"], list):
        return _list_of_mappings(data["findings"])
    if "gates" in data and isinstance(data["gates"], list):
        return [data]
    return None


def _normalize_list(data: list[object]) -> list[Mapping[str, object]]:
    """Normalize a bare list of gates or findings into a uniform list of findings."""
    items = _list_of_mappings(data)
    if not items:
        return []
    first = items[0]
    wrap = CRITERION_NAME_FIELD in first or ("gates" not in first and "tracking_id" not in first)
    return [{"tracking_id": "", "gates": items}] if wrap else items


def _normalize_input(data: object) -> list[Mapping[str, object]]:
    """Auto-detect agent output shape and return a uniform list of findings."""
    if isinstance(data, Mapping):
        normalized = _normalize_mapping(data)
        if normalized is not None:
            return normalized
    elif isinstance(data, list):
        return _normalize_list(data)

    raise ValueError(
        "Unrecognized input format: expected gates array, single finding, "
        "or multi-finding object"
    )


if __name__ == "__main__":
    sys.exit(main())
