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

"""remediation_agent.report_augment.sarif — add remediation blocks to the SARIF copy.

Matches each remediation DTO to a SARIF result (by (file, line_start), else by
title prefix) and adds its ``remediation`` block; every other result gets an
explicit ``skipped`` block so no finding is left ambiguous."""
from __future__ import annotations

import json
from pathlib import Path

from vvaharness.remediation_agent.report_augment.dto import (
    _finding_of, _remediation_block, _skipped_dto)


def _result_loc(sarif_result: dict) -> tuple[str, int]:
    """Return (uri, startLine) for a SARIF result, or ("", -1) when unavailable."""
    try:
        pl = sarif_result["locations"][0]["physicalLocation"]
        return pl["artifactLocation"]["uri"], int(pl["region"]["startLine"])
    except (KeyError, IndexError, TypeError, ValueError):
        return "", -1


def _match_by_loc(results: list[dict], file: str, line: int) -> dict | None:
    """Return the result whose physical location is exactly (file, line)."""
    for r in results:
        if _result_loc(r) == (file, line):
            return r
    return None


def _match_by_title(results: list[dict], title: str) -> dict | None:
    """Return the first result whose message text starts with *title*."""
    for r in results:
        if str(r.get("message", {}).get("text", "")).startswith(title):
            return r
    return None


def _match_sarif(results: list[dict], dto: dict) -> dict | None:
    """Match a SARIF result to a DTO by (file, line_start), else by title prefix."""
    finding = _finding_of(dto)
    file = str(finding.get("file") or "")
    line = finding.get("line_start")
    by_loc = (_match_by_loc(results, file, int(line))
              if file and isinstance(line, int) else None)
    if by_loc is not None:
        return by_loc
    title = str(finding.get("title") or "").strip()
    return _match_by_title(results, title) if title else None


def _augment_sarif(path: Path, dtos: list[dict]) -> None:
    """Add a ``remediation`` block to every SARIF result.

    Results matching a remediation DTO get that DTO's status/reason; every other
    result (a finding that was never processed for remediation) gets an explicit
    ``skipped`` block so no finding is left ambiguous."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    runs = doc.get("runs") or [{}]
    results = runs[0].get("results", []) if runs else []
    matched_ids: set[int] = set()
    for dto in dtos:
        match = _match_sarif(results, dto)
        if match is not None:
            match["remediation"] = _remediation_block(dto)
            matched_ids.add(id(match))
    # Unprocessed findings → explicit skipped block.
    skipped = _remediation_block(_skipped_dto())
    for r in results:
        if id(r) not in matched_ids:
            r["remediation"] = dict(skipped)
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
