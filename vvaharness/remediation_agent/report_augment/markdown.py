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

"""remediation_agent.report_augment.markdown — add remediation sections to the MD copy.

Inserts a per-finding ``### Remediation`` section (status / summary / approach /
files changed) under each finding heading plus a report-level
``## Remediation Summary``. Title matching is exact-first / ambiguity-safe
(:func:`_best_md_match`) so a result is never attached under the wrong finding
(CWE-345)."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from vvaharness.remediation_agent.report_augment.dto import (
    _files_touched, _finding_of, _skipped_dto)
from vvaharness.remediation_agent.report_augment.mdsafe import (
    _md_code_span, _md_escape)
from vvaharness.remediation_agent.report_augment.summary import _md_summary_section

log = logging.getLogger(__name__)

# Finding heading in the markdown report, e.g. ``### 1. [HIGH] Some title``.
_FINDING_RE = re.compile(r"(?m)^### \d+\. \[[^\]]*\]\s*(.+?)\s*$")
# A previously-appended ``### Remediation`` block, anchored to the end of a finding segment.
_EXISTING_REMEDIATION_RE = re.compile(r"(?s)\n+### Remediation\n.*\Z")
# A previously-appended ``## Remediation Summary`` block (idempotent re-runs strip it
# before re-inserting), bounded by the next markdown heading or end of document.
_SUMMARY_RE = re.compile(r"(?s)## Remediation Summary\n.*?(?=\n#{1,6} |\Z)")


def _md_remediation_section(dto: dict) -> str:
    """Render the ``### Remediation`` markdown section for one finding."""
    status = dto.get("_remediation_status", "skipped")
    reason = str(dto.get("_remediation_reason", "")).strip()
    patch = dto.get("patch") or {}
    summary = str(patch.get("remediation_summary", "")).strip() or reason or "n/a"
    files = _files_touched(dto)

    if status == "remediated":
        approach = ("Automated fix applied by the Remediation Agent and written as a "
                    "unified diff; awaiting validation.")
    elif status == "deny":
        approach = ("Policy gate denied automated patching; guidance-only — a human "
                    "must remediate.")
    else:
        approach = "No automated patch applied."

    # status/approach are harness-controlled (closed enums / literals); summary
    # and file names are model/DTO-controlled and MUST be escaped at this render
    # boundary (CWE-79).
    lines = [
        "### Remediation",
        f"- **Status:** {_md_escape(status)}",
        f"- **Summary:** {_md_escape(summary)}",
        f"- **Approach:** {approach}",
        "- **Details of what was remediated:**",
    ]
    if files:
        lines += [f"  - {_md_code_span(f)}" for f in files]
    else:
        lines.append("  - (no files changed)")
    return "\n".join(lines) + "\n"


def _best_md_match(title: str, dtos: list[dict]) -> dict | None:
    """Find the DTO for the MD heading *title*, refusing ambiguous matches.

    Matching is deterministic and fails closed to avoid attaching a remediation
    result under the WRONG finding (CWE-345): exact (case-insensitive,
    whitespace-normalised) title equality is tried first — exactly one match
    wins, several sharing that title return ``None`` (rendered ``skipped``
    rather than mis-attributed). Only when NO exact match exists do we fall
    back to substring containment, and that is accepted ONLY when unambiguous
    (exactly one DTO contains / is contained by the heading). This avoids the
    previous FIRST-bidirectional-substring behaviour that could cross-match
    overlapping titles (e.g. "SQL injection" vs "SQL injection in reports")."""
    norm = title.strip().lower()
    if not norm:
        return None

    exact = [d for d in dtos
             if str(_finding_of(d).get("title") or "").strip().lower() == norm]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        log.warning("remediate: %d DTOs share the exact title %r — refusing to "
                    "guess; finding rendered as skipped", len(exact), title)
        return None

    # No exact match → unambiguous substring fallback only.
    fuzzy = []
    for d in dtos:
        ftitle = str(_finding_of(d).get("title") or "").strip().lower()
        if ftitle and (ftitle in norm or norm in ftitle):
            fuzzy.append(d)
    if len(fuzzy) == 1:
        return fuzzy[0]
    if len(fuzzy) > 1:
        log.warning("remediate: ambiguous title match for %r (%d candidates) — "
                    "refusing to guess; finding rendered as skipped",
                    title, len(fuzzy))
    return None


def _augment_md(path: Path, dtos: list[dict]) -> None:
    """Insert/replace per-finding ``### Remediation`` sections plus a report-level
    ``## Remediation Summary``."""
    text = path.read_text(encoding="utf-8")
    # Drop any prior report-level summary so re-runs stay idempotent; it is
    # re-appended at the end from the freshly tallied DTOs.
    text = _SUMMARY_RE.sub("", text).rstrip() + "\n"
    matches = list(_FINDING_RE.finditer(text))
    if not matches:
        return
    bounds = [m.start() for m in matches] + [len(text)]
    rebuilt = [text[: bounds[0]]]
    for i, m in enumerate(matches):
        segment = text[bounds[i]: bounds[i + 1]]
        # A finding with no matching DTO was never processed → skipped section.
        dto = _best_md_match(m.group(1), dtos) or _skipped_dto()
        rebuilt.append(_augment_segment(segment, dto))
    rebuilt.append("\n" + _md_summary_section(dtos))
    path.write_text("".join(rebuilt), encoding="utf-8")


def _augment_segment(segment: str, dto: dict | None) -> str:
    """Replace any prior ``### Remediation`` block in *segment* and append the current one."""
    if dto is None:
        return segment
    stripped = _EXISTING_REMEDIATION_RE.sub("", segment)
    return stripped.rstrip() + "\n\n" + _md_remediation_section(dto) + "\n"
