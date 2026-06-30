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

"""Build the fix-validation launch prompt for a pre-staged workspace."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vvaharness.validation.constants.artifacts import DIFF_FILENAME, MISSING_FIELD_PLACEHOLDER
from vvaharness.validation.hints import hints_for
from vvaharness.validation.models import Manifest

if TYPE_CHECKING:
    from vvaharness.validation.models import ManifestFinding


def _score_line(label: str, score: object, vector: object) -> str:
    """Render a ``- **LABEL**: score (vector)`` markdown bullet line."""
    line = f"- **{label}**: {score}"
    if vector:
        line += f" ({vector})"
    return line


_NARRATIVE_FIELDS = (
    "description_detail",
    "impact",
    "exploit_scenario",
    "preconditions",
    "recommendation",
)


def _narrative_lines(finding: ManifestFinding) -> list[str]:
    """Return markdown bullets for optional narrative fields that are non-empty."""
    return [
        f"- **{name.replace('_', ' ').title()}**: {val}"
        for name in _NARRATIVE_FIELDS
        if (val := getattr(finding, name, ""))
    ]


def _bypass_hint_lines(finding: ManifestFinding) -> list[str]:
    """Return markdown bullets for known bypass patterns, empty list if none."""
    hints = hints_for(finding.category or "")
    if not hints:
        return []
    return [
        f"- **Known bypass patterns for {finding.category}**:",
        *[f"  - {hint}" for hint in hints],
    ]


def _append_finding_details(lines: list[str], finding: ManifestFinding) -> None:
    """Append a markdown finding-details section to lines in place."""
    lines += ["", "## Finding Details", ""]
    lines.append(f"- **Title**: {finding.title or MISSING_FIELD_PLACEHOLDER}")
    lines.append(f"- **Category**: {finding.category or MISSING_FIELD_PLACEHOLDER}")
    lines.append(f"- **Severity**: {finding.severity or MISSING_FIELD_PLACEHOLDER}")
    if finding.cvss_base_score:
        lines.append(_score_line("CVSS", finding.cvss_base_score, finding.cvss_base_vector))
    if finding.source_file:
        lines.append(f"- **Source**: {finding.source_file}:{finding.source_line}")
    if finding.affected_files:
        lines.append(f"- **Affected files**: {', '.join(finding.affected_files)}")
    lines += _narrative_lines(finding)
    lines += _bypass_hint_lines(finding)


def build_launch_prompt(manifest: Manifest) -> str:
    """Compose the fix-validation launch prompt for a pre-staged workspace."""
    lines = [
        f"JIRA: {manifest.jira_key} ({manifest.jira_url})",
        f"Session: {manifest.session_id}",
        f"Finding IDs: {', '.join(manifest.finding_ids)}",
        "",
        "## Patch under validation",
        "",
        f"The remediation patch is **already applied** to this workspace tree; the "
        f"applied unified diff is at `{DIFF_FILENAME}` in the workspace root. Read it first "
        "-- it is your primary focus -- then read the rest of the tree freely for "
        "cross-file context. Follow the grounding and independence rules in the system "
        "prompt: navigate by hunk content and symbol names, never by line number; treat "
        "the remediator's `triage.json` verdict as an unverified claim to confirm or "
        "refute, not as evidence.",
    ]
    if manifest.finding:
        _append_finding_details(lines, manifest.finding)
    lines.append("")
    lines.append("## Session Config")
    lines.append(f"- post_results: {'true' if manifest.post_results else 'false'}")
    if manifest.post_results:
        lines.append("")
        lines.append("### Post Markers")
        jira_marker = f"<!-- validation-session:{manifest.session_id} -->"
        lines.append(f"- JIRA {manifest.jira_key}: {jira_marker}")
    return "\n".join(lines)
