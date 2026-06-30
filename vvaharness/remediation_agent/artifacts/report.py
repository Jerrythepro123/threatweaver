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

"""remediation_agent.artifacts.report — assemble the canonical ``remediate_report.json``.

Joins the verbatim scan ``finding`` fields with the ``patch`` produced by this
remediation pass and an empty ``validation`` block (filled later by s11), so a
reviewer can validate the fix against the original finding from a single file at
the finding's root."""
from __future__ import annotations

from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.report_parser import Finding, finding_id, parse_finding_fields
from vvaharness.remediation_agent.artifacts.layout import SCHEMA_VERSION, DEFAULT_MAX_ATTEMPTS
from vvaharness.remediation_agent.artifacts.validation import empty_validation


def status_for(verdict: RemediationVerdict, mode: str) -> str:
    """Map a verdict + mode to the remediation report ``status`` field.

    A finding the policy gate denied is ``deny`` (the agent never ran). A
    successful ``fix``-mode pass is ``awaiting_validation`` (the edit landed but
    still needs a re-scan to confirm); ``report-only`` is ``proposed``; false
    positives are closed out as ``rejected``; anything else needs a human."""
    if verdict.verdict == "Denied":
        return "deny"
    if verdict.verdict == "False Positive":
        return "rejected"
    if mode == "report-only":
        return "proposed"
    if verdict.verdict in ("Fixed", "Partially Fixed"):
        return "awaiting_validation"
    return "needs_review"


def build_report(finding: Finding, verdict: RemediationVerdict, *, meta: dict,
                 diff: str | None, attempt: int = 1,
                 max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> dict:
    """Assemble the canonical ``remediate_report.json`` payload: the verbatim
    scan ``finding`` fields joined with the ``patch`` this pass produced, plus
    an empty ``validation`` block the downstream validator (s11) fills in."""
    return {
        "schema_version": SCHEMA_VERSION,
        "finding_id": finding_id(finding),
        "attempt": attempt,
        "max_attempts": max_attempts,
        "status": status_for(verdict, meta.get("mode", "fix")),
        "finding": parse_finding_fields(finding),
        "patch": {
            "_source": "s10 remediation (filled in by remediation stage)",
            "remediation_summary": verdict.summary,
            "files_touched": [c.file for c in verdict.changes if c.file],
            "diff": diff or "",
        },
        # Emitted empty here — the downstream validator (s11) fills it in. We
        # only lay out the structure so the schema is stable and the validator
        # has a well-known shape to populate; remediation never writes scores.
        "validation": empty_validation(),
    }
