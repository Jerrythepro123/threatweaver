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

"""remediation_agent.report_augment.dto — load + classify the per-finding DTOs.

Reads every ``remediate_report.json`` the agent wrote (plus its
``evidence/triage.json`` sidecar for the policy decision) and enriches each with
a report-facing ``_remediation_status`` / ``_remediation_reason``. Purely
filesystem-driven — no model spend."""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

REMEDIATE_REPORT_FILENAME = "remediate_report.json"
TRIAGE_RELPATH = ("evidence", "triage.json")

# Synthetic record for a finding that was never handed to the remediation agent
# (e.g. below the top-N cap or otherwise not selected): it still gets a block /
# section so every finding in the report carries an explicit remediation status.
_NOT_PROCESSED_REASON = "finding not processed for remediation"

# Report-facing reason for each non-success ("skipped" bucket) DTO status. Statuses
# not listed fall back to the generic needs-review message. ``validation_failed`` is
# the terminal status s11 writes when an applied fix did not pass review.
_SKIPPED_REASONS = {
    "validation_failed": "fix applied but failed validation; needs rework",
    "rejected": "finding rejected as a false positive",
}


def _skipped_dto() -> dict:
    """A synthetic DTO marking a finding that was never processed → skipped."""
    return {
        "_remediation_status": "skipped",
        "_remediation_reason": _NOT_PROCESSED_REASON,
        "patch": {},
        "finding": {},
    }


def _load_dtos(rem_dir: Path) -> list[dict]:
    """Load every ``remediate_report.json`` under the remediation dir.

    Each returned dict is enriched with a synthetic ``_remediation_status`` /
    ``_remediation_reason`` (the report-facing enum + human reason) derived from
    the DTO ``status`` and, when present, the policy decision in the finding's
    ``evidence/triage.json`` sidecar."""
    dtos: list[dict] = []
    for dto_path in sorted(rem_dir.glob(f"*/{REMEDIATE_REPORT_FILENAME}")):
        try:
            dto = json.loads(dto_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            log.warning(
                "remediate: skipping unreadable report '%s' (%s): %s",
                dto_path.parent.name, dto_path, e,
            )
            continue
        if not isinstance(dto, dict):
            continue
        triage = _load_triage(dto_path.parent)
        status, reason = _status_and_reason(dto, triage)
        dto["_remediation_status"] = status
        dto["_remediation_reason"] = reason
        dtos.append(dto)
    return dtos


def _load_triage(finding_dir: Path) -> dict:
    """Load the ``evidence/triage.json`` sidecar for one finding (``{}`` on absence)."""
    triage_path = finding_dir.joinpath(*TRIAGE_RELPATH)
    try:
        data = json.loads(triage_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _status_and_reason(dto: dict, triage: dict) -> tuple[str, str]:
    """Map a remediation DTO (+ triage sidecar) to (remediationStatus, reason).

    ``remediated`` — a fix landed (DTO status awaiting_validation / proposed /
                     validated — the last being the terminal state s11 sets once
                     it confirms the fix).
    ``deny``        — the policy gate refused to patch (denied verdict).
    ``skipped``     — false positive, needs-review, validation_failed (a fix was
                     applied but did not pass s11 review), or anything else not
                     counted as remediated.
    """
    status = str(dto.get("status", "")).lower()
    patch = dto.get("patch") or {}
    summary = str(patch.get("remediation_summary", "")).strip()

    # Policy pre-gate denial short-circuits to a deny: the DTO carries
    # status == "deny" (verdict "Denied"). The human reason is the policy
    # reason recorded in the triage sidecar, falling back to the DTO summary.
    if status == "deny":
        reason = (triage.get("policy_reason") or summary
                  or "policy gate denied automated remediation")
        return "deny", str(reason)

    # ``validated`` is the terminal status s11 writes once it confirms the fix;
    # an out-of-order re-run of this s10 augmenter over an already-advanced repo
    # must NOT mislabel a confirmed-fixed finding as "skipped" (F45). It maps to
    # the same report-facing "remediated" bucket as awaiting_validation/proposed.
    if status in ("awaiting_validation", "proposed", "validated"):
        return "remediated", summary or "remediation applied"
    # All remaining statuses map to the non-success "skipped" bucket, each with an
    # explicit reason. validation_failed (a fix was applied but did not pass s11 review)
    # is NOT remediated and is distinguished from the generic needs-review fallback.
    skipped_reason = _SKIPPED_REASONS.get(status, "remediation not applied; needs review")
    return "skipped", summary or skipped_reason


def _finding_of(dto: dict) -> dict:
    f = dto.get("finding")
    return f if isinstance(f, dict) else {}


def _files_touched(dto: dict) -> list[str]:
    patch = dto.get("patch") or {}
    files = patch.get("files_touched")
    if not isinstance(files, list):
        return []
    # De-duplicate while preserving first-seen order so each file is listed once.
    seen: set[str] = set()
    unique: list[str] = []
    for f in files:
        if not f:
            continue
        s = str(f)
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def _remediation_block(dto: dict) -> dict:
    """Build the SARIF per-result ``remediation`` object."""
    return {
        "remediationStatus": dto.get("_remediation_status", "skipped"),
        "remediationReason": str(dto.get("_remediation_reason", ""))[:2000],
    }
