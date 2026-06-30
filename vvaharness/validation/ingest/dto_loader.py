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

"""Discover and load remediation report DTOs from a target repository."""

from __future__ import annotations

import sys
from pathlib import Path

from pydantic import ValidationError

from vvaharness.validation.constants.artifacts import (
    REMEDIATION_GLOB,
    VALIDATABLE_STATUSES,
)
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.models import RemediationReport

_VALIDATABLE = ", ".join(VALIDATABLE_STATUSES)


def discover_reports(repo: Path) -> list[Path]:
    """Return sorted remediation report paths under the repo's remediation dir."""
    return sorted(repo.glob(REMEDIATION_GLOB))


def load_report(path: Path) -> RemediationReport:
    """Parse a single remediation report from disk."""
    return RemediationReport.from_file(path)


def _load_report_safe(path: Path) -> RemediationReport | None:
    """Load a report, or None (with a named warning) when it's malformed/unreadable.

    A malformed (bad JSON) or schema-invalid report is skipped so one corrupt
    artefact can't abort an ``--all`` run.
    """
    try:
        return load_report(path)
    except (ValueError, ValidationError) as e:
        print(
            f"validate: skipping finding '{path.parent.name}' — "
            f"unreadable remediation report ({path}): {e}",
            file=sys.stderr,
        )
        return None


def _all_reports(repo: Path) -> list[RemediationReport]:
    """Load every readable remediation report under *repo* (any status)."""
    return [r for path in discover_reports(repo) if (r := _load_report_safe(path)) is not None]


def _is_validatable(report: RemediationReport) -> bool:
    """True if the report's status is one the validator can act on."""
    return report.status in VALIDATABLE_STATUSES


def _cvss_score(report: RemediationReport) -> float:
    """Return the finding's CVSS base score as a float; 0.0 when absent/unparseable."""
    try:
        return float(report.finding.cvss_score)
    except (TypeError, ValueError):
        return 0.0


def _top_by_cvss(reports: list[RemediationReport], limit: int) -> list[RemediationReport]:
    """Return the *limit* highest-CVSS reports; stable discovery order on ties."""
    return sorted(reports, key=_cvss_score, reverse=True)[:limit]


def _log_selection(reports: list[RemediationReport]) -> None:
    """Emit one stderr line per selected finding so the ``--all`` route is never silent."""
    for r in reports:
        print(f"validate: selected {r.finding_id} (status={r.status})", file=sys.stderr)


def select_reports(
    repo: Path,
    finding_ids: list[str] | None,
    max_findings: int | None = None,
) -> list[RemediationReport]:
    """Load validatable reports (statuses in ``VALIDATABLE_STATUSES``).

    ``finding_ids`` selects exactly those ids (cap ignored); a requested finding with a
    non-validatable status raises ``IngestError``. Otherwise every validatable report is
    returned, trimmed to the top ``max_findings`` by CVSS (``--all``/``None`` disables the
    cap). Every selected finding is logged to stderr.
    """
    all_reports = _all_reports(repo)
    if finding_ids is not None:
        selected = _select_by_id(all_reports, finding_ids)
    else:
        selected = [r for r in all_reports if _is_validatable(r)]
        if max_findings is not None and max_findings > 0 and len(selected) > max_findings:
            total = len(selected)
            selected = _top_by_cvss(selected, max_findings)
            print(
                f"validate: capping to top {max_findings} of {total} validatable findings by CVSS "
                f"(use --all to validate every finding)",
                file=sys.stderr,
            )
    _log_selection(selected)
    return selected


def _select_by_id(
    all_reports: list[RemediationReport], finding_ids: list[str],
) -> list[RemediationReport]:
    """Resolve explicit finding ids, raising IngestError on missing or non-validatable status."""
    by_id = {r.finding_id: r for r in all_reports}
    missing = [fid for fid in finding_ids if fid not in by_id]
    if missing:
        raise IngestError(f"requested finding ids not found: {', '.join(missing)}")
    not_validatable = [
        f"{fid} (status '{by_id[fid].status or 'unset'}')"
        for fid in finding_ids
        if not _is_validatable(by_id[fid])
    ]
    if not_validatable:
        raise IngestError(
            "validation cannot run — these findings have no validatable status "
            f"(need {_VALIDATABLE}): {', '.join(not_validatable)}"
        )
    return [by_id[fid] for fid in finding_ids]
