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

"""Map a remediation report DTO onto the agent-facing validation manifest."""

from __future__ import annotations

from vvaharness.validation.constants.paths import ValidationPath
from vvaharness.validation.models import Manifest, ManifestFinding, RemediationReport


def build_manifest(report: RemediationReport, session_id: str) -> Manifest:
    """Build a single-finding validation manifest from a remediation report."""
    finding = report.finding
    manifest_finding = ManifestFinding(
        tracking_id=report.finding_id,
        title=finding.title,
        source_file=finding.file,
        source_line=finding.line_start,
        category=finding.cwe or finding.vuln_class,
        severity=finding.cvss_rating,
        description_detail=finding.description,
        impact=finding.impact,
        exploit_scenario=finding.exploit_scenario,
        preconditions="\n".join(finding.preconditions),
        recommendation=finding.recommendation,
        cvss_base_score=str(finding.cvss_score),
        cvss_base_vector=finding.cvss_vector,
        affected_files=report.patch.files_touched,
    )
    return Manifest(
        jira_key=report.finding_id,
        session_id=session_id,
        finding_ids=[report.finding_id],
        finding=manifest_finding,
        post_results=False,
        validation_path=ValidationPath.FIX_VALIDATION.value,
    )
