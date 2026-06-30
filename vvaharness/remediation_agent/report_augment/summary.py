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

"""remediation_agent.report_augment.summary — the report-level ``## Remediation Summary``.

Tally the loaded DTOs (:func:`_summary_counts`) and render the report-level
``## Remediation Summary`` block (:func:`_md_summary_section`) appended to the
combined Markdown report."""
from __future__ import annotations


def _summary_counts(dtos: list[dict]) -> dict[str, int]:
    """Tally report-level remediation metrics from the loaded DTOs.

    - ``true_positive`` — genuine findings (everything except false positives,
      i.e. DTOs whose original ``status`` was ``rejected``).
    - ``in_scope`` — findings that were actually handed to the remediation agent,
      i.e. every finding that has a per-finding DTO folder on disk. This is just
      ``len(dtos)``; findings dropped below the ``--top N`` cap never get a DTO
      and so are not in scope.
    - ``remediated`` — findings a fix actually landed for.
    """
    total = len(dtos)
    false_positive = sum(
        1 for d in dtos if str(d.get("status", "")).lower() == "rejected"
    )
    remediated = sum(1 for d in dtos if d.get("_remediation_status") == "remediated")
    return {
        "true_positive": total - false_positive,
        "in_scope": total,
        "remediated": remediated,
    }


def _md_summary_section(dtos: list[dict]) -> str:
    """Render the report-level ``## Remediation Summary`` section."""
    c = _summary_counts(dtos)
    in_scope = c["in_scope"]
    remediated = c["remediated"]
    rate = f"{(remediated / in_scope * 100):.0f}%" if in_scope > 0 else "n/a"
    return (
        "## Remediation Summary\n"
        f"- Total findings (true positive): {c['true_positive']}\n"
        f"- Findings in scope for remediation: {in_scope}\n"
        f"- Remediated: {remediated}\n"
        f"- Success Rate(remediated/true positive): {rate}\n"
    )
