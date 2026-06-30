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

"""remediation_agent.discovery — locate the scan report and select findings.

Pure(-ish) input handling for the ``remediate`` command, kept separate from the
processing loop:

  * :func:`locate_report`  — find the newest ``*_report.md`` (or an exit code).
  * :func:`cvss_score_of`  — per-finding score accessor for ``--top N``.
  * :func:`load_findings`  — parse findings + apply the ``--top N`` selection.
  * :class:`Layout` / :func:`prepare_layout` — per-repo output + checkpoints.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from vvaharness.remediation_agent.report_parser import (
    REMEDIATION_DIR_NAME, SCAN_DIR_NAME, Finding,
    find_scan_dir, latest_report, parse_findings, cvss_score_only)
from vvaharness.remediation_agent.select import select_top_logged
from vvaharness.orchestrator.checkpoints import run_id_for


CHECKPOINTS_DIR_NAME = "checkpoints"


def locate_report(repo_path: Path) -> tuple[Path | None, int]:
    """Find the newest scan report under ``<repo>/security-scan/``.

    Returns ``(report_path, 0)`` on success or ``(None, exit_code)`` with the
    error already printed, so the caller can ``return`` the code directly."""
    scan_dir = find_scan_dir(repo_path)
    if scan_dir is None:
        print(f"  ✗ no '{SCAN_DIR_NAME}' folder found under {repo_path} — run "
              f"`vvaharness scan --repo {repo_path}` first.", file=sys.stderr)
        return None, 1

    report = latest_report(scan_dir)
    if report is None:
        print(f"  ✗ no scan report (*_report.md) found in {scan_dir} — run "
              f"`vvaharness scan --repo {repo_path}` first.", file=sys.stderr)
        return None, 1
    return report, 0


def cvss_score_of(finding: Finding) -> float | None:
    """Numeric CVSS base score for a parsed markdown finding, or ``None`` when
    the report rendered only a vector / bare severity band. Used as the
    ``score_of`` accessor for ``--top N`` selection.

    Uses the cheap single-line :func:`cvss_score_only` extractor — selection
    only needs the score, so the full :func:`parse_finding_fields` (section
    split) is deferred to the findings that actually get remediated."""
    return cvss_score_only(finding)


def load_findings(report: Path, top: int | None) -> list[Finding]:
    """Parse findings from *report* and, when ``top`` is set, keep only the N
    highest-CVSS findings (limit & reorder) via the SAME shared PQ helper the
    in-pipeline ``scan --remediate --top N`` path uses. The ``--top`` gate and
    its log line live in :func:`select_top_logged` so both paths stay in sync."""
    findings = parse_findings(report.read_text(encoding="utf-8"))
    return select_top_logged(findings, top, score_of=cvss_score_of,
                             log_prefix="[Remediation Agent]")


@dataclass(frozen=True)
class Layout:
    """Resolved per-repo output + checkpoint locations for one remediation run."""
    rem_dir: Path
    ckpt_dir: Path
    run_id: str


def prepare_layout(repo_path: Path) -> Layout:
    """Resolve (and create) the per-repo remediation output dir, and reuse the
    SAME checkpoint folder the scan pipeline writes to (``<repo>/checkpoints``)
    rather than carving out a private one under security-remediation/, so a
    target's scan + remediation state live together and the cleanup
    preserve-list already covers them."""
    rem_dir = repo_path / REMEDIATION_DIR_NAME
    rem_dir.mkdir(parents=True, exist_ok=True)
    return Layout(
        rem_dir=rem_dir,
        ckpt_dir=repo_path / CHECKPOINTS_DIR_NAME,
        run_id=run_id_for(repo_path),
    )
