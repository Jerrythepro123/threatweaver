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

"""Augment the combined SARIF + MD report with remediation results.

After a remediation run, copy the scan's pristine ``security-scan/*_report.{sarif,md}``
into ``security-remediation/`` (once) and add, per remediated finding, a ``remediation``
block to the matching SARIF result and a ``### Remediation`` section (status, summary,
approach, files changed) to the matching MD finding.

This mirrors :mod:`vvaharness.validation.report.augment` (the s11 validation analog) so
the combined report carries BOTH the validation and remediation results in the same
shape. Best-effort: a failure here never fails the remediation run.

The remediation results are read back from the canonical per-finding DTOs the
remediation agent already wrote — ``security-remediation/<NN_slug>/remediate_report.json``
(plus its ``evidence/triage.json`` sidecar for the policy decision) — so this module
adds NO model spend and is purely filesystem-driven.

Split into focused modules, re-exported here so callers keep using
``from vvaharness.remediation_agent.report_augment import augment_reports`` unchanged:

  - :mod:`vvaharness.remediation_agent.report_augment.dto`      — DTO load + status classification
  - :mod:`vvaharness.remediation_agent.report_augment.locate`   — locate + copy the scan report
  - :mod:`vvaharness.remediation_agent.report_augment.mdsafe`   — escape untrusted text (CWE-79)
  - :mod:`vvaharness.remediation_agent.report_augment.sarif`    — SARIF augmentation
  - :mod:`vvaharness.remediation_agent.report_augment.markdown` — Markdown augmentation
"""
from __future__ import annotations

import logging
from pathlib import Path

from vvaharness.remediation_agent.report_parser import (
    REMEDIATION_DIR_NAME, SCAN_DIR_NAME)
from vvaharness.remediation_agent.report_augment.dto import _load_dtos
from vvaharness.remediation_agent.report_augment.locate import (
    _ensure_combined, _locate_scan_report)
from vvaharness.remediation_agent.report_augment.markdown import _augment_md
from vvaharness.remediation_agent.report_augment.sarif import _augment_sarif

log = logging.getLogger(__name__)

__all__ = ["augment_reports"]


def augment_reports(repo: Path, report_md: Path | str | None = None) -> None:
    """Copy the scan report into ``security-remediation/`` and add remediation results.

    *report_md* is the EXPLICIT canonical scan Markdown report to augment (its
    sibling ``*.sarif`` is derived). Callers that produced/located the report
    (the scan pipeline, the ``remediate`` command) pass it so augmentation binds
    to the exact report this run processed — never a planted/stale file picked by
    a newest-wins glob (MV-06). When omitted, ``_augment`` falls back to the glob
    with an explicit ambiguity warning.

    Best-effort: any failure is logged and swallowed so reporting never breaks a run.
    """
    try:
        _augment(Path(repo), Path(report_md) if report_md else None)
    except Exception:  # report augmentation must never fail the remediation run
        log.exception("remediation report augmentation failed; results not written "
                      "to combined report")


def _augment(repo: Path, report_md: Path | None = None) -> None:
    """Locate + copy the scan report, then augment the SARIF and MD copies."""
    rem_dir = repo / REMEDIATION_DIR_NAME
    dtos = _load_dtos(rem_dir) if rem_dir.is_dir() else []
    if not dtos:
        log.info("no remediation DTOs under %s — skipping report augmentation", rem_dir)
        return

    located = _locate_scan_report(repo, report_md)
    if located is None:
        log.warning("no scan report under %s/%s — skipping report augmentation",
                    repo, SCAN_DIR_NAME)
        return
    sarif_dst, md_dst = _ensure_combined(repo, *located)
    _augment_sarif(sarif_dst, dtos)
    _augment_md(md_dst, dtos)
    log.info("remediation results written to combined report under %s", sarif_dst.parent)
