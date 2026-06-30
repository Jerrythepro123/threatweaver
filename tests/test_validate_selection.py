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

"""Tests for validation finding selection: the max_findings (top-N by CVSS) cap.

Covers _resolve_selection precedence (--finding / --all / --max-findings / config
default), the CVSS sort helpers, and select_reports capping against on-disk reports.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from vvaharness.validation.cli import _resolve_selection
from vvaharness.validation.cli._run import Selection
from vvaharness.validation.constants.artifacts import STATUS_AWAITING_VALIDATION
from vvaharness.validation.ingest.dto_loader import (
    _cvss_score,
    _top_by_cvss,
    select_reports,
)
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.models import RemediationReport


# ---------------------------------------------------------------------------
# _resolve_selection precedence
# ---------------------------------------------------------------------------


def _args(*, all: bool = False, findings=None, max_findings=None) -> SimpleNamespace:  # noqa: A002
    return SimpleNamespace(all=all, findings=findings, max_findings=max_findings)


_CFG = SimpleNamespace(max_findings=20)


def test_default_uses_config_cap() -> None:
    """No flags -> cap from config.max_findings, no explicit ids."""
    assert _resolve_selection(_args(), _CFG) == Selection(finding_ids=None, max_findings=20)


def test_all_bypasses_cap() -> None:
    """--all -> no ids, no cap (validate everything)."""
    assert _resolve_selection(_args(all=True), _CFG) == Selection(None, None)


def test_finding_ids_bypass_cap() -> None:
    """--finding ids -> exactly those, cap ignored."""
    sel = _resolve_selection(_args(findings=["F-1", "F-2"]), _CFG)
    assert sel == Selection(finding_ids=["F-1", "F-2"], max_findings=None)


def test_flag_overrides_config_cap() -> None:
    """--max-findings N overrides the config default."""
    assert _resolve_selection(_args(max_findings=5), _CFG) == Selection(None, 5)


def test_all_wins_over_max_flag() -> None:
    """--all beats --max-findings ('all means all')."""
    assert _resolve_selection(_args(all=True, max_findings=5), _CFG) == Selection(None, None)


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------


def _report(fid: str, cvss: object) -> RemediationReport:
    return RemediationReport.model_validate({"finding_id": fid, "finding": {"cvss_score": cvss}})


def test_cvss_score_coercion() -> None:
    """Numeric strings parse; blanks/garbage fall back to 0.0."""
    assert _cvss_score(_report("a", 9.8)) == 9.8
    assert _cvss_score(_report("b", "7.5")) == 7.5
    assert _cvss_score(_report("c", "")) == 0.0
    assert _cvss_score(_report("d", "n/a")) == 0.0


def test_top_by_cvss_orders_and_trims() -> None:
    """Highest CVSS first; trimmed to the limit."""
    reports = [_report("low", 2.1), _report("crit", 9.8), _report("none", ""), _report("med", 5.5)]
    top = _top_by_cvss(reports, 2)
    assert [r.finding_id for r in top] == ["crit", "med"]


# ---------------------------------------------------------------------------
# select_reports capping against on-disk reports
# ---------------------------------------------------------------------------


def _write_report(repo: Path, fid: str, cvss: float) -> None:
    d = repo / "security-remediation" / fid
    d.mkdir(parents=True)
    (d / "remediate_report.json").write_text(json.dumps({
        "finding_id": fid,
        "status": STATUS_AWAITING_VALIDATION,
        "finding": {"cvss_score": cvss},
        "patch": {"diff": "", "files_touched": []},
    }))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _write_report(tmp_path, "f-crit", 9.8)
    _write_report(tmp_path, "f-high", 7.2)
    _write_report(tmp_path, "f-low", 3.1)
    return tmp_path


def test_select_caps_to_top_n_by_cvss(repo: Path) -> None:
    """max_findings keeps only the top-N awaiting reports by CVSS."""
    got = select_reports(repo, None, max_findings=2)
    assert {r.finding_id for r in got} == {"f-crit", "f-high"}


def test_select_no_cap_returns_all(repo: Path) -> None:
    """max_findings=None (the --all path) returns every awaiting report."""
    got = select_reports(repo, None, max_findings=None)
    assert len(got) == 3


def test_select_cap_above_count_returns_all(repo: Path) -> None:
    """A cap larger than the awaiting count returns everything (no trim)."""
    assert len(select_reports(repo, None, max_findings=99)) == 3


def test_select_finding_ids_ignore_cap(repo: Path) -> None:
    """Explicit finding ids are returned verbatim, cap ignored."""
    got = select_reports(repo, ["f-low"], max_findings=1)
    assert [r.finding_id for r in got] == ["f-low"]


def test_select_missing_finding_id_raises(repo: Path) -> None:
    """An unknown explicit id raises IngestError."""
    with pytest.raises(IngestError):
        select_reports(repo, ["nope"], max_findings=None)
