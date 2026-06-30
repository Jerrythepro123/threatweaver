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

"""A malformed remediate_report.json must be skipped (named), not abort the run.

Regression for the validator crashing with a bare json.JSONDecodeError that did
not identify which security-remediation/*/remediate_report.json was corrupt.
"""
import json
from pathlib import Path

import pytest

from vvaharness.validation.ingest.dto_loader import select_reports
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.models import RemediationReport


def _report(fid: str, status: str) -> str:
    return json.dumps({
        "finding_id": fid, "status": status,
        "finding": {"title": "t", "cvss_score": "5.0"}, "patch": {},
    })


def _write(dir_: Path, name: str, text: str) -> Path:
    sub = dir_ / "security-remediation" / name
    sub.mkdir(parents=True)
    path = sub / "remediate_report.json"
    path.write_text(text, encoding="utf-8")
    return path


def _good(fid: str) -> str:
    return json.dumps({
        "finding_id": fid, "status": "awaiting_validation",
        "finding": {"title": "t", "cvss_score": "7.5"}, "patch": {},
    })


# "Expecting ',' delimiter" — the exact field-level failure mode reported.
_MALFORMED = '{\n  "finding_id": "bad-1"\n  "status": "awaiting_validation"\n}'


def test_malformed_report_is_skipped_not_fatal(tmp_path, capsys) -> None:
    _write(tmp_path, "01_good", _good("good-1"))
    _write(tmp_path, "02_bad", _MALFORMED)

    reports = select_reports(tmp_path, None, None)

    assert [r.finding_id for r in reports] == ["good-1"]          # good one survives
    warning = capsys.readouterr().err
    assert "skipping finding '02_bad'" in warning                 # names the finding


def test_from_file_error_names_the_path(tmp_path) -> None:
    path = _write(tmp_path, "02_bad", _MALFORMED)
    with pytest.raises(ValueError, match="malformed JSON in remediation report"):
        RemediationReport.from_file(path)


def test_null_cvss_fields_coerced_not_rejected() -> None:
    # Remediation may emit cvss_* as JSON null; that must parse (coerced to ""),
    # not raise a pydantic ValidationError that aborts the whole load.
    report = RemediationReport.model_validate({
        "finding_id": "n-1", "status": "awaiting_validation",
        "finding": {"title": "t", "cvss_vector": None,
                    "cvss_score": None, "cvss_rating": None},
    })
    assert report.finding.cvss_vector == ""
    assert report.finding.cvss_score == ""
    assert report.finding.cvss_rating == ""


# ---------------------------------------------------------------------------
# Dual-status: both awaiting_validation and needs_review are validatable
# ---------------------------------------------------------------------------


def test_needs_review_and_awaiting_both_selected(tmp_path) -> None:
    _write(tmp_path, "01_await", _report("AW-1", "awaiting_validation"))
    _write(tmp_path, "02_review", _report("NR-1", "needs_review"))
    _write(tmp_path, "03_proposed", _report("PR-1", "proposed"))  # not validatable

    ids = {r.finding_id for r in select_reports(tmp_path, None, None)}

    assert ids == {"AW-1", "NR-1"}        # needs_review now included; proposed excluded


def test_finding_with_non_validatable_status_reports_clearly(tmp_path) -> None:
    _write(tmp_path, "03_proposed", _report("PR-1", "proposed"))
    with pytest.raises(IngestError, match="no validatable status.*PR-1.*proposed"):
        select_reports(tmp_path, ["PR-1"], None)


def test_needs_review_finding_selectable_by_id(tmp_path) -> None:
    _write(tmp_path, "02_review", _report("NR-1", "needs_review"))
    sel = select_reports(tmp_path, ["NR-1"], None)
    assert [r.finding_id for r in sel] == ["NR-1"]
