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

"""Remediation DTO (``remediate_report.json``) consumed by the validator; tolerant wire shape."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator


class DtoFinding(BaseModel):
    """The finding (CVE) block carried by the remediation DTO."""

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    vuln_class: str = ""
    cwe: str = ""
    file: str = ""
    line_start: int = 0
    line_end: int = 0
    description: str = ""
    recommendation: str = ""
    impact: str = ""
    exploit_scenario: str = ""
    preconditions: list[str] = Field(default_factory=list)
    cvss_vector: str = ""
    cvss_score: float | str = ""
    cvss_rating: str = ""

    @field_validator("cvss_vector", "cvss_score", "cvss_rating", mode="before")
    @classmethod
    def _null_to_default(cls, v: object) -> object:
        """Coerce an explicit JSON ``null`` to the field default (tolerant wire shape).

        Remediation may emit ``cvss_*: null`` when CVSS metadata is absent; that is
        not a parse error, so map it to ``""`` rather than rejecting the report.
        """
        return "" if v is None else v


class DtoPatch(BaseModel):
    """The applied-patch block carried by the remediation DTO."""

    model_config = ConfigDict(extra="ignore")

    files_touched: list[str] = Field(default_factory=list)
    diff: str = ""


class RemediationReport(BaseModel):
    """Top-level ``remediate_report.json`` document."""

    model_config = ConfigDict(extra="ignore")

    schema_version: str = ""
    finding_id: str = ""
    attempt: int = 0
    max_attempts: int = 0
    status: str = ""
    finding: DtoFinding = Field(default_factory=DtoFinding)
    patch: DtoPatch = Field(default_factory=DtoPatch)
    # Origin path on disk, retained so the validator can write its verdict back into
    # this same remediate_report.json. Excluded from serialization (not a wire field).
    source_path: Path | None = Field(default=None, exclude=True)

    @classmethod
    def from_file(cls, path: Path) -> RemediationReport:
        """Parse a remediation report from disk (malformed JSON names the file)."""
        report: RemediationReport = cls.model_validate(_read_json(path))
        report.source_path = path
        return report


def _read_json(path: Path) -> object:
    """Read and JSON-parse *path*, raising a path-qualified error on malformed JSON."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"malformed JSON in remediation report {path}: {e}") from e
