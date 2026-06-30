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

"""Per-finding workspace manifest (``manifest.json``); treated as a stable wire shape."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from vvaharness.validation.constants.paths import ValidationPath


class ManifestFinding(BaseModel):
    """The finding (CVE) detail block the agent reads from the manifest."""

    model_config = ConfigDict(extra="ignore")

    tracking_id: str = ""
    title: str = ""
    source_file: str = ""
    source_line: int = 0
    category: str = ""
    severity: str = ""
    description_detail: str = ""
    impact: str = ""
    exploit_scenario: str = ""
    preconditions: str = ""
    recommendation: str = ""
    cvss_base_score: str = ""
    cvss_base_vector: str = ""
    affected_files: list[str] = Field(default_factory=list)


class Manifest(BaseModel):
    """The per-finding validation manifest written to the workspace root."""

    model_config = ConfigDict(extra="ignore")

    jira_key: str = ""
    jira_url: str = ""
    session_id: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    finding: ManifestFinding | None = None
    post_results: bool = False
    validation_path: str = ValidationPath.FIX_VALIDATION.value

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain JSON-compatible dict."""
        return self.model_dump(mode="json")

    def write(self, path: Path) -> None:
        """Persist the manifest as pretty JSON."""
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def from_file(cls, path: Path) -> Manifest:
        """Load a manifest from disk, tolerating legacy/extra keys."""
        return cls.model_validate(json.loads(path.read_text(encoding="utf-8")))
