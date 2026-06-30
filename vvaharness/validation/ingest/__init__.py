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

"""DTO ingest layer: discover remediation reports and stage validation workspaces."""

from __future__ import annotations

from vvaharness.validation.ingest.dto_loader import (
    discover_reports,
    load_report,
    select_reports,
)
from vvaharness.validation.ingest.errors import IngestError
from vvaharness.validation.ingest.manifest_builder import build_manifest
from vvaharness.validation.ingest.workspace import (
    assert_remediation_applied,
    stage_workspace,
)

__all__ = [
    "IngestError",
    "assert_remediation_applied",
    "build_manifest",
    "discover_reports",
    "load_report",
    "select_reports",
    "stage_workspace",
]
