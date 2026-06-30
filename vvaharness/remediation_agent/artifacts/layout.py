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

"""remediation_agent.artifacts.layout — file/folder names and schema constants.

Single source of truth for the per-finding artefact layout so the writer, the
report builder, and tests all agree on names without duplicating string
literals."""
from __future__ import annotations

# Evidence artefacts live in a subfolder; the canonical report sits at the root.
EVIDENCE_DIR = "evidence"
TRIAGE_JSON = "triage.json"
SUMMARY_MD = "summary.md"
# Shares the literal "diff.patch" with validation's DIFF_FILENAME by design; the two
# subsystems are deliberately decoupled — do not extract a shared constant.
DIFF_PATCH = "diff.patch"
REMEDIATE_REPORT_JSON = "remediate_report.json"

SCHEMA_VERSION = "1.0"
# Default remediation attempt budget; surfaced so the report records its place
# in a retry sequence even though the current pipeline runs a single attempt.
DEFAULT_MAX_ATTEMPTS = 2
