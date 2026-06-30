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

"""remediation_agent.report_parser — locate and parse the Markdown reports a scan produced.

`scan` writes its artefacts to ``<repo>/security-scan/`` (see
``orchestrator.scan.scan_repo``). This package mirrors that convention so
``remediate`` reads exactly what ``scan`` wrote. Split into focused modules,
re-exported here so callers keep using
``from vvaharness.remediation_agent.report_parser import …`` unchanged:

  - :mod:`vvaharness.remediation_agent.report_parser.finding` — the ``Finding`` dataclass
  - :mod:`vvaharness.remediation_agent.report_parser.locate`  — folder names + report discovery
  - :mod:`vvaharness.remediation_agent.report_parser.parse`   — header parsing + done-marker
  - :mod:`vvaharness.remediation_agent.report_parser.fields`  — rich per-finding field extraction
"""
from __future__ import annotations

from vvaharness.remediation_agent.report_parser.finding import Finding  # noqa: F401
from vvaharness.remediation_agent.report_parser.locate import (  # noqa: F401
    SCAN_DIR_NAME, REMEDIATION_DIR_NAME, REPORT_GLOB,
    find_scan_dir, latest_report)
from vvaharness.remediation_agent.report_parser.parse import (  # noqa: F401
    DONE_MARKER, parse_findings, mark_done)
from vvaharness.remediation_agent.report_parser.fields import (  # noqa: F401
    parse_finding_fields)
from vvaharness.remediation_agent.report_parser.ids import (  # noqa: F401
    cvss_score_only, finding_id)


__all__ = [
    "Finding",
    "SCAN_DIR_NAME", "REMEDIATION_DIR_NAME", "REPORT_GLOB",
    "find_scan_dir", "latest_report",
    "DONE_MARKER", "parse_findings", "mark_done",
    "parse_finding_fields", "cvss_score_only", "finding_id",
]
