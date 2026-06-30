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

"""remediation_agent.artifacts — render and persist a remediation verdict to disk.

Pure I/O + formatting, isolated from the model call (``plugin_runner``) and the
prompt text (``prompts``). Split into focused modules, re-exported here so
callers keep using ``from vvaharness.remediation_agent import artifacts; artifacts.write_verdict(...)``
unchanged:

  - :mod:`vvaharness.remediation_agent.artifacts.layout`     — file/folder names + constants
  - :mod:`vvaharness.remediation_agent.artifacts.summary`    — human-readable summary.md
  - :mod:`vvaharness.remediation_agent.artifacts.diff`       — git-diff capture
  - :mod:`vvaharness.remediation_agent.artifacts.validation` — the empty s11 validation block
  - :mod:`vvaharness.remediation_agent.artifacts.report`     — the canonical remediate_report.json
  - :mod:`vvaharness.remediation_agent.artifacts.writer`     — orchestrates the on-disk layout

Per-finding layout::

    <rem_dir>/<NN_slug>/
        remediate_report.json     # the canonical, schema-versioned record
        evidence/
            triage.json           # raw structured verdict + meta (redacted)
            summary.md            # human-readable report (redacted)
            diff.patch            # unified git diff of exactly what changed
"""
from __future__ import annotations

from vvaharness.remediation_agent.artifacts.layout import (  # noqa: F401
    EVIDENCE_DIR, TRIAGE_JSON, SUMMARY_MD, DIFF_PATCH,
    REMEDIATE_REPORT_JSON, SCHEMA_VERSION, DEFAULT_MAX_ATTEMPTS)
from vvaharness.remediation_agent.artifacts.summary import render_summary  # noqa: F401
from vvaharness.remediation_agent.artifacts.diff import (  # noqa: F401
    capture_git_diff, synth_unified_diff, snapshot_files)
from vvaharness.remediation_agent.artifacts.validation import empty_validation  # noqa: F401
from vvaharness.remediation_agent.artifacts.report import build_report, status_for  # noqa: F401
from vvaharness.remediation_agent.artifacts.writer import write_verdict  # noqa: F401

__all__ = [
    "EVIDENCE_DIR", "TRIAGE_JSON", "SUMMARY_MD", "DIFF_PATCH",
    "REMEDIATE_REPORT_JSON", "SCHEMA_VERSION", "DEFAULT_MAX_ATTEMPTS",
    "render_summary", "capture_git_diff", "synth_unified_diff",
    "snapshot_files", "empty_validation",
    "build_report", "status_for", "write_verdict",
]

