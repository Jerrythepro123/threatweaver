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

"""remediation_agent — remediation subpackage.

Consumes the scan artefacts under ``<repo>/security-scan/`` and walks the
reported findings, applying (eventually) per-finding remediation. The public
entry point is :func:`remediate`, invoked by ``vvaharness remediate``.
"""
from __future__ import annotations

from vvaharness.remediation_agent.remediate import remediate  # noqa: F401
from vvaharness.remediation_agent.options import (  # noqa: F401
    RemediateOptions, parse_options, VALID_MODES)
from vvaharness.remediation_agent.discovery import (  # noqa: F401
    Layout, locate_report, load_findings, prepare_layout, cvss_score_of)
from vvaharness.remediation_agent.runner import (  # noqa: F401
    model_banner, remediate_one, process_findings)
from vvaharness.remediation_agent.select import (  # noqa: F401
    parse_top_arg, select_top_by_cvss, select_top_logged, band_score,
    cfg_top_n_findings, resolve_top)
from vvaharness.remediation_agent.plugin_runner import apply_plugin  # noqa: F401
from vvaharness.remediation_agent.models import RemediationVerdict  # noqa: F401
from vvaharness.remediation_agent.report_parser import (  # noqa: F401
    Finding, REMEDIATION_DIR_NAME, SCAN_DIR_NAME, DONE_MARKER,
    find_scan_dir, latest_report, parse_findings, mark_done)
from vvaharness.remediation_agent.interactive import (  # noqa: F401
    run_interactive, parse_selection, decode_key, render_rows)



