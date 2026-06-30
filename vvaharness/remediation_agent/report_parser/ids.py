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

"""remediation_agent.report_parser.ids — stable finding id + cheap CVSS extraction.

:func:`cvss_score_only` is the fast path for ``--top N`` selection (it scans for
just the CVSS line); :func:`finding_id` derives a stable, reproducible
``<hash6>-<class>-<file>-<line>`` id. Both kept separate from the heavier
section-splitting field extraction in :mod:`…report_parser.fields`."""
from __future__ import annotations

import hashlib
import re

from vvaharness.remediation_agent.report_parser.finding import Finding
from vvaharness.remediation_agent.report_parser.field_sections import _CVSS_SCORE_RE
from vvaharness.remediation_agent.report_parser.fields import parse_finding_fields


def cvss_score_only(finding: Finding) -> float | None:
    """Cheaply extract just the numeric CVSS base score from a finding's
    markdown ``body``, or ``None`` when the report rendered only a vector / a
    bare severity band.

    This is a fast path for ``--top N`` selection: it scans line-by-line for the
    ``**CVSS 3.1:** **<score>** (…)`` line and stops at the first match, instead
    of running the full :func:`parse_finding_fields` (which section-splits the
    whole block). Selection only needs the score, so the heavier parse is
    deferred to the findings that actually get remediated."""
    for line in (finding.body or "").splitlines():
        m = _CVSS_SCORE_RE.match(line.strip())
        if m:
            return float(m.group(1))
    return None


def finding_id(finding: Finding) -> str:
    """Stable, human-readable id for a finding: ``<hash6>-<class>-<file>-<line>``,
    e.g. ``a3f2c1-injection-app/db/users.py-142``. The 6-char hash disambiguates
    findings that share a file/line, and is derived from the title + location so
    it is reproducible across runs."""
    fields = parse_finding_fields(finding)
    vc = (fields["vuln_class"] or "finding").split(":")[0].strip()
    vc = re.sub(r"^CWE-\d+\s*", "", vc) or "finding"
    file_path = fields["file"] or "unknown"
    line = fields["line_start"] or 0
    seed = f"{finding.title}|{file_path}|{line}".encode("utf-8")
    h = hashlib.sha1(seed).hexdigest()[:6]
    return f"{h}-{vc}-{file_path}-{line}"
