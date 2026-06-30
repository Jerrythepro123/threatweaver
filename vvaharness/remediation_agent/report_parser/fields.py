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

"""remediation_agent.report_parser.fields — rich per-finding field extraction.

Pulls the verbatim scan ``Finding`` fields (title, class/CWE, file/line, CVSS,
description, recommendation, etc.) out of a finding's markdown ``body`` into a
dict shaped like the scan pipeline's ``Finding`` — the ``finding`` block of the
remediation report. The inline metadata regexes + ``#### Heading`` section
splitter live in the sibling
:mod:`vvaharness.remediation_agent.report_parser.field_sections` module, and the
``finding_id`` / ``cvss_score_only`` helpers in
:mod:`vvaharness.remediation_agent.report_parser.ids`, so this file stays
focused on assembling the finding dict."""
from __future__ import annotations

import re

from vvaharness.remediation_agent.report_parser.finding import Finding
from vvaharness.remediation_agent.report_parser.field_sections import (
    _CLASS_RE, _CONF_RE, _CVSS_SCORE_RE, _CVSS_VECONLY_RE, _CWE_RE, _VERDICT_RE,
    _file_loc, _first_code_block, _sections)



def parse_finding_fields(finding: Finding) -> dict:
    """Extract the verbatim Finding fields (title, class, file/line, CVSS,
    description, recommendation, etc.) from a finding's markdown ``body`` into
    a dict shaped like the scan pipeline's ``Finding`` — the ``finding`` block
    of the remediation report. Missing fields degrade to safe empty defaults so
    a partially-rendered report never breaks report generation.

    Note: ``source_ref``/``sink_ref`` are not rendered into the scan Markdown,
    so they are reported as ``null`` here."""
    body = finding.body or ""
    secs = _sections(body)
    head = secs.get("", "")

    vuln_class = ""
    cwe = None
    file_ref = finding.file or ""
    file_path, line_start, line_end = _file_loc(file_ref) if file_ref else ("", 0, 0)
    confidence = 0.0
    votes = 0
    cvss_vector = cvss_rating = None
    cvss_score = None
    verdict = None
    verdict_confidence = None

    for line in head.splitlines():
        line = line.strip()
        if (m := _CLASS_RE.match(line)):
            vuln_class = m.group(1).strip()
        elif (m := _CWE_RE.match(line)):
            cwe = m.group(1).strip()
        elif (m := _CONF_RE.match(line)):
            confidence = float(m.group(1))
            votes = int(m.group(2))
        elif (m := _CVSS_SCORE_RE.match(line)):
            cvss_score = float(m.group(1))
            cvss_rating = m.group(2).strip()
            cvss_vector = m.group(3).strip()
        elif (m := _CVSS_VECONLY_RE.match(line)):
            cvss_vector = m.group(1).strip()

    # `**Class:**` may itself carry the CWE (e.g. "CWE-89: SQL Injection" or a
    # bare "CWE-943") when no dedicated `**CWE:**` line was rendered.
    if cwe is None and vuln_class:
        cm = re.match(r"(CWE-\d+)", vuln_class)
        if cm:
            cwe = cm.group(1)

    # The adversarial-verification block carries the verdict line.
    verify = secs.get("adversarial verification", "")
    for line in verify.splitlines():
        vm = _VERDICT_RE.match(line.strip())
        if vm:
            verdict = vm.group(1).strip()
            verdict_confidence = int(vm.group(2))
            break

    preconds = [
        re.sub(r"^[-*]\s+", "", ln).strip()
        for ln in secs.get("preconditions", "").splitlines()
        if ln.strip().startswith(("-", "*"))
    ]

    return {
        "_source": "vvaharness s8 (verbatim Finding fields)",
        "title": finding.title,
        "vuln_class": vuln_class,
        "cwe": cwe,
        "file": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "source_ref": None,
        "sink_ref": None,
        "description": secs.get("description", ""),
        "recommendation": secs.get("how to fix", ""),
        "code_snippet": _first_code_block(body),
        "impact": secs.get("impact", ""),
        "exploit_scenario": secs.get("exploit scenario", ""),
        "preconditions": preconds,
        "confidence": confidence,
        "votes": votes,
        "verdict": verdict,
        "verdict_confidence": verdict_confidence,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "cvss_rating": cvss_rating,
    }

