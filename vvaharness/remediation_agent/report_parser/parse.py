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

"""remediation_agent.report_parser.parse — finding-header parsing and the done-marker.

Finds the per-finding headers (``### N. [SEVERITY] title`` followed by a
``**File:** `path``` line) in a scan report's Markdown and turns them into
:class:`Finding` objects the remediation loop iterates over; also stamps the
invisible done-marker into the report once a finding is remediated."""
from __future__ import annotations

import re
from pathlib import Path

from vvaharness.remediation_agent.report_parser.finding import Finding

# Invisible (in rendered markdown) marker appended to a finding header once it
# has been remediated, so "done" is recorded in the report itself and survives
# across runs. HTML comments don't render, are trivial to detect, and the append
# is idempotent.
DONE_MARKER = "<!-- remediation-agent:done -->"

# Finding header, e.g. ``### 1. [CRITICAL] Stored JQL injection via …``.
# The trailing group optionally captures the done marker so parsing strips it
# from the title and records ``done``.
_HEADER_RE = re.compile(
    r"^###\s+(\d+)\.\s*\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]\s*(.+?)\s*"
    r"(<!--\s*remediation-agent:done\s*-->)?\s*$",
    re.IGNORECASE,
)
# The ``**File:** `routers/jira.py:174-174``` line emitted under each header.
_FILE_RE = re.compile(r"^\*\*File:\*\*\s*`([^`]+)`")


def parse_findings(md_text: str) -> list[Finding]:
    """Extract findings from a scan report's Markdown.

    Walks the lines, opening a new :class:`Finding` at each ``### N. [SEV] …``
    header and attaching the first ``**File:**`` line plus the full markdown
    block (header through the line before the next header) so the remediation
    agent receives the complete description / impact / exploit / fix guidance."""
    findings: list[Finding] = []
    current: Finding | None = None
    buf: list[str] = []

    def _flush() -> None:
        if current is not None:
            current.body = "\n".join(buf).strip()

    for line in md_text.splitlines():
        m = _HEADER_RE.match(line)
        if m:
            _flush()
            current = Finding(
                index=int(m.group(1)),
                severity=m.group(2).upper(),
                title=m.group(3).strip(),
                done=bool(m.group(4)),  # DONE_MARKER captured by the header regex
            )
            findings.append(current)
            buf = [line]
            continue
        if current is not None:
            buf.append(line)
            if current.file is None:
                fm = _FILE_RE.match(line.strip())
                if fm:
                    current.file = fm.group(1).strip()
    _flush()
    return findings


def mark_done(report_path: Path, finding: Finding) -> bool:
    """Append :data:`DONE_MARKER` to *finding*'s header line in *report_path*,
    in place. Idempotent (no-op if already marked). Returns True if the file was
    modified. Matches the header by index + severity so it targets exactly the
    right ``### N. [SEV] …`` line."""
    report_path = Path(report_path)
    text = report_path.read_text(encoding="utf-8")
    out: list[str] = []
    changed = False
    for line in text.splitlines():
        m = _HEADER_RE.match(line)
        if (m and int(m.group(1)) == finding.index
                and m.group(2).upper() == finding.severity
                and not m.group(4)):
            line = f"{line.rstrip()}  {DONE_MARKER}"
            changed = True
        out.append(line)
    if changed:
        trailing = "\n" if text.endswith("\n") else ""
        report_path.write_text("\n".join(out) + trailing, encoding="utf-8")
    return changed
