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

"""remediation_agent.artifacts.writer — orchestrate the per-finding on-disk layout.

Ties the renderer (summary), diff capture, and report builder together and
writes the redacted files to disk in the canonical layout."""
from __future__ import annotations

import json
from pathlib import Path

from vvaharness.report.redact import redact, redact_tree

from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.report_parser import Finding
from vvaharness.remediation_agent.artifacts.layout import (
    EVIDENCE_DIR, TRIAGE_JSON, SUMMARY_MD, DIFF_PATCH,
    REMEDIATE_REPORT_JSON, DEFAULT_MAX_ATTEMPTS)
from vvaharness.remediation_agent.artifacts.summary import render_summary
from vvaharness.remediation_agent.artifacts.diff import capture_git_diff, synth_unified_diff
from vvaharness.remediation_agent.artifacts.report import build_report


def write_verdict(out_dir: Path, verdict: RemediationVerdict, *, meta: dict,
                  repo: Path | None = None,
                  finding: Finding | None = None,
                  before_snapshot: dict[str, str | None] | None = None,
                  attempt: int = 1,
                  max_attempts: int = DEFAULT_MAX_ATTEMPTS) -> None:
    """Persist a remediation result under *out_dir*.

    Writes the canonical, schema-versioned ``remediate_report.json`` at the
    per-finding root, and the supporting evidence (``triage.json``,
    ``summary.md``, and — when *repo* is given and the verdict reports changed
    files — ``diff.patch``) into an ``evidence/`` subfolder. All file contents
    are redacted. ``remediate_report.json`` is only emitted when *finding* is
    supplied (it carries the verbatim scan fields the schema requires).

    Diff capture prefers a real ``git diff`` (when *repo* is a git work tree).
    For **non-git** targets it falls back to a synthesized unified diff built
    from *before_snapshot* (the pre-edit file contents the runner captured), so
    a ``diff.patch`` is produced regardless of version control."""
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = out_dir / EVIDENCE_DIR
    evidence_dir.mkdir(parents=True, exist_ok=True)
    payload = {**verdict.model_dump(), **meta}

    diff = None
    if repo is not None:
        changed = [c.file for c in verdict.changes]
        diff = capture_git_diff(repo, changed)
        # Non-git target (or git produced nothing): synthesize a diff from the
        # pre-edit snapshot the runner captured so we always emit a patch.
        if not diff and before_snapshot is not None:
            diff = synth_unified_diff(repo, before_snapshot,
                                      extra_files=changed)
    payload["diff_captured"] = bool(diff)


    # JSON artifacts: redact every string leaf BEFORE serialising (redact_tree),
    # so the json encoder owns all escaping. Redacting the already-serialised
    # JSON string would let a secret pattern match across JSON quotes/escapes
    # and corrupt them, producing a file that no longer parses (and that the
    # report augmenter then logs as "could not read remediation DTO").
    (evidence_dir / TRIAGE_JSON).write_text(
        json.dumps(redact_tree(payload), indent=2), encoding="utf-8")
    # summary.md and diff.patch are plain text, not JSON — redact the rendered
    # string directly.
    (evidence_dir / SUMMARY_MD).write_text(
        redact(render_summary(verdict, meta=meta)), encoding="utf-8")
    if diff:
        (evidence_dir / DIFF_PATCH).write_text(redact(diff), encoding="utf-8")

    if finding is not None:
        report = build_report(finding, verdict, meta=meta, diff=diff,
                              attempt=attempt, max_attempts=max_attempts)
        (out_dir / REMEDIATE_REPORT_JSON).write_text(
            json.dumps(redact_tree(report), indent=2), encoding="utf-8")

