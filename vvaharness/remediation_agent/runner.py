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

"""remediation_agent.runner — the per-finding processing loop.

The sequential walk that drives one finding at a time through
``plugin_runner.apply_plugin`` and checkpoints each result. Kept separate from
:mod:`vvaharness.remediation_agent.remediate` (the thin orchestrator) and
:mod:`vvaharness.remediation_agent.discovery` (input handling) so the
agent-driving logic is small and independently testable."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from vvaharness.report.redact import redact
from vvaharness.util.status import stage
from vvaharness.backends.llm import resolve as resolve_model
from vvaharness.orchestrator.checkpoints import save_ckpt, load_ckpt
from vvaharness.remediation_agent.plugin_runner import apply_plugin
from vvaharness.remediation_agent.report_parser import Finding
from vvaharness.remediation_agent.discovery import Layout
from vvaharness.remediation_agent.options import RemediateOptions
from vvaharness.remediation_agent import policy as _policy


def model_banner(cfg) -> str:
    """One-line description of the model/backend doing remediation."""
    try:
        mid, via, _ = resolve_model(cfg.models.remediate)
        return f"{mid} [{via}]"
    except Exception:  # noqa: BLE001 — banner is best-effort only
        return "unknown"


def _finding_identity(finding: Finding) -> str:
    """Content hash binding a checkpoint to the EXACT finding it remediated.

    The resume key is position-only — ``run_id`` is the repo PATH hash and
    ``step`` is the ordinal ``remediate_<index>`` — so a bare ``(run_id, step)``
    hit proves nothing about *which* finding was remediated. Hashing the
    finding's stable content (ordinal + title + file + body) lets
    :func:`remediate_one` verify a loaded checkpoint actually belongs to THIS
    finding before skipping it, closing the existence-implies-done gap:
    a stale checkpoint from a prior run on the same path whose findings have
    since reordered, or an attacker-seeded state DB, no longer suppresses a real
    remediation while the run reports it processed."""
    h = hashlib.sha256()
    for part in (str(finding.index), finding.title or "",
                 finding.file or "", finding.body or ""):
        h.update(part.encode("utf-8", "replace"))
        h.update(b"\x00")
    return h.hexdigest()


def remediate_one(finding: Finding, *, idx: int, total: int, layout: Layout,
                  cfg, repo_path: Path, opts: RemediateOptions,
                  policy_ctx=None) -> bool:
    """Process a single finding: skip-if-cached (resume), otherwise run the
    agent and checkpoint the result. Returns True when the finding is counted
    as processed (cached or freshly remediated), False on failure.

    One bad finding never aborts the run — the exception is logged and we move
    on to the next finding."""
    label = redact(finding.label)
    out_dir = layout.rem_dir / finding.slug
    step = f"remediate_{finding.index}"
    fid = _finding_identity(finding)

    # Resume: skip a finding ONLY when a checkpoint exists AND its recorded
    # finding identity matches the current finding. Existence alone is not proof
    # of completion: the key is path+ordinal only, so a mismatched or
    # identity-less record (stale prior run, reordered findings, tampered state
    # DB) must re-run, not silently count as done. Same-run continuation still
    # matches its own ``fid`` and skips.
    if opts.resume:
        cached = load_ckpt(layout.ckpt_dir, layout.run_id, step)
        if isinstance(cached, dict) and cached.get("finding_id") == fid:
            with stage(f"{label} — cached", n=idx, total=total):
                pass
            return True

    try:
        # Spinner on for clarity; disabled only in verbose mode where the live
        # agent trace streams many stderr lines that would otherwise shred an
        # in-place spinner.
        with stage(label, n=idx, total=total, animate=not opts.verbose):
            record = apply_plugin(finding, out_dir, cfg=cfg, repo=repo_path,
                                  mode=opts.mode, verbose=opts.verbose,
                                  policy_ctx=policy_ctx)
            # Bind the finding identity into the checkpoint so a later --resume
            # can authenticate it (see _finding_identity).
            if isinstance(record, dict):
                record["finding_id"] = fid
            save_ckpt(layout.ckpt_dir, layout.run_id, step, record)
        return True
    except Exception as e:  # noqa: BLE001 — one bad finding shouldn't abort
        print(f"    WARN: remediation failed for finding {finding.index} "
              f"({redact(str(e))}); continuing.", file=sys.stderr)
        return False


def process_findings(findings: list[Finding], *, layout: Layout, cfg,
                     repo_path: Path, opts: RemediateOptions,
                     report: Path | None = None) -> int:
    """Walk *findings* sequentially, remediating each one. Returns a process
    exit code: 0 when every finding was processed, 1 otherwise.

    *report* is the canonical scan Markdown report these findings were parsed
    from; it is threaded into report augmentation so the combined report binds to
    the exact file this run processed rather than a tamperable newest-wins glob
    (MV-06)."""
    total = len(findings)

    # Build the policy context once per run (gate + playbook from the shipped
    # rules, frameworks detected from the repo). No-op unless
    # step_remediate.enforce_policy is true.
    policy_ctx = _policy.build_context(cfg, repo_path)
    if policy_ctx.enabled:
        print("  [Remediation Agent] policy gate ENABLED "
              "(deny-list + playbook + diff post-gate)", file=sys.stderr)
    fixed = sum(
        remediate_one(finding, idx=i, total=total, layout=layout, cfg=cfg,
                      repo_path=repo_path, opts=opts, policy_ctx=policy_ctx)
        for i, finding in enumerate(findings, start=1)
    )
    print(f"\n  ✓ {fixed}/{total} findings processed", file=sys.stderr)
    # Copy the scan's MD + SARIF into security-remediation/ and annotate each
    # finding with its remediation result (best-effort — never fails the run).
    from vvaharness.remediation_agent.report_augment import augment_reports
    augment_reports(repo_path, report)
    return 0 if fixed == total else 1


