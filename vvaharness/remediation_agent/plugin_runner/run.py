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

"""remediation_agent.plugin_runner.run — the per-finding apply_plugin orchestration.

Wires the policy pre-gate, the model call, verdict coercion, the policy
post-gate, and artefact persistence together for one finding. The model seam
(``_invoke`` → ``agentic``) is looked up on the package
(:mod:`vvaharness.remediation_agent.plugin_runner`) so tests that monkeypatch
``plugin_runner._invoke`` / ``plugin_runner.agentic`` keep working unchanged."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.remediation_agent import artifacts
from vvaharness.remediation_agent import policy as _policy
from vvaharness.remediation_agent.report_parser import Finding


def apply_plugin(finding: Finding, out_dir: Path, *, cfg, repo: Path,
                 mode: str = "fix", verbose: bool = False,
                 policy_ctx=None) -> dict:
    """Run the remediation agent for one *finding* and persist its artefacts.

    When *policy_ctx* (a :class:`vvaharness.remediation_agent.policy.PolicyContext`)
    is supplied and enabled, the deterministic gate runs before and after the
    model call: a denied CWE/path is short-circuited to guidance (no model call),
    and a patch that touches forbidden/sensitive paths is reverted on disk before
    artefacts are written.

    When *verbose*, the prompt and raw model response are echoed to stderr.
    Returns a small JSON-serialisable record the orchestrator stores in the
    per-finding checkpoint."""
    # Resolve the model seam + verbose dumps on the package so monkeypatched
    # ``plugin_runner._invoke`` / ``plugin_runner.agentic`` are honoured.
    from vvaharness.remediation_agent import plugin_runner as _pr

    ts = datetime.now(timezone.utc).isoformat()
    meta = {
        "severity": finding.severity,
        "title": finding.title,
        "file": finding.file,
        "mode": mode,
        "generated": ts,
    }

    enforce = policy_ctx is not None and getattr(policy_ctx, "enabled", False)
    pre = _policy.pre_decision(policy_ctx, finding) if enforce else None

    # Verbose: surface the policy decision + resolved playbook strategy that was
    # ingested for this finding (covers both the DENY and ALLOW paths below).
    # When enforcement is OFF there is no policy decision and NO playbook
    # strategy injected — say so explicitly so the absence of the POLICY /
    # PLAYBOOK blocks is never ambiguous (and point at the toggle).
    if verbose:
        if enforce and pre is not None:
            _pr._dump_policy(finding, pre)
        else:
            print(f"    [policy] enforcement disabled "
                  f"(step_remediate.enforce_policy=false) — no policy gate or "
                  f"playbook strategy injected for finding {finding.index}",
                  file=sys.stderr)

    # ── Pre-gate DENY: skip the agent entirely, emit guidance, no tokens. ──
    if enforce and pre is not None and not pre.allowed:
        verdict = _policy.guidance_verdict(policy_ctx, finding, pre)
        meta["policy_action"] = pre.decision.action.value
        meta["policy_reason"] = pre.decision.reason
        meta["final_verdict"] = "REJECT"
        artifacts.write_verdict(out_dir, verdict, meta=meta, repo=repo,
                                finding=finding, before_snapshot={})
        print(f"    [policy] pre-gate guidance-only for finding "
              f"{finding.index} ({pre.decision.reason}) — agent skipped",
              file=sys.stderr)
        return {
            "finding_index": finding.index,
            "artifact_dir": str(out_dir),
            "verdict": verdict.verdict,
            **meta,
        }

    # Snapshot the finding's file BEFORE the agent edits it so a unified diff
    # can be synthesized for non-git targets (where there is no HEAD to diff
    # against) and so the post-gate can restore an exact pre-edit baseline.
    snap_targets = [finding.file] if finding.file else []
    # F13: when the policy gate is enforced, ALSO snapshot every working-tree
    # file matching the gate's forbid_patch_paths/deny_paths up-front. On a
    # non-git target the post-gate has no git baseline to restore from, so if
    # the agent makes an off-book edit to a forbidden build script (omitting it
    # from verdict.changes) the revert needs this pre-edit snapshot to roll it
    # back. (On a git target this is redundant with `git checkout`, but cheap
    # and harmless.)
    if enforce and policy_ctx is not None:
        gate = getattr(policy_ctx, "gate", None)
        patterns = ([*getattr(gate, "forbid_patch_paths", []),
                     *getattr(gate, "deny_paths", [])] if gate else [])
        snap_targets = list(dict.fromkeys(
            [*snap_targets, *_policy.worktree_forbidden_matches(repo, patterns)]))
    before = artifacts.snapshot_files(repo, snap_targets)

    # When policy is off, call _invoke with its original positional signature so
    # existing monkeypatched seams (which don't accept pre/ctx) keep working.
    if enforce:
        raw = _pr._invoke(finding, cfg, repo, mode, verbose, pre=pre, ctx=policy_ctx)
    else:
        raw = _pr._invoke(finding, cfg, repo, mode, verbose)
    verdict = _pr._coerce_verdict(raw, finding)

    # ── Post-gate: inspect the diff, revert forbidden-path edits on disk. ──
    if enforce and pre is not None:
        post = _policy.enforce_post(policy_ctx, finding, verdict, pre,
                                    repo=repo, before_snapshot=before)
        meta["policy_action"] = pre.decision.action.value
        meta["policy_reason"] = pre.decision.reason
        meta["final_verdict"] = post.final_verdict
        if post.reverted:
            meta["policy_reverted"] = post.reverted
            meta["policy_matched_globs"] = post.matched_globs

    artifacts.write_verdict(out_dir, verdict, meta=meta, repo=repo,
                            finding=finding, before_snapshot=before)

    return {
        "finding_index": finding.index,
        "artifact_dir": str(out_dir),
        "verdict": verdict.verdict,
        **meta,
    }
