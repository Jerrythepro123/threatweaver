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

"""remediation_agent.policy.postgate — enforce path policy on the generated diff.

:func:`enforce_post` inspects what ACTUALLY changed on disk after the agent ran,
reverts only the files that hit ``forbid_patch_paths``/``deny_paths`` (keeping
legitimate edits), strips them from ``verdict.changes`` so the recomputed
``diff.patch`` reflects the reverted state, and downgrades the verdict to
guidance when anything was reverted."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff import (_norm_path,
                                                         capture_git_diff,
                                                         changed_files_whole_tree,
                                                         synth_unified_diff)
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.policy_gate import cap_verdict, inspect_diff
from vvaharness.remediation_agent.policy_gate.matching import _glob_match

from vvaharness.remediation_agent.policy.context import PolicyContext
from vvaharness.remediation_agent.policy.decide import PreResult
from vvaharness.remediation_agent.policy.revert import revert_files
from vvaharness.remediation_agent.report_parser import Finding

# Cap the worktree glob (non-git fallback) so a huge target can't pin the
# post-gate. Generous enough to cover any real source tree's forbidden files.
_WORKTREE_SCAN_MAX = 20000


def worktree_forbidden_matches(repo: Path, patterns: list[str]) -> list[str]:
    """Return repo-relative files in *repo*'s working tree that hit any of
    *patterns* (``forbid_patch_paths`` ∪ ``deny_paths``).


    Used only as the **non-git** fallback for the post-gate: a git target gets
    its full changed-file set from ``changed_files_whole_tree``, but a non-git
    target has no such ground truth, so a forbidden file the agent edited but
    OMITTED from ``verdict.changes`` would never be seen. Walking the tree for
    pattern hits restores coverage parity (F13/MV-03). Best-effort: never raises;
    bounded by :data:`_WORKTREE_SCAN_MAX`."""
    if not patterns:
        return []
    repo = Path(repo)
    out: list[str] = []
    seen = 0
    try:
        for p in repo.rglob("*"):
            if not p.is_file():
                continue
            # Count only FILES toward the budget. rglob('*') also yields
            # directories; counting them before this filter let vendored dirs
            # (node_modules/.venv) consume the cap and silently lower the
            # forbidden-FILE coverage ceiling, so an agent-omitted forbidden
            # file past the truncation point went undiscovered/unreverted (RV2).
            seen += 1
            if seen > _WORKTREE_SCAN_MAX:
                break
            try:
                rel = p.relative_to(repo).as_posix()
            except ValueError:
                continue
            for pat in patterns:
                if _glob_match(rel, pat):
                    out.append(rel)
                    break
    except Exception:  # noqa: BLE001 — a best-effort scan must never break a run
        return out
    return out



@dataclass
class PostResult:
    """Outcome of the post-gate after the agent edited files."""
    reverted: list[str]          # repo-relative files reverted on disk
    matched_globs: list[str]     # the policy globs that triggered the revert
    downgraded: bool             # True if the verdict was forced to REJECT
    final_verdict: str           # ACCEPT | REJECT


def _gates_ok(verdict: RemediationVerdict) -> bool:
    """True iff ALL three evidence gates in the agent's own verdict read 'pass'.

    F40: the clean post-gate path must derive the final ACCEPT/REJECT label from
    the verdict's gate evidence — not assume success. A 'partial'/'fail' on any
    gate means the agent did not fully substantiate the fix, so the audit label
    is REJECT even when nothing was reverted."""
    g = getattr(verdict, "gates", None)
    if g is None:
        return False
    return (g.source == "pass" and g.sink == "pass"
            and g.missing_control == "pass")


def enforce_post(ctx: PolicyContext, finding: Finding,
                 verdict: RemediationVerdict, pre: PreResult, *,
                 repo: Path,
                 before_snapshot: dict[str, str | None] | None = None,
                 all_gates_passed: bool = True) -> PostResult:
    """Inspect the generated diff and enforce path policy on what ACTUALLY
    changed on disk.

    Reverts ONLY the files that hit ``forbid_patch_paths``/``deny_paths``
    (keeping legitimate edits), strips them from ``verdict.changes`` so the
    caller's recomputed ``diff.patch`` reflects the reverted state, and downgrades
    the verdict to guidance when anything was reverted. Mutates *verdict* in
    place; returns a :class:`PostResult` for the audit record."""
    changed = [c.file for c in verdict.changes if c.file]

    # Observe the WHOLE working tree, not just what the agent reported. An edit
    # to a forbidden/sensitive file that the agent omits from ``verdict.changes``
    # (whether by mistake or to evade the gate) would otherwise never be seen and
    # never reverted (MV-03). ``changed_files_whole_tree`` returns git's full
    # modified/added/deleted/untracked set; we union it with the agent's
    # self-reported changes and the scoped diff's files.
    whole_tree = changed_files_whole_tree(repo)

    # Non-git fallback (F13): ``changed_files_whole_tree`` returns [] for a
    # non-git target, so an agent-omitted forbidden file would never surface.
    # Walk the working tree for files matching the gate's forbidden/sensitive
    # globs so those are still discovered and reverted even off the git path.
    # (On a git target whole_tree is authoritative, so we skip the scan.)
    worktree_forbidden: list[str] = []
    if not whole_tree:
        worktree_forbidden = worktree_forbidden_matches(
            repo, [*ctx.gate.forbid_patch_paths, *ctx.gate.deny_paths])

    # Inspect the real diff's changed-file set (ground truth) when we can build
    # one; union with the agent's self-reported changes for robustness. Scope the
    # diff to the union of reported + whole-tree paths so omitted files still
    # render into the synthesized (non-git) diff baseline.
    diff_scope = list(dict.fromkeys([*changed, *whole_tree]))
    diff = capture_git_diff(repo, diff_scope)
    if not diff and before_snapshot is not None:
        diff = synth_unified_diff(repo, before_snapshot, extra_files=diff_scope)
    diff_files = inspect_diff(diff)
    candidates = list(dict.fromkeys(
        [*diff_files, *changed, *whole_tree, *worktree_forbidden]))

    bad = ctx.gate.forbidden_files(candidates)
    matched: list[str] = []
    for f in bad:
        g = (ctx.gate.patch_touches_forbidden([f])
             or ctx.gate.changed_paths_hit_deny([f]))
        if g:
            matched.append(g)

    ceiling = pre.decision.action
    if not bad:
        # F40: derive the gate status from the agent's OWN verdict.gates rather
        # than trusting the caller's default-True flag. The clean-path audit
        # label is ACCEPT only when the action permitted a patch AND every
        # evidence gate the agent reported reads 'pass'.
        gates_passed = all_gates_passed and _gates_ok(verdict)
        return PostResult(reverted=[], matched_globs=[], downgraded=False,
                          final_verdict=cap_verdict(ceiling, gates_passed))

    reverted = revert_files(repo, bad, before_snapshot)
    bad_norm = {_norm_path(f) for f in bad}
    verdict.changes = [c for c in verdict.changes
                       if _norm_path(c.file) not in bad_norm]

    note = (f"Policy post-gate reverted {len(reverted)} file(s) that touched "
            f"forbidden/sensitive paths ({', '.join(sorted(set(matched)))}): "
            f"{', '.join(reverted)}. These edits were rolled back on disk; "
            f"route to a human.")
    verdict.remaining_risks = list(verdict.remaining_risks) + [note]
    # Post-gate revert is a PARTIAL outcome: legitimate edits are kept and only
    # the forbidden/sensitive-path edits were rolled back, so route to a human
    # for review rather than marking the whole finding Denied (the pre-gate
    # deny path owns the terminal Denied state).
    if verdict.verdict in ("Fixed", "Partially Fixed"):
        verdict.verdict = "Needs Review"
    verdict.summary = (verdict.summary + " " if verdict.summary else "") + note
    print(f"    [policy] post-gate reverted {len(reverted)} forbidden-path "
          f"edit(s): {', '.join(reverted)}", file=sys.stderr)
    return PostResult(reverted=reverted, matched_globs=sorted(set(matched)),
                      downgraded=True, final_verdict="REJECT")
