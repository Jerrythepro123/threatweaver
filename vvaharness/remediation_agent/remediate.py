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

"""remediation_agent.remediate — drive remediation from an existing scan report.

`vvaharness remediate --repo <path>` reads the artefacts a prior
`vvaharness scan` wrote under ``<repo>/security-scan/``, parses the findings out
of the newest Markdown report, and walks them one-by-one. The per-step output
reuses the SAME ``util.status.stage`` renderer the scan pipeline uses
(``▶ [n/total] … / ✓ … (Ns)``) so the CLI look is identical.

For each finding the remediation method (``plugin_runner.apply_plugin``) runs
through the harness's own backend dispatcher on the configured
``models.remediate`` role, writing artefacts into a dedicated per-finding folder
under ``<repo>/security-remediation/<NN_slug>/`` — a canonical
``remediate_report.json`` at the folder root plus an ``evidence/`` subfolder
(``triage.json`` + ``summary.md`` + ``diff.patch``). Progress is checkpointed
per finding using the SAME hardened engine AND the SAME ``<repo>/checkpoints``
folder as the scan pipeline (``orchestrator.checkpoints``), so ``--resume``
skips completed findings and scan + remediation state live together.

This file is intentionally a *thin orchestrator*. Each concern lives in its own
small, independently testable module:

  * :mod:`vvaharness.remediation_agent.options`   — CLI flag parsing.
  * :mod:`vvaharness.remediation_agent.discovery` — report location + finding
    selection (top-N cap) + per-repo output/checkpoint layout.
  * :mod:`vvaharness.remediation_agent.runner`    — the per-finding loop.
  * :mod:`vvaharness.remediation_agent.select`    — shared "top N by CVSS" PQ.

The top-N cap is *profile-driven*: it comes from ``step_remediate.top_n_findings``
in the active profile and can be overridden ad-hoc with ``--top N``
(:func:`vvaharness.remediation_agent.select.resolve_top`).
"""

from __future__ import annotations

import sys
from pathlib import Path

from vvaharness.remediation_agent.options import parse_options
from vvaharness.remediation_agent.discovery import (
    locate_report, load_findings, prepare_layout)
from vvaharness.remediation_agent.runner import model_banner, process_findings
from vvaharness.remediation_agent.select import resolve_top


def remediate(repo: str | None, args=None, cfg=None) -> int:
    """Entry point for the ``remediate`` command.

    *cfg* is the loaded harness Config (the CLI resolves ``--config`` and passes
    it in). Returns a process exit code: 0 on success, non-zero when ``--repo``
    is missing/invalid, no scan output exists, or no config was provided.

    This is a thin orchestrator — each concern lives in its own helper module."""
    if not repo:
        print("usage: vvaharness remediate --repo <path>", file=sys.stderr)
        return 2
    if cfg is None:
        print("  ✗ no config loaded — internal error: remediate() requires cfg.",
              file=sys.stderr)
        return 2

    try:
        opts = parse_options(args or [])
    except ValueError as e:
        print(f"  ✗ {e}", file=sys.stderr)
        return 2

    repo_path = Path(repo)
    if not repo_path.exists():
        print(f"  ✗ no such path: {repo}", file=sys.stderr)
        return 1

    report, rc = locate_report(repo_path)
    if report is None:
        return rc

    # Top-N cap: profile's step_remediate.top_n_findings is the source of truth;
    # --top N (opts.top) overrides it ad-hoc for this run.
    #
    # Interactive mode is a manual picker — the user chooses which findings to
    # remediate row-by-row, so a profile cap must NOT silently pre-truncate the
    # list (that would hide findings the user might want to act on). We therefore
    # ignore the profile cap in interactive mode and show the FULL list, while
    # still honoring an explicit ``--top N`` the user typed on the CLI for this
    # run (opts.top is not None).
    if opts.interactive and opts.top is None:
        top = None
    else:
        top = resolve_top(opts.top, cfg)
    print(f"  [Remediation Agent] report: {report}", file=sys.stderr)
    findings = load_findings(report, top)

    n = len(findings)
    if n == 0:
        print("  ✓ identified 0 SAST issue(s) — nothing to remediate.",
              file=sys.stderr)
        return 0

    layout = prepare_layout(repo_path)
    print(f"  identified {n} SAST issue(s) to remediate", file=sys.stderr)
    print(f"  [Remediation Agent] model: {model_banner(cfg)}  mode={opts.mode}",
          file=sys.stderr)
    print(f"  [Remediation Agent] artefacts → {layout.rem_dir}", file=sys.stderr)
    if opts.verbose:
        print("  [Remediation Agent] verbose: printing prompt + raw LLM response "
              "per finding", file=sys.stderr)

    # Interactive: let the user pick which issues to remediate, exit anytime.
    if opts.interactive:
        from vvaharness.remediation_agent.interactive import run_interactive
        return run_interactive(findings, report_path=report,
                               rem_dir=layout.rem_dir, ckpt_dir=layout.ckpt_dir,
                               run_id=layout.run_id, cfg=cfg, mode=opts.mode,
                               verbose=opts.verbose)

    return process_findings(findings, layout=layout, cfg=cfg,
                            repo_path=repo_path, opts=opts, report=report)

