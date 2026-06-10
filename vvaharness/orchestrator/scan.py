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
from __future__ import annotations
"""orchestrator.scan — see package docstring."""
import copy
import sys
import time
from pathlib import Path
from vvaharness import config as config_mod
from vvaharness.injectors.cve_feed import load_cves
from vvaharness.injectors.design_controls import load_controls
from vvaharness.models import (ContextPackage, TaskManifest, Finding,
                    FinalReport, ThreatModel)
from vvaharness.pipeline.stages import (
    s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
    s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain)
from vvaharness.util import metrics as _metrics
from vvaharness.backends.llm import resolve as resolve_model
from vvaharness.util.tokens import TOKENS
from vvaharness.util import errlog as _errlog
from vvaharness.util.status import stage
from vvaharness.report import enrich as vcs_enrich
from vvaharness.report.redact import redact
from vvaharness.orchestrator.config_paths import (_resolve_against, _iter_model_roles)
from vvaharness.orchestrator.checkpoints import (save_ckpt, load_ckpt,
    run_id_for)
from vvaharness.orchestrator.cmdb import _load_app_profile
from vvaharness.orchestrator.enrich_findings import _enrich_findings


def scan_repo(repo: Path, repo_name: str, application_id: str | None,
              args, cfg,
              path_prefix: str | None = None) -> tuple[Path | None, int]:
    """
    Run the full s1→s9 pipeline against one local checkout.

    Returns (markdown_report_path, verified_finding_count). Raises on failure —
    the batch driver catches and records it. Returns (None, 0) when
    --stop-after short-circuits before s8.
    """
    run_id = run_id_for(repo)

    # ── per-repo output layout ───────────────────────────────────────────
    # Checkpoints and final report both live under the TARGET repo so each
    # scanned project carries its own artefacts.
    ckpt_dir = repo / "checkpoints"
    out_dir = repo / "security-scan"

    t0 = time.time()
    start_ts = _metrics.now_iso()
    # Filesystem-safe timestamp (':' is illegal on Windows).
    ts_safe = start_ts.replace(":", "").replace("-", "")
    module_safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in repo_name)
    out_path = out_dir / f"{module_safe}_{ts_safe}_report.md"
    sarif_path = out_dir / f"{module_safe}_{ts_safe}_report.sarif"
    # Configure the per-scan error log BEFORE any stage (incl. the optional
    # auto-step1 block below) can call _errlog.log(), so its failures land in
    # <repo>/security-scan/..._errors.jsonl rather than the module-global
    # default (cwd/pipeline-errors.jsonl).
    _errlog.configure(out_dir / f"{module_safe}_{ts_safe}_errors.jsonl")

    # ── Optional: AI-derive a per-target step1 overlay ──────────────────
    # Runs once per cloned target, BEFORE s1, and layers its exclusions on
    # top of config.yaml's step1. cfg is deep-copied so batch entries don't
    # accumulate each other's overlays. Skipped when --step1-config supplied
    # an explicit overlay (handled at startup).
    if getattr(args, "auto_step1", False):
        auto_path = ckpt_dir / "step1.yaml"
        if not (args.resume and auto_path.is_file()):
            try:
                with TOKENS.phase("s1-autoexclude"):
                    s1_autoexclude.run(repo, cfg, out_path=auto_path)
            except Exception as e:
                print(f"  [auto-step1] WARN: failed ({e}); continuing with "
                      f"global step1 only.", file=sys.stderr)
                _errlog.log("s1.autoexclude", repo_name, e)
                auto_path = None
        else:
            print(f"  [auto-step1] reusing {auto_path}", file=sys.stderr)
        if auto_path and auto_path.is_file():
            cfg = config_mod.Config(copy.deepcopy(cfg._data))
            cfg, _ = config_mod.apply_step1_overlay(cfg, auto_path)
            s1 = cfg._data.get("step1", {})
            print(f"  [auto-step1] applied overlay  "
                  f"(exclude_dirs={len(s1.get('exclude_dirs') or [])} "
                  f"exts={len(s1.get('exclude_exts') or [])} "
                  f"globs={len(s1.get('exclude_globs') or [])})",
                  file=sys.stderr)

    print(f"Agentic SAST  repo={repo}  module={repo_name}  "
          f"app_id={application_id or '-'}  run_id={run_id}",
          file=sys.stderr)
    print("  models:", file=sys.stderr)
    for role, m in _iter_model_roles(cfg):
        mid, via, extras = resolve_model(m)
        ex = f" {extras}" if extras else ""
        print(f"    {role:<11} -> {mid:<28} [{via}]{ex}", file=sys.stderr)

    # ── inject external context once ─────────────────────────────────────
    cfg_dir = Path(args.config).resolve().parent
    cves = load_cves(_resolve_against(cfg_dir, cfg.inject.cve_file))
    controls = load_controls(_resolve_against(cfg_dir, cfg.inject.controls_file))
    app_profile, app_info = _load_app_profile(application_id)
    print(f"  injected: {len(cves)} CVEs, {len(controls)} controls, "
          f"app_profile={'yes' if app_profile else 'no'}", file=sys.stderr)

    def _m(role: str) -> str:
        mid, via, _ = resolve_model(getattr(cfg.models, role))
        return f"{mid} [{via}]"

    # ── Step 1 — Pre-process (runs first; s2 consumes its output) ───────
    ctx: ContextPackage | None = load_ckpt(ckpt_dir, run_id, "s1") if args.resume else None
    if ctx is None:
        with stage(f"Step 1 — Pre-process ({_m('preprocess')})", n=1, total=9), \
                TOKENS.phase("s1-preprocess"):
            ctx = s1_preprocess.run(str(repo), cfg, cves, controls)
        save_ckpt(ckpt_dir, run_id, "s1", ctx)
    ctx.app_profile = app_profile
    if args.stop_after == "s1":
        return None, 0

    # ── Step 2 — Threat model (optional; reasons over s1's mapped surface) ─
    s2_enabled = getattr(getattr(cfg, "step2", None), "enabled", True)
    tm: ThreatModel | None = (load_ckpt(ckpt_dir, run_id, "s2")
                              if args.resume else None)
    if tm is None and s2_enabled:
        try:
            with stage(f"Step 2 — Threat model ({_m('threatmodel')})",
                       n=2, total=9), TOKENS.phase("s2-threatmodel"):
                tm = s2_threatmodel.run(str(repo), repo_name, cfg, cves,
                                        controls, ctx=ctx,
                                        app_profile=app_profile)
            save_ckpt(ckpt_dir, run_id, "s2", tm)
        except Exception as e:
            print(f"  [s2] WARN: threat-model step failed ({e}); "
                  f"continuing without it.", file=sys.stderr)
            _errlog.log("s2", repo_name, e)
            tm = None
    # Always re-attach (s2/CMDB may differ across resumed runs).
    ctx.threat_model = tm
    if args.stop_after == "s2":
        return None, 0

    # ── Step 3 ───────────────────────────────────────────────────────────
    manifest: TaskManifest | None = load_ckpt(ckpt_dir, run_id, "s3") if args.resume else None
    if manifest is None:
        with stage(f"Step 3 — Decompose ({_m('decompose')})", n=3, total=9), \
                TOKENS.phase("s3-decompose"):
            manifest = s3_decompose.run(ctx, cfg)
        save_ckpt(ckpt_dir, run_id, "s3", manifest)
    if args.stop_after == "s3":
        return None, 0

    # ── Step 4 ───────────────────────────────────────────────────────────
    s4_ckpt = load_ckpt(ckpt_dir, run_id, "s4") if args.resume else None
    chunk_outcomes: dict[str, str] = {}
    if s4_ckpt is None:
        with stage(f"Step 4 — Deep-dive ({_m('deepdive')}; {cfg.step4.runs} runs, "
                   f"vote≥{cfg.step4.vote_threshold}, "
                   f"parallel={getattr(cfg.step4, 'parallel', 1)})",
                   n=4, total=9), TOKENS.phase("s4-deepdive"):
            findings, chunk_outcomes = s4_deepdive.run(manifest.sorted_chunks(), ctx, cfg)
        # Bundle the per-chunk outcomes with the findings so a --resume that
        # rebuilds metrics still sees the coverage tally.
        save_ckpt(ckpt_dir, run_id, "s4",
                  {"findings": findings, "outcomes": chunk_outcomes})
    elif isinstance(s4_ckpt, dict):
        findings = s4_ckpt.get("findings", [])
        chunk_outcomes = s4_ckpt.get("outcomes", {})
    else:  # legacy bare-list checkpoint (pre outcome-tracking)
        findings = s4_ckpt
    if args.stop_after == "s4":
        return None, 0

    raw_count = len(findings)

    # ── Steps 5+6+7 — Pre-filter + verify + dedup (checkpointed together) ──
    s7_ckpt = load_ckpt(ckpt_dir, run_id, "s7") if args.resume else None
    if s7_ckpt is None:
        with stage("Step 5 — Pre-filter (deterministic + semantic pre-dedup)",
                   n=5, total=9), TOKENS.phase("s5-prefilter"):
            findings, pre_dropped = s5_prefilter.run(findings, ctx, cfg)
        if args.stop_after == "s5":
            return None, 0
        with stage(f"Step 6 — Verify ({_m('verify')})", n=6, total=9), \
                TOKENS.phase("s6-verify"):
            verified, dropped = s6_verify.run(findings, ctx, cfg)
        if args.stop_after == "s6":
            return None, 0
        with stage(f"Step 7 — Dedup ({_m('dedup')})", n=7, total=9), \
                TOKENS.phase("s7-dedup"):
            canonical, dup_dropped = s7_dedup.run(verified, cfg)
        save_ckpt(ckpt_dir, run_id, "s7",
                  (pre_dropped, verified, dropped, canonical, dup_dropped))
    elif len(s7_ckpt) == 5:
        pre_dropped, verified, dropped, canonical, dup_dropped = s7_ckpt
    else:  # legacy 4-tuple checkpoint (pre_dropped not stored)
        verified, dropped, canonical, dup_dropped = s7_ckpt
        pre_dropped = []
    # Honour --stop-after s5 / s6 even on a --resume that loaded a combined
    # s5+6+7 checkpoint: the in-branch early-returns above are skipped when
    # s7_ckpt is present, so without this the flags would be silently ignored.
    if args.stop_after in ("s5", "s6"):
        return None, 0
    _enrich_findings(canonical, app_info, path_prefix=path_prefix)
    all_dropped = pre_dropped + dropped + dup_dropped
    if args.stop_after == "s7":
        return None, 0

    # ── Step 8 — Chain ───────────────────────────────────────────────────
    report: FinalReport | None = load_ckpt(ckpt_dir, run_id, "s8") if args.resume else None
    if report is None:
        end_ts = _metrics.now_iso()
        fp = sum(1 for d in dropped if d.reason == "FALSE_POSITIVE")
        metrics = _metrics.build(
            ctx, manifest,
            repo_name=repo_name, start_ts=start_ts, end_ts=end_ts,
            raw_findings=raw_count, true_pos=len(verified),
            false_pos=fp, duplicates=len(dup_dropped),
            chunk_outcomes=chunk_outcomes,
        )
        with stage(f"Step 8 — Chain ({_m('chain')})", n=8, total=9), \
                TOKENS.phase("s8-chain"):
            report = s8_chain.run(canonical, ctx, cfg,
                              dropped=all_dropped,
                              raw_findings_count=raw_count,
                              metrics=metrics)
        report.repo_name = repo_name
        report.threat_model = tm
        report.app_profile = app_profile
        save_ckpt(ckpt_dir, run_id, "s8", report)

    # ── Output (always re-render — cheap, and s9 needs it on disk) ───────
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md_text = redact(report.to_markdown())
    out_path.write_text(md_text, encoding="utf-8")
    n_redacted = sum(getattr(redact, "last_counts", {}).values())
    print(f"  [out] wrote {out_path}"
          + (f"  ({n_redacted} sensitive values masked)" if n_redacted else ""),
          file=sys.stderr)
    if args.stop_after == "s8":
        return out_path, len(report.findings)

    # ── Step 9 — SARIF (parse the already-enriched MD) ──────────────────
    s9_done = load_ckpt(ckpt_dir, run_id, "s9") if args.resume else None
    if s9_done is None or not sarif_path.exists():
        scan_health = {
            "executionSuccessful": not report.degraded,
            "degraded": report.degraded,
            "chunks_failed": report.metrics.chunks_failed if report.metrics else 0,
            "errors_by_stage": (report.metrics.errors_by_stage
                                if report.metrics else {}),
        }
        with stage(f"Step 9 — SARIF (app_id={application_id or '-'})",
                   n=9, total=9):
            vcs_enrich.md_to_sarif(str(out_path), application_id, app_info,
                                    str(sarif_path), scan_health=scan_health)
        print(f"  [out] wrote {sarif_path}", file=sys.stderr)
        save_ckpt(ckpt_dir, run_id, "s9", str(sarif_path))
    if args.stop_after == "s9":
        return out_path, len(report.findings)

    elapsed = time.time() - t0
    print(f"\nDone in {elapsed:.0f}s. {len(report.findings)} verified findings "
          f"({len(report.dropped)} dropped), {len(report.chains)} chains.",
          file=sys.stderr)
    m = report.metrics
    tok_p = m.prompt_tokens if m and m.prompt_tokens is not None else "unavailable"
    tok_c = m.completion_tokens if m and m.completion_tokens is not None else "unavailable"
    tok_t = m.total_tokens if m and m.total_tokens is not None else "unavailable"
    print(f"Tokens: prompt={tok_p}, completion={tok_c}, total={tok_t}",
          file=sys.stderr)
    print(f"Report: {out_path}", file=sys.stderr)

    # Print markdown to stdout for piping
    print(md_text)
    return out_path, len(report.findings)
