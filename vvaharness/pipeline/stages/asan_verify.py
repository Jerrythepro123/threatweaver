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

"""Optional Codex-authored ASAN repro evidence for Step 6.

Codex is used as a repro author, not as an unrestricted shell. It inspects the
repository and emits a JSON bundle containing small bug-triggering samples,
optional scripts, and bounded run commands. The harness saves that bundle under
``security-scan/asan/bugN_*`` and executes only configured build commands plus
run commands that pass a narrow allow-list.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from vvaharness.backends.llm import agentic
from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.report.redact import redact
from vvaharness.util.json_extract import extract_json


# Runtime confirmation is deliberately stricter than build-instrumentation
# detection below.  A model mentioning "AddressSanitizer" is not evidence that
# an executed reproduction triggered it.  Require the canonical ASAN error and
# summary records in a harness-captured command log, plus a non-zero process
# result (the configured ASAN_OPTIONS uses abort_on_error=1).
_ASAN_ERROR_RE = re.compile(
    r"^(?:==\d+==)?(?:ERROR: AddressSanitizer:|AddressSanitizer:DEADLYSIGNAL)",
    re.IGNORECASE | re.MULTILINE,
)
_ASAN_SUMMARY_RE = re.compile(
    r"^SUMMARY: AddressSanitizer:",
    re.IGNORECASE | re.MULTILINE,
)
_RUN_RC_RE = re.compile(r"^\[rc=(-?\d+)\]$", re.MULTILINE)
_ASAN_BUILD_RE = re.compile(
    r"-fsanitize=(?:address|undefined)|\bfsanitize=address\b|"
    r"\blibasan\b|AddressSanitizer|UndefinedBehaviorSanitizer|"
    r"\b__asan\b|sanitize-address",
    re.IGNORECASE,
)
_DENY_RE = re.compile(
    r"(^|\s)(sudo|su|apt|apt-get|dnf|yum|pacman|curl|wget|scp|ssh|nc|ncat|"
    r"git|python\s+-c|python3\s+-c|perl\s+-e|ruby\s+-e|powershell|cmd\.exe)\b|"
    r"rm\s+-[^\n]*r|>\s*/dev/|/etc/|/var/run/docker|docker\s|podman\s",
    re.IGNORECASE,
)
_DEFAULT_CLASSES = {
    VulnClass.UAF.value,
    VulnClass.HEAP_OVERFLOW.value,
    VulnClass.STACK_OVERFLOW.value,
    VulnClass.FMT_STRING.value,
    VulnClass.INT_OVERFLOW.value,
    VulnClass.TYPE_CONFUSION.value,
}


@dataclass(frozen=True)
class AsanResult:
    attempted: bool
    crashed: bool
    summary: str
    artifact_dir: Path | None = None
    repro_command: str = ""


@dataclass(frozen=True)
class AsanBuildResult:
    succeeded: bool
    summary: str
    artifact_dir: Path | None = None


@dataclass(frozen=True)
class VerificationBudget:
    timeout: int
    max_turns: int
    max_budget_usd: float
    complexity: int
    rationale: str
    source: str


def enabled(cfg) -> bool:
    block = getattr(getattr(cfg, "step6_verify", None), "asan", None)
    return bool(getattr(block, "enabled", False))


def should_try(finding: Finding, cfg) -> bool:
    block = getattr(getattr(cfg, "step6_verify", None), "asan", None)
    if not enabled(cfg):
        return False
    if bool(getattr(block, "all_classes", False)):
        return True
    classes = set(getattr(block, "classes", None) or _DEFAULT_CLASSES)
    return finding.vuln_class.value in classes

def build_repo(ctx: ContextPackage, cfg, *, findings: list[Finding] | None = None
               ) -> AsanBuildResult:
    """Build the target repository with ASAN once for all selected findings."""
    if not enabled(cfg):
        return AsanBuildResult(False, "ASAN verifier disabled")
    block = cfg.step6_verify.asan
    repo = Path(ctx.repo_root)
    out_dir = repo / "security-scan" / "asan" / "repo_build"
    out_dir.mkdir(parents=True, exist_ok=True)
    timeout = int(
        getattr(block, "repo_build_timeout", None)
        or getattr(block, "per_bug_timeout", None)
        or getattr(block, "timeout", None)
        or getattr(block, "plan_timeout", 1800)
        or 1800
    )
    deadline = time.monotonic() + max(1, timeout)
    attempts: list[str] = []
    summary = ""
    attempt = 0
    while _remaining(deadline) > 0:
        attempt += 1
        attempt_dir = out_dir / f"build_attempt{attempt}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        try:
            plan = _build_plan(
                ctx,
                cfg,
                attempt_dir,
                idx=0,
                attempt=attempt,
                findings=findings or [],
                previous_summary="\n\n".join(attempts[-2:]),
                timeout=_phase_timeout(block, deadline, "build_plan_timeout", int(getattr(block, "plan_timeout", 600) or 600)),
            )
            build_commands = list(getattr(block, "build_commands", None) or [])
            planned_builds = [str(c) for c in plan.get("build_commands", []) if str(c).strip()]
            max_builds = int(getattr(block, "max_build_commands", 3) or 0)
            build_commands += planned_builds[:max_builds]
            build_logs = _run_model_commands(
                repo,
                build_commands,
                prefixes=list(getattr(block, "allowed_build_prefixes", None) or []),
                timeout=_phase_timeout(block, deadline, "build_timeout", 300),
                env=_asan_env(),
                out_dir=attempt_dir,
                label="build",
            )
            ok = _asan_build_succeeded(build_logs, plan, repo)
            summary = _build_summary(ok, build_logs, attempt_dir, attempt, plan=plan)
        except Exception as exc:
            summary = _exception_summary("ASAN_BUILD_FAIL", f"repo build attempt={attempt}", exc, attempt_dir)
        (attempt_dir / "summary.txt").write_text(summary, encoding="utf-8")
        attempts.append(summary)
        if summary.startswith("ASAN_BUILD_OK"):
            final = (
                f"ASAN_REPO_BUILD_OK after {attempt} attempt(s) within {timeout}s\n"
                f"Artifacts: {_rel_artifact_dir(out_dir)}/\n{summary}"
            )
            (out_dir / "summary.txt").write_text(final, encoding="utf-8")
            return AsanBuildResult(True, final, out_dir)
    final = (
        f"ASAN_REPO_BUILD_FAIL: ASAN build did not succeed after {attempt} attempt(s) "
        f"within {timeout}s\nArtifacts: {_rel_artifact_dir(out_dir)}/\n"
        + (attempts[-1] if attempts else "No ASAN build attempt completed before timeout")
    )
    (out_dir / "summary.txt").write_text(final, encoding="utf-8")
    return AsanBuildResult(False, final, out_dir)


def _chain_complexity(finding: Finding, ctx: ContextPackage) -> int:
    """Estimate source-to-sink complexity on a stable 1..5 scale."""
    text = " ".join((
        finding.title,
        finding.description,
        finding.exploit_scenario,
        " ".join(finding.preconditions),
        finding.source_ref or "",
        finding.sink_ref or "",
    )).lower()
    score = 1
    arrows = text.count("->") + text.count("→")
    if arrows >= 2:
        score += 1
    if arrows >= 5:
        score += 1
    if len(finding.preconditions) >= 2:
        score += 1
    complex_groups = (
        ("async", "callback", "queue", "event loop", "stream"),
        ("thread", "race", "concurrent", "lifetime", "use-after-free"),
        ("backend", "gpu", "cuda", "rdma", "hardware", "accelerator"),
        ("server", "http", "network", "remote", "rpc", "websocket"),
        ("model", "fixture", "configuration", "feature flag", "plugin"),
    )
    score += min(2, sum(any(word in text for word in group)
                        for group in complex_groups))

    file_functions = {
        fn for fn, locations in ctx.call_graph_files.items()
        if any((loc.split(":", 1)[0] == finding.file)
               for loc in locations)
    }
    related_edges = sum(
        1 for caller, callees in ctx.call_graph.items()
        if caller in file_functions or any(callee in file_functions for callee in callees)
    )
    if related_edges >= 5:
        score += 1
    if related_edges >= 15:
        score += 1
    return max(1, min(5, score))


def _scaled_floor(low: float, high: float, complexity: int) -> float:
    return low + (high - low) * (max(1, min(5, complexity)) - 1) / 4


def _adaptive_budget(finding: Finding, ctx: ContextPackage, cfg,
                     out_dir: Path, *, idx: int) -> VerificationBudget:
    block = cfg.step6_verify.asan
    fallback_timeout = int(
        getattr(block, "per_bug_timeout", None)
        or getattr(block, "timeout", None)
        or getattr(block, "plan_timeout", 600)
        or 600
    )
    complexity = _chain_complexity(finding, ctx)
    configured_turns = int(getattr(block, "max_turns", 12) or 12)
    configured_usd = float(getattr(block, "max_budget_usd", 2.0) or 2.0)
    if not bool(getattr(block, "adaptive_timeout", True)):
        return VerificationBudget(
            max(1, fallback_timeout), configured_turns, configured_usd,
            complexity, "adaptive verification budgeting disabled", "fixed",
        )

    min_timeout = int(getattr(block, "min_per_bug_timeout", 180) or 180)
    max_timeout = int(getattr(block, "max_per_bug_timeout", 1800) or 1800)
    min_turns = int(getattr(block, "min_repro_turns", 6) or 6)
    max_turns = int(getattr(block, "max_repro_turns", 40) or 40)
    min_usd = float(getattr(block, "min_repro_budget_usd", 0.5) or 0.5)
    max_usd = float(getattr(block, "max_repro_budget_usd", 15.0) or 15.0)
    if max_timeout < min_timeout:
        min_timeout, max_timeout = max_timeout, min_timeout
    if max_turns < min_turns:
        min_turns, max_turns = max_turns, min_turns
    if max_usd < min_usd:
        min_usd, max_usd = max_usd, min_usd

    floor_timeout = int(_scaled_floor(min_timeout, max_timeout, complexity))
    floor_turns = int(round(_scaled_floor(min_turns, max_turns, complexity)))
    floor_usd = _scaled_floor(min_usd, max_usd, complexity)
    estimate_timeout = int(getattr(block, "estimate_timeout", 90) or 90)
    estimate_turns = int(getattr(block, "estimate_max_turns", 4) or 4)
    estimate_usd = float(getattr(block, "estimate_max_budget_usd", 0.5) or 0.5)
    model = (getattr(getattr(cfg, "models", None), "asan_verify", None)
             or cfg.models.verify)
    prompt = f"""Estimate the resources needed to dynamically verify this security finding.
Do not verify or reproduce it now. Inspect repository build/test instructions and the
cited code with Read/Glob/Grep only. Estimate wall-clock time, reasoning turns, and
model budget. Longer source-to-sink chains, asynchronous or concurrent behavior,
specialized backends, server startup, fixtures, models, and configuration requirements
must receive larger allocations.

Repository: {ctx.repo_root}
Language: {ctx.language}
Finding: {finding.file}:{finding.line_start}-{finding.line_end}
Class: {finding.vuln_class.value}
Title: {finding.title}
Description: {finding.description}
Exploit scenario: {finding.exploit_scenario or "(none)"}
Source: {finding.source_ref or "(none)"}
Sink: {finding.sink_ref or "(none)"}
Preconditions: {finding.preconditions or []}
Deterministic chain-complexity floor: {complexity}/5
Allowed bounds: {min_timeout}-{max_timeout} seconds, {min_turns}-{max_turns} turns,
${min_usd:.2f}-${max_usd:.2f}.

Return JSON only:
{{
  "complexity": 1,
  "estimated_seconds": 300,
  "recommended_turns": 10,
  "recommended_budget_usd": 2.0,
  "chain_factors": ["specific factor"],
  "rationale": "short explanation"
}}"""
    source = "heuristic"
    rationale = f"deterministic chain complexity {complexity}/5"
    requested_timeout = floor_timeout
    requested_turns = floor_turns
    requested_usd = floor_usd
    try:
        raw = agentic(
            prompt,
            model=model,
            system_prompt=(
                "You estimate verification effort; you do not verify findings. "
                "Use repository evidence, never inflate exploitability, and return JSON only."
            ),
            allowed_tools=["Read", "Glob", "Grep"],
            cwd=ctx.repo_root,
            max_budget_usd=estimate_usd,
            max_turns=estimate_turns,
            timeout=estimate_timeout,
            tag=f"asan estimate#{idx}",
        )
        data = extract_json(raw)
        if not isinstance(data, dict):
            raise ValueError("verification estimator returned non-object JSON")
        requested_timeout = max(floor_timeout, int(data.get("estimated_seconds", 0)))
        requested_turns = max(floor_turns, int(data.get("recommended_turns", 0)))
        requested_usd = max(floor_usd, float(data.get("recommended_budget_usd", 0)))
        model_complexity = max(1, min(5, int(data.get("complexity", complexity))))
        complexity = max(complexity, model_complexity)
        rationale = str(data.get("rationale") or rationale).strip()
        factors = data.get("chain_factors")
        if isinstance(factors, list) and factors:
            rationale += "; factors: " + ", ".join(str(x) for x in factors[:8])
        source = "model+heuristic"
    except Exception as exc:
        rationale += f"; estimator fallback: {redact(str(exc))[:240]}"

    requested_timeout = max(
        requested_timeout,
        int(_scaled_floor(min_timeout, max_timeout, complexity)),
    )
    requested_turns = max(
        requested_turns,
        int(round(_scaled_floor(min_turns, max_turns, complexity))),
    )
    requested_usd = max(
        requested_usd,
        _scaled_floor(min_usd, max_usd, complexity),
    )
    budget = VerificationBudget(
        timeout=max(min_timeout, min(max_timeout, requested_timeout)),
        max_turns=max(min_turns, min(max_turns, requested_turns)),
        max_budget_usd=max(min_usd, min(max_usd, requested_usd)),
        complexity=complexity,
        rationale=rationale,
        source=source,
    )
    (out_dir / "time-estimate.json").write_text(json.dumps({
        "timeout_seconds": budget.timeout,
        "max_turns": budget.max_turns,
        "max_budget_usd": round(budget.max_budget_usd, 2),
        "complexity": budget.complexity,
        "source": budget.source,
        "rationale": budget.rationale,
    }, indent=2), encoding="utf-8")
    return budget

def run(finding: Finding, ctx: ContextPackage, cfg, *, idx: int, build: AsanBuildResult | None = None) -> AsanResult:
    if not should_try(finding, cfg):
        return AsanResult(False, False, "ASAN verifier disabled or finding class not selected")
    block = cfg.step6_verify.asan
    repo = Path(ctx.repo_root)
    out_dir = repo / "security-scan" / "asan" / _bug_dir_name(idx, finding)
    out_dir.mkdir(parents=True, exist_ok=True)

    fallback_timeout = int(
        getattr(block, "per_bug_timeout", None)
        or getattr(block, "timeout", None)
        or getattr(block, "plan_timeout", 1800)
        or 1800
    )
    repro_attempts: list[str] = []
    build = build or build_repo(ctx, cfg)
    build_summary = build.summary

    if not build.succeeded:
        final = (
            f"NO_ASAN_CRASH: shared ASAN repo build failed; repro skipped "
            f"(fallback budget {fallback_timeout}s)\n"
            f"Artifacts: {_rel_artifact_dir(out_dir)}/\n{build_summary}"
        )
        (out_dir / "summary.txt").write_text(final, encoding="utf-8")
        return AsanResult(True, False, final, out_dir)

    budget = _adaptive_budget(finding, ctx, cfg, out_dir, idx=idx)
    deadline = time.monotonic() + budget.timeout
    budget_summary = (
        f"Adaptive verification budget: {budget.timeout}s, {budget.max_turns} turns, "
        f"${budget.max_budget_usd:.2f}, complexity={budget.complexity}/5 "
        f"({budget.source}) — {budget.rationale}"
    )
    execution_reserve = int(
        getattr(block, "execution_reserve", None)
        or max(60, int(getattr(block, "run_timeout", 60) or 60) * 2)
    )
    repro_attempt = 0
    while _remaining(deadline) > execution_reserve:
        repro_attempt += 1
        attempt_dir = out_dir / f"repro_attempt{repro_attempt}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        try:
            plan = _repro_plan(
                finding,
                ctx,
                cfg,
                attempt_dir,
                idx=idx,
                attempt=repro_attempt,
                build_summary=build_summary,
                previous_summary="\n\n".join(repro_attempts[-2:]),
                timeout=_planning_timeout(block, deadline, execution_reserve),
                max_turns=budget.max_turns,
                max_budget_usd=budget.max_budget_usd,
            )
            sample_count = _write_artifacts(
                plan,
                attempt_dir,
                key="samples",
                subdir="samples",
                max_items=int(getattr(block, "max_samples", 2) or 0),
                max_bytes=int(getattr(block, "max_sample_bytes", 16384)),
                executable=False,
            )
            script_count = _write_artifacts(
                plan,
                attempt_dir,
                key="scripts",
                subdir="scripts",
                max_items=int(getattr(block, "max_scripts", 1) or 0),
                max_bytes=int(getattr(block, "max_script_bytes", 16384)),
                executable=True,
            )
            run_commands = [str(c) for c in plan.get("run_commands", []) if str(c).strip()]
            run_commands = run_commands[:int(getattr(block, "max_run_commands", 2) or 0)]
            runs = _run_model_commands(
                repo,
                run_commands,
                prefixes=list(getattr(block, "allowed_run_prefixes", None) or []),
                timeout=_phase_timeout(block, deadline, "run_timeout", 60),
                env=_asan_env(),
                out_dir=attempt_dir,
                deadline=deadline,
            )
            # Only captured command output can confirm ASAN.  Model-authored
            # evidence is retained in the summary for auditability, but it is
            # never part of the verdict calculation.
            crashed = any(_actual_asan_trigger(log) for log in runs)
            repro_command = _first_crashing_command(runs) if crashed else ""
            summary = _summarize(crashed, sample_count, script_count, runs, attempt_dir, attempt=repro_attempt, plan=plan, repro_command=repro_command)
        except Exception as exc:
            crashed = False
            summary = _exception_summary("NO_ASAN_CRASH", f"repro attempt={repro_attempt}", exc, attempt_dir)
        (attempt_dir / "summary.txt").write_text(summary, encoding="utf-8")
        repro_attempts.append(summary)
        if crashed:
            final = (
                f"ASAN_CRASH after shared_repo_build=1, repro_attempts={repro_attempt} "
                f"within {budget.timeout}s\n{budget_summary}\n{build_summary}\n{summary}"
            )
            (out_dir / "summary.txt").write_text(final, encoding="utf-8")
            return AsanResult(True, True, final, out_dir, repro_command)

    final = (
        f"NO_ASAN_CRASH after successful ASAN build and {repro_attempt} repro attempt(s) "
        f"within {budget.timeout}s\nArtifacts: {_rel_artifact_dir(out_dir)}/\n"
        f"{budget_summary}\n"
        f"{build_summary}\n"
        + (repro_attempts[-1] if repro_attempts else "No repro attempt completed before timeout")
    )
    (out_dir / "summary.txt").write_text(final, encoding="utf-8")
    return AsanResult(True, False, final, out_dir)


def _build_plan(ctx: ContextPackage, cfg, out_dir: Path, *, idx: int, attempt: int,
                findings: list[Finding], previous_summary: str,
                timeout: int) -> dict:
    block = cfg.step6_verify.asan
    model = getattr(getattr(cfg, "models", None), "asan_verify", None) or cfg.models.verify
    artifact_rel = _rel_artifact_dir(out_dir)
    finding_scope = "\n".join(
        f"- {f.file}:{f.line_start} [{f.vuln_class.value}] {f.title}"
        for f in findings[:30]
    ) or "- No specific finding supplied; build a runnable primary application or test target."
    prompt = f"""Plan how to compile this repository with AddressSanitizer enabled, then return JSON only.

Target repository: {ctx.repo_root}
Visible artifact directory for this build attempt: {artifact_rel}/
Build label: {"repo_build" if idx <= 0 else f"bug{idx}"}
Build attempt: {attempt}

Previous failed ASAN build attempts:
{previous_summary or "(none)"}

Selected findings the build must be able to exercise:
{finding_scope}

Codex task:
- Use Bash to inspect the current project guides and build files (README*, docs/*,
  BUILD*, Makefile, CMakeLists.txt, configure scripts, package metadata, existing tests).
- Identify existing runnable application or test targets that exercise the components
  named by the selected findings. If findings are in a server component, build that
  server executable rather than only a shared library.
- Generate the exact ASAN configure/build commands for this repository. You may run
  quick discovery or configuration commands, but do not perform the full compile in
  this planning call; the harness executes the returned build_commands.
- You must build existing project targets only. Do not create, generate, compile, or link standalone C/C++/Rust/Go source files, harnesses, wrappers, test programs, or toy repro programs.
- Change strategy if the previous build attempt failed.
- Do not create trigger samples yet; this phase is build-only.
- Return the build strategy, supporting evidence from the repository instructions,
  and the exact commands the harness should run to produce the ASAN build.
- Return repo-relative paths for the runnable executables or existing test binaries
  that the commands will produce. A library alone is not a verification artifact.

Constraints:
- Do not modify source files or application logic. You may amend build/configuration files only when necessary to fix ASAN compilation, and you must describe those changes in build_evidence.
- Do not create standalone source files, harnesses, wrappers, test programs, or toy repro programs.
- Do not install packages, use the network, use git, sudo, docker/podman, or invoke destructive commands.
- Return at most {int(getattr(block, "max_build_commands", 3) or 0)} build commands.
- Build commands must start with one of these exact prefixes:
  {list(getattr(block, "allowed_build_prefixes", None) or [])}

JSON schema:
{{
  "rationale": "short explanation of the repository-specific ASAN build strategy",
  "build_evidence": "short excerpt from project guides/build configuration supporting the selected targets and sanitizer flags",
  "commands_tried": ["exact discovery/configuration commands you ran with Bash"],
  "build_commands": [
    "timeout 600 make CFLAGS=' -fsanitize=address -fno-omit-frame-pointer -g -O1' LDFLAGS=' -fsanitize=address'"
  ],
  "verification_artifacts": ["build/bin/server-or-existing-test-binary"]
}}"""
    raw = _codex_asan_json(
        prompt, model=model, ctx=ctx, block=block, timeout=timeout,
        tag=f"asan build bug{idx}.{attempt}", plan_only=True)
    data = extract_json(raw)
    if not isinstance(data, dict):
        raise ValueError("ASAN build planner returned non-object JSON")
    (out_dir / f"build-plan-attempt{attempt}.json").write_text(redact(raw), encoding="utf-8")
    return data


def _repro_plan(finding: Finding, ctx: ContextPackage, cfg, out_dir: Path, *, idx: int,
                attempt: int, build_summary: str, previous_summary: str,
                timeout: int, max_turns: int,
                max_budget_usd: float) -> dict:
    block = cfg.step6_verify.asan
    model = getattr(getattr(cfg, "models", None), "asan_verify", None) or cfg.models.verify
    artifact_rel = _rel_artifact_dir(out_dir)
    prompt = f"""Generate and test a bounded AddressSanitizer reproduction bundle, then return JSON only.

Target repository: {ctx.repo_root}
Visible artifact directory for this repro attempt: {artifact_rel}/
ASAN build evidence:
{build_summary}

Finding:
- bug label: bug{idx}
- repro attempt: {attempt}
- file: {finding.file}
- lines: {finding.line_start}-{finding.line_end}
- class: {finding.vuln_class.value}
- title: {finding.title}
- description: {finding.description}
- reported source: {finding.source_ref or "(none)"}
- reported sink: {finding.sink_ref or "(none)"}
- snippet:
{finding.code_snippet}

Previous failed repro attempts for this same finding:
{previous_summary or "(none)"}

Codex task:
- Reason from the report and source to create a concrete input sample or driver script that could trigger this bug in the already ASAN-built project.
- Use Bash to run the generated sample/script against existing ASAN-built project binaries within the timeout.
- Do not create, compile, or run standalone source code, harnesses, wrappers, test programs, or toy repro programs.
- If a command fails or does not trigger ASAN, adapt and try another strategy until timeout is near.
- Keep artifacts readable and named by purpose under {artifact_rel}/samples/ and {artifact_rel}/scripts/.
- Return whether ASAN triggered, the sanitizer evidence you observed, and the best repro artifacts/run commands you actually tried or that directly reproduce the observed ASAN crash.

Constraints:
- Do not modify source files, application logic, build files, or configuration files during repro.
- In {artifact_rel}/, create only input samples and scripts that run existing ASAN-built project binaries; scripts must not compile code.
- Do not create standalone source files, harnesses, wrappers, test programs, or toy repro programs.
- Do not install packages, use the network, use git, sudo, docker/podman, or invoke destructive commands.
- Return at most {int(getattr(block, "max_samples", 2))} samples, at most
  {int(getattr(block, "max_scripts", 1) or 0)} scripts, and at most
  {int(getattr(block, "max_run_commands", 2))} run commands.
- Run commands must start with one of these exact prefixes:
  {list(getattr(block, "allowed_run_prefixes", None) or [])}

JSON schema:
{{
  "rationale": "short explanation of why these artifacts target the bug",
  "asan_evidence": "short AddressSanitizer/UBSan output excerpt from running existing project binaries, else empty",
  "commands_tried": ["exact commands you ran with Bash against existing project binaries"],
  "samples": [
    {{"path": "samples/trigger.bin", "content_b64": "base64 bytes"}}
  ],
  "scripts": [
    {{"path": "scripts/repro.sh", "content_b64": "base64 script bytes"}}
  ],
  "run_commands": [
    "timeout 12 bash {artifact_rel}/scripts/repro.sh"
  ]
}}"""
    raw = _codex_asan_json(
        prompt, model=model, ctx=ctx, block=block, timeout=timeout,
        tag=f"asan repro bug{idx}.{attempt}", max_turns=max_turns,
        max_budget_usd=max_budget_usd)
    data = extract_json(raw)
    if not isinstance(data, dict):
        raise ValueError("ASAN repro planner returned non-object JSON")
    (out_dir / f"repro-plan-attempt{attempt}.json").write_text(redact(raw), encoding="utf-8")
    return data


def _codex_asan_json(prompt: str, *, model, ctx: ContextPackage, block,
                     timeout: int, tag: str, plan_only: bool = False,
                     max_turns: int | None = None,
                     max_budget_usd: float | None = None) -> str:
    execution_instruction = (
        "For build planning, inspect the repository and return executable build "
        "commands without waiting for a full compile; the harness runs them next."
        if plan_only else
        "Return only JSON after trying the relevant existing-project repro step yourself."
    )
    return agentic(
        prompt,
        model=model,
        system_prompt=(
            "You are Codex generating and testing ASAN evidence. Inspect source with "
            "Read/Grep/Glob and use Bash for bounded local build/test/repro commands. "
            f"{execution_instruction} "
            "Follow the current repository build/test guides; do not assume target-specific "
            "binaries from another project. You may amend build/configuration files only to fix compilation, "
            "but never change source code or application logic. Never create or compile standalone source, "
            "harnesses, wrappers, test programs, or toy repro programs. Never install packages, use the network, "
            "use git, sudo, docker/podman, or destructive commands."
        ),
        allowed_tools=["Read", "Glob", "Grep", "Bash"],
        cwd=ctx.repo_root,
        max_budget_usd=(max_budget_usd if max_budget_usd is not None
                        else getattr(block, "max_budget_usd", 0.2)),
        max_turns=(max_turns if max_turns is not None
                   else getattr(block, "max_turns", 3)),
        timeout=timeout,
        tag=tag,
    )


def _write_artifacts(plan: dict, out_dir: Path, *, key: str, subdir: str,
                     max_items: int, max_bytes: int, executable: bool) -> int:
    items = plan.get(key, [])
    if not isinstance(items, list) or max_items <= 0:
        return 0
    root = (out_dir / subdir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    count = 0
    for item in items[:max_items]:
        if not isinstance(item, dict):
            continue
        rel = _safe_relpath(str(item.get("path") or f"{subdir}/artifact-{count}"), subdir)
        dest = (root / rel).resolve()
        if root not in dest.parents and dest != root:
            continue
        raw = _artifact_bytes(item)
        if _forbidden_artifact(rel, raw, executable=executable):
            continue
        if len(raw) > max_bytes:
            raw = raw[:max_bytes]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(raw)
        if executable:
            try:
                dest.chmod(0o700)
            except OSError:
                pass
        count += 1
    return count



_FORBIDDEN_SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".rs", ".go", ".java", ".cs", ".m", ".mm", ".s", ".asm", ".o", ".a", ".so"}
_COMPILE_IN_SCRIPT_RE = re.compile(r"\b(gcc|g\+\+|clang|clang\+\+|cc|c\+\+|rustc|go\s+build|cmake|make|ninja)\b", re.IGNORECASE)


def _forbidden_artifact(rel: str, raw: bytes, *, executable: bool) -> bool:
    suffix = Path(rel).suffix.lower()
    if suffix in _FORBIDDEN_SOURCE_EXTS:
        return True
    if executable:
        text = raw[:8192].decode("utf-8", errors="ignore")
        return bool(_COMPILE_IN_SCRIPT_RE.search(text))
    return False

def _artifact_bytes(item: dict) -> bytes:
    if item.get("content_b64") is not None:
        return base64.b64decode(str(item.get("content_b64") or ""), validate=True)
    if item.get("content") is not None:
        return str(item.get("content") or "").encode("utf-8")
    return b""


def _safe_relpath(path: str, subdir: str) -> str:
    rel = path.replace("\\", "/")
    rel = rel.split(f"{subdir}/", 1)[-1].lstrip("/")
    parts = [p for p in rel.split("/") if p and p not in {".", ".."}]
    return "/".join(parts) or "artifact"


def _run_configured_commands(repo: Path, commands: list[str], *, timeout: int,
                             env: dict[str, str], out_dir: Path, label: str) -> list[str]:
    outputs: list[str] = []
    for i, cmd in enumerate(commands):
        outputs.append(_run_shell(repo, cmd, timeout=timeout, env=env,
                                  log_path=out_dir / f"{label}-{i}.log"))
    return outputs


def _run_model_commands(repo: Path, commands: list[str], *, prefixes: list[str],
                        timeout: int, env: dict[str, str], out_dir: Path,
                        label: str = "run",
                        deadline: float | None = None) -> list[str]:
    outputs: list[str] = []
    for i, cmd in enumerate(commands):
        command_timeout = timeout
        if deadline is not None:
            remaining = _remaining(deadline)
            if remaining <= 0:
                outputs.append("SKIPPED verification deadline exhausted")
                break
            command_timeout = min(command_timeout, remaining)
        if not _allowed_command(cmd, prefixes):
            outputs.append(f"SKIPPED disallowed run command: {cmd}")
            continue
        outputs.append(_run_shell(repo, cmd, timeout=command_timeout, env=env,
                                  log_path=out_dir / f"{label}-{i}.log"))
    return outputs


def _allowed_command(cmd: str, prefixes: list[str]) -> bool:
    if not cmd or "\x00" in cmd or _DENY_RE.search(cmd):
        return False
    stripped = cmd.strip()
    return any(_prefix_matches(stripped, str(prefix)) for prefix in prefixes)


def _prefix_matches(cmd: str, prefix: str) -> bool:
    prefix = prefix.strip()
    if not prefix or not cmd.startswith(prefix):
        return False
    if len(cmd) == len(prefix):
        return True
    # Command prefixes must end on a shell-token boundary, but several ASAN
    # allowlist entries are path stems (bug*, repo_build/*, cmake-build-*).
    nxt = cmd[len(prefix)]
    if nxt.isspace() or nxt in "/._-" or nxt.isdigit():
        return True
    return False


def _run_shell(repo: Path, cmd: str, *, timeout: int, env: dict[str, str],
               log_path: Path) -> str:
    if _DENY_RE.search(cmd):
        raise ValueError(f"refusing unsafe ASAN command: {cmd}")
    proc_env = {**os.environ, **env}
    if os.name == "nt" and str(repo).startswith("/mnt/"):
        argv = ["wsl.exe", "--cd", str(repo), "--exec", "bash", "-lc", cmd]
        cwd = None
    else:
        argv = ["bash", "-lc", cmd]
        cwd = str(repo)
    try:
        result = subprocess.run(
            argv,
            cwd=cwd,
            env=proc_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        text = f"$ {cmd}\n[rc={result.returncode}]\n{result.stdout}\n{result.stderr}"
    except subprocess.TimeoutExpired as exc:
        text = f"$ {cmd}\n[TIMEOUT after {timeout}s]\n{exc.stdout or ''}\n{exc.stderr or ''}"
    text = redact(text)
    if len(text) > 20000:
        text = text[:10000] + "\n...<truncated>...\n" + text[-8000:]
    log_path.write_text(text, encoding="utf-8")
    return text


def _asan_env() -> dict[str, str]:
    return {
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:symbolize=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }


def _exception_summary(status: str, phase: str, exc: Exception, out_dir: Path) -> str:
    detail = redact(str(exc))
    if len(detail) > 4000:
        detail = detail[:2000] + "\n...<truncated>...\n" + detail[-1500:]
    return f"{status}: {phase}, error={detail}\nArtifacts: {_rel_artifact_dir(out_dir)}/"

def _summarize(crashed: bool, sample_count: int, script_count: int,
               runs: list[str], out_dir: Path, *, attempt: int, plan: dict,
               repro_command: str) -> str:
    status = "ASAN_CRASH" if crashed else "NO_ASAN_CRASH"
    evidence = _plan_text(plan, "asan_evidence", "crash_evidence", "run_evidence")
    tails = _tail_logs(runs + ([evidence] if evidence else []))
    command_line = f"Exact trigger command: {repro_command}\n" if repro_command else ""
    return (
        f"{status}: repro_attempt={attempt}, samples={sample_count}, scripts={script_count}, "
        f"run_steps={len(runs)}\n"
        f"Artifacts: {_rel_artifact_dir(out_dir)}/\n"
        f"{command_line}"
        f"{tails}"
    )



def _first_crashing_command(logs: list[str]) -> str:
    for log in logs:
        if not _actual_asan_trigger(log):
            continue
        for line in log.splitlines():
            if line.startswith("$ "):
                return line[2:].strip()
    return ""


def _actual_asan_trigger(log: str) -> bool:
    """Return true only for an ASAN failure captured from an executed command.

    The harness prefixes real executions with ``$ ...`` and ``[rc=N]``.  With
    ``abort_on_error=1``, a genuine report must have a non-zero result and both
    ASAN's canonical ERROR and SUMMARY records.  This intentionally treats
    truncated, model-reported, generic, UBSAN-only, or zero-exit output as
    unconfirmed instead of promoting a possible false positive.
    """
    if not log or not log.startswith("$ ") or log.startswith("SKIPPED "):
        return False
    rc_match = _RUN_RC_RE.search(log)
    if rc_match is None or int(rc_match.group(1)) == 0:
        return False
    return bool(_ASAN_ERROR_RE.search(log) and _ASAN_SUMMARY_RE.search(log))


def _build_summary(ok: bool, build: list[str], out_dir: Path, attempt: int, *, plan: dict) -> str:
    status = "ASAN_BUILD_OK" if ok else "ASAN_BUILD_FAIL"
    evidence = _plan_text(plan, "build_evidence", "rationale")
    return (
        f"{status}: build_attempt={attempt}, build_steps={len(build)}\n"
        f"Artifacts: {_rel_artifact_dir(out_dir)}/\n"
        f"{_tail_logs(build + ([evidence] if evidence else []))}"
    )


def _plan_bool(plan: dict, *keys: str) -> bool:
    for key in keys:
        value = plan.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in {"1", "true", "yes", "ok", "success", "succeeded"}:
            return True
    return False


def _plan_text(plan: dict, *keys: str) -> str:
    parts: list[str] = []
    for key in keys:
        value = plan.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
        elif isinstance(value, list):
            parts.extend(str(item).strip() for item in value if str(item).strip())
    return "\n".join(parts)

def _tail_logs(logs: list[str]) -> str:
    tails = "\n".join(logs[-2:])
    if len(tails) > 2500:
        tails = tails[-2500:]
    return tails


def _command_succeeded(logs: list[str]) -> bool:
    useful = [log for log in logs if not log.startswith("SKIPPED ")]
    if not useful:
        return False
    for log in useful:
        first = log.splitlines()[0] if log.splitlines() else ""
        cmd = first[2:].strip() if first.startswith("$ ") else first
        build_like = (
            "cmake --build" in cmd
            or re.search(r"(^|\s)(make|ninja)(\s|$)", cmd) is not None
            or "--target" in cmd
        )
        if build_like and "[rc=0]" in log:
            return True
    return False




def _asan_build_succeeded(logs: list[str], plan: dict, repo: Path) -> bool:
    """True only when a successful build has sanitizer proof.

    A plain `make`/`ninja` with rc=0 is not enough for the dynamic verifier:
    the repro phase needs binaries that were actually compiled or linked with
    ASAN/UBSAN instrumentation.
    """
    if not _command_succeeded(logs):
        return False
    evidence = "\n".join(logs + [_plan_text(plan, "build_evidence", "commands_tried")])
    if not _ASAN_BUILD_RE.search(evidence):
        return False

    artifacts = plan.get("verification_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return False
    root = repo.resolve()
    for artifact in artifacts:
        rel = Path(str(artifact))
        if rel.is_absolute() or ".." in rel.parts:
            continue
        candidate = (root / rel).resolve()
        if candidate != root and root not in candidate.parents:
            continue
        if candidate.is_file():
            return True
    return False


def _remaining(deadline: float) -> int:
    return int(deadline - time.monotonic())


def _phase_timeout(block, deadline: float, attr: str, default: int) -> int:
    configured = int(getattr(block, attr, default) or default)
    return max(1, min(configured, max(1, _remaining(deadline))))


def _planning_timeout(block, deadline: float, execution_reserve: int) -> int:
    configured = int(
        getattr(block, "repro_plan_timeout", None)
        or getattr(block, "plan_timeout", 600)
        or 600
    )
    available = max(1, _remaining(deadline) - max(1, execution_reserve))
    return max(1, min(configured, available))


def _bug_dir_name(idx: int, finding: Finding) -> str:
    title = finding.title or finding.file or "finding"
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", title).strip("._")
    return f"bug{max(1, idx)}_{safe[:72] or 'finding'}"


def _rel_artifact_dir(out_dir: Path) -> str:
    text = out_dir.as_posix()
    marker = "/security-scan/asan/"
    if marker in text:
        return "security-scan/asan/" + text.split(marker, 1)[1]
    return text
