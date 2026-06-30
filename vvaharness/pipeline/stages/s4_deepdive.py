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

"""
Step 4 — Deep-dive each chunk N times, then majority-vote.

Temperature: when `models.deepdive.via` is `sdk` or `openai` AND the config
node sets `temperature`, the dispatcher passes that value through (see
backends/llm.py `resolve()`/`prompt()`), so each run samples differently and
the vote means something. The code supplies NO temperature default: if the
config omits `temperature`, none is sent and the provider's own default
applies. When `via == cli`, the CLI has no --temperature flag and the kwarg
is dropped — diversity is lower, expect tighter agreement.

Voting is effectively DISABLED by default. The shipped profile pins
`models.deepdive` to a model that rejects an explicit `temperature` (Opus
4.7+/Sonnet 4.5+/Haiku 4.5+; see backends/sdk._supports_temperature), so
`_effective_runs()` collapses runs/vote_threshold to 1/1 — N identical-temp
runs would just be N copies of one output (N× cost, 0 filtering). To enable
real majority voting, point `models.deepdive` at a temperature-capable model
(e.g. Opus 4.6 / Sonnet 4.6 / Haiku 4.5) AND set `temperature: 1.0` on that
node. The s5 prefilter + s6 verifier are the FP defence when voting is off.
"""
from __future__ import annotations
import re
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from vvaharness.models import Chunk, ChunkSize, ContextPackage, Finding, VulnClass
from vvaharness.backends.llm import prompt, resolve
from vvaharness.report.redact import redact_counts, redact, _luhn
from vvaharness.util.json_extract import extract_json
from vvaharness.util import errlog as _errlog
from vvaharness.backends import claude_cli as cli
from vvaharness.backends.claude_cli import GuardrailBlocked
from vvaharness.backends.sdk import _supports_temperature
from vvaharness.util.prompts import (EXCLUSION_RULES, SELF_VERIFICATION,
                            SEVERITY_GUIDANCE, EXHAUSTIVENESS)
from vvaharness.lang.hints import hints_for, LANG_DISPLAY
from vvaharness.pipeline.stages.s1_preprocess import q_file, q_name

_QUALITY_BAR = """\
QUALITY BAR:
- Trace data flow: WHERE untrusted input enters → HOW it reaches the dangerous
  operation. No confirmed data flow = no finding.
- Verify reachability from external input (not dead code, not test-only).
- Check for upstream protections (validation, sanitization, framework
  safeguards) BEFORE reporting.
- Write a concrete exploit: specific input, specific impact. If you can't,
  drop the finding.

For each file, trace the logic — don't just scan for patterns:
- What does the code assume about its inputs?
- What happens at boundary conditions?
- Are there check-then-act patterns where state could change between check
  and action?
- Do error paths leak state or skip validation?

CROSS-CUTTING (applies to docs/config/non-code files in your scope too):
- Insecure-transport directives committed to the repo (CWE-295): grep your
  scope for sslVerify=false, SSL_VERIFY_NONE, verify=False, verify_ssl: false,
  rejectUnauthorized: false, InsecureSkipVerify, NODE_TLS_REJECT_UNAUTHORIZED=0,
  curl -k / --insecure, TrustAllCerts, ALLOW_ALL_HOSTNAME_VERIFIER. A README
  or setup script that INSTRUCTS users to disable TLS verification is a
  reportable supply-chain finding even though it is not executable code.
- Output-side injection: data the program WRITES (CSV cells, HTML reports,
  log lines later parsed by another tool) is a sink. Hunt for unescaped
  emission, not just unescaped ingestion."""

_OUTPUT_SCHEMA = """\
Respond with ONLY a JSON object (no prose before or after):
{
  "findings": [
    {
      "file": "src/parser.c",
      "line_start": 142,
      "line_end": 158,
      "vuln_class": "heap-overflow|use-after-free|stack-overflow|format-string|integer-overflow|type-confusion|race-condition|injection|unsafe-deserialization|logic-flaw|info-leak|other",
      "cwe": "CWE-79  (single most-specific CWE id; omit if no clear mapping)",
      "title": "Under 12 words",
      "impact": "2-3 plain-language sentences: what an attacker gains, who is affected, why it matters",
      "description": "Detailed input-to-bug data flow explanation",
      "exploit_scenario": "Max 5 sentences: the specific input the attacker sends and the resulting impact",
      "preconditions": ["condition 1", "condition 2"],
      "recommendation": "Security property that must hold + specific location in THIS code and what to change",
      "code_snippet": "the vulnerable lines",
      "source_ref": "src/api/Controller.java:71   (where untrusted input enters; same as sink_ref for context-free bugs like hardcoded secrets)",
      "sink_ref": "src/parser.c:148   (where that input is used unsafely)",
      "confidence": 0.85
    }
  ]
}

An empty {"findings": []} is acceptable ONLY after you have traced every
entry point, every sink, and every cross-cutting pattern above and confirmed
each is mitigated or unreachable — never as a default. Assume at least one
exploitable defect is present in the slice."""


SYSTEM = "\n\n".join([
    "You are a security researcher performing deep code analysis. You receive "
    "source code for a focused slice of a repository plus a research lens "
    "(language/specialist hints) and a hypothesis from a strategist.",
    "Treat the slice as hostile: assume at least one exploitable defect is "
    "present and do not stop until every line and data flow has been examined.",
    _QUALITY_BAR,
    EXCLUSION_RULES,
    SELF_VERIFICATION,
    SEVERITY_GUIDANCE,
    EXHAUSTIVENESS,
    _OUTPUT_SCHEMA,
])


def build_research_lens(chunk: Chunk, code: str | None = None) -> str:
    """Per-chunk language/specialist guidance — lives in the USER prompt so the
    SYSTEM block stays byte-identical across all s4 calls and the sdk
    cache_control marker hits on every call after the first."""
    hints = hints_for(chunk.languages, chunk.specialist, code=code)
    if chunk.specialist:
        header = hints or f"You are a {chunk.specialist} specialist."
    else:
        lang_label = " / ".join(LANG_DISPLAY.get(l, l) for l in chunk.languages[:3]) \
                     or "this codebase"
        header = f"Research lens: {lang_label} security researcher."
        if hints:
            header += f"\n\n{hints}"
    return header


def build_system_prompt(chunk: Chunk) -> str:  # noqa: ARG001 — back-compat shim
    return SYSTEM

# Sliding window for LARGE chunks
WINDOW_LINES = 600
WINDOW_OVERLAP = 100
# Per-line character cap. A minified/single-line file would otherwise become one
# enormous "line" that bypasses WINDOW_LINES and blows the prompt/token budget.
# This caps per-line SIZE only; it does not re-window a single huge line.
MAX_LINE_CHARS = 8000


def _effective_runs(cfg) -> tuple[int, int]:
    """
    Voting only filters noise when runs sample differently. The CLI backend
    has no temperature flag, and Opus 4.7+ / Sonnet 5+ / Haiku 5+ on SDK
    reject `temperature` outright — N identical-temp runs ≈ N copies of the
    same output → N× cost, 0 filtering. Degrade to 1/1 in those cases and
    warn once.
    """
    runs = cfg.step4.runs
    threshold = cfg.step4.vote_threshold
    model_id, via, extras = resolve(cfg.models.deepdive)
    if via == "cli" and runs > 1:
        print(f"  [s4] WARN: models.deepdive.via={via!r} has no temperature control; "
              f"forcing runs=1, vote_threshold=1 (was {runs}/{threshold}). "
              f"Set via: sdk or via: openai to enable majority voting.",
              file=sys.stderr)
        return 1, 1
    if via == "sdk" and runs > 1 and not _supports_temperature(model_id):
        # The shipped default (claude-opus-4-8) lands here: voting is disabled
        # by design. This is NOT a silent scan-behaviour change — runs/vote
        # were already config-overridable and we warn loudly once per scan so
        # the operator can opt into a temperature-capable model if they want
        # real voting. See the module docstring for the rationale.
        print(f"  [s4] WARN: model {model_id!r} rejects `temperature` — "
              f"runs={runs} would produce identical samples, voting filters "
              f"nothing. Forcing runs=1, vote_threshold=1. Use Opus 4.6 / "
              f"Sonnet 4.6 / Haiku 4.5 with temperature: 1.0 if you want "
              f"voting on s4.", file=sys.stderr)
        return 1, 1
    # `temperature` omitted (not in extras) is NOT the same as temperature=0:
    # only warn about identical samples when the config EXPLICITLY pins temp 0.
    # When it is simply unset, the provider applies its own (non-zero) default
    # and runs do still diverge — esp. via:openai.
    if via != "cli" and runs > 1 and "temperature" in extras \
            and extras["temperature"] == 0:
        print(f"  [s4] WARN: runs={runs} but temperature=0 — runs will be identical. "
              f"Set temperature: 1.0 on models.deepdive.", file=sys.stderr)
    # vote_threshold must be reachable: a threshold > effective runs means NO
    # finding can ever accumulate enough votes and _deepdive_chunk silently
    # drops everything. Clamp down to runs and warn.
    if threshold > runs:
        print(f"  [s4] WARN: vote_threshold={threshold} exceeds runs={runs}; "
              f"no finding could survive the vote — clamping vote_threshold to "
              f"{runs}.", file=sys.stderr)
        threshold = runs
    if threshold < 1:
        threshold = 1
    return runs, threshold


def run(manifest_chunks: list[Chunk], ctx: ContextPackage, cfg
        ) -> tuple[list[Finding], dict[str, str]]:
    """Process every chunk.

    Returns ``(findings, outcomes)`` where ``outcomes`` maps each chunk id to
    ``"completed"`` / ``"error"`` / ``"guardrail"`` so the report can disclose
    coverage loss (a failed/timed-out chunk yields no findings, previously
    indistinguishable from a clean chunk that simply found nothing)."""
    repo_root = Path(ctx.repo_root)
    chunks = sorted(manifest_chunks, key=lambda c: c.risk_rank)
    parallel = getattr(cfg.step4, "parallel", 1)
    runs_n, threshold = _effective_runs(cfg)

    def _label(chunk: Chunk) -> None:
        lens = chunk.specialist or "+".join(chunk.languages[:3]) or "generic"
        h = chunk.hypothesis
        print(f"  [s4] chunk {chunk.id} ({chunk.size.value}, rank {chunk.risk_rank}, "
              f"lens={lens}): {h[:120]}{'…' if len(h) > 120 else ''}",
              file=sys.stderr)

    guardrail_hits = 0
    guardrail_gate = max(3, parallel)
    successes = 0
    outcomes: dict[str, str] = {}   # chunk id -> "completed"|"error"|"guardrail"

    def _guardrail_fail_fast(e: GuardrailBlocked) -> None:
        raise RuntimeError(
            f"s4-deepdive: {guardrail_hits} guardrail blocks with zero "
            "successful chunks — aborting run. The CLI/OAuth path is "
            "intercepted; switch models.deepdive.via to 'sdk' .") from e

    if parallel <= 1:
        all_findings: list[Finding] = []
        for chunk in chunks:
            _label(chunk)
            try:
                findings = _deepdive_chunk(chunk, ctx, repo_root, cfg,
                                           runs_n, threshold)
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"  [s4] chunk {chunk.id} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s4", f"guardrail:{chunk.id}", e, scope="chunk",
                            files=len(chunk.files))
                outcomes[chunk.id] = "guardrail"
                if guardrail_hits >= guardrail_gate and successes == 0:
                    _guardrail_fail_fast(e)
                continue
            except Exception as e:
                if cli.aborted():
                    raise
                # A chunk whose every run failed (timeout, socket drop, parse
                # error) raises here; record it as failed so the report can
                # disclose the coverage gap instead of silently dropping it.
                print(f"  [s4] chunk {chunk.id} ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s4", chunk.id, e, scope="chunk",
                            files=len(chunk.files))
                outcomes[chunk.id] = "error"
                continue
            successes += 1
            outcomes[chunk.id] = "completed"
            all_findings.extend(findings)
            print(f"  [s4] chunk {chunk.id}: {len(findings)} high-confidence findings",
                  file=sys.stderr)
        return _collapse_across_chunks(all_findings, cfg.step4.line_bucket), outcomes

    print(f"  [s4] processing {len(chunks)} chunks ({parallel} parallel)...",
          file=sys.stderr)
    results: dict[str, list[Finding]] = {}
    ex = ThreadPoolExecutor(max_workers=parallel)
    futs = {}
    for chunk in chunks:
        _label(chunk)
        futs[ex.submit(_deepdive_chunk, chunk, ctx, repo_root, cfg,
                       runs_n, threshold)] = chunk
    try:
        for fut in as_completed(futs):
            chunk = futs[fut]
            try:
                findings = fut.result()
            except GuardrailBlocked as e:
                guardrail_hits += 1
                print(f"  [s4] chunk {chunk.id} GUARDRAIL-BLOCKED "
                      f"({guardrail_hits}/{guardrail_gate})", file=sys.stderr)
                _errlog.log("s4", f"guardrail:{chunk.id}", e, scope="chunk",
                            files=len(chunk.files))
                results[chunk.id] = []
                outcomes[chunk.id] = "guardrail"
                if guardrail_hits >= guardrail_gate and successes == 0:
                    cli.abort()
                    ex.shutdown(wait=False, cancel_futures=True)
                    _guardrail_fail_fast(e)
                continue
            except Exception as e:
                print(f"  [s4] chunk {chunk.id} ERROR: {redact(str(e))}", file=sys.stderr)
                _errlog.log("s4", chunk.id, e, scope="chunk",
                            files=len(chunk.files))
                results[chunk.id] = []
                outcomes[chunk.id] = "error"
                continue
            successes += 1
            results[chunk.id] = findings
            outcomes[chunk.id] = "completed"
            print(f"  [s4] chunk {chunk.id}: {len(findings)} high-confidence findings",
                  file=sys.stderr)
    except KeyboardInterrupt:
        n = cli.abort()
        print(f"  [s4] interrupted — killed {n} running subprocess(es), "
              f"cancelling {sum(1 for f in futs if not f.done())} pending chunks",
              file=sys.stderr)
        ex.shutdown(wait=False, cancel_futures=True)
        raise
    finally:
        ex.shutdown(wait=True)

    # Reassemble in risk-rank order so downstream ordering is stable.
    all_findings: list[Finding] = []
    for chunk in chunks:
        all_findings.extend(results.get(chunk.id, []))
    return _collapse_across_chunks(all_findings, cfg.step4.line_bucket), outcomes


def _deepdive_chunk(chunk: Chunk, ctx: ContextPackage, repo_root: Path, cfg,
                    runs_n: int, threshold: int) -> list[Finding]:
    code = _load_chunk_code(chunk, repo_root)
    code += _neighbor_context(chunk, ctx, repo_root, cfg)
    if chunk.specialist:
        # Specialist passes are a different LENS, not a consistency probe.
        # Run once; s6 adversarial verification is the FP filter.
        runs_n = getattr(cfg.step4, "specialist_runs", 1)
        threshold = 1
    line_bucket = cfg.step4.line_bucket

    # ── N independent runs ───────────────────────────────────────────────
    runs: list[set[tuple]] = []
    by_key: dict[tuple, Finding] = {}
    runs_ok = 0

    for run_i in range(runs_n):
        if cli.aborted():
            raise RuntimeError("aborted by user (Ctrl-C)")
        try:
            findings = _single_run(chunk, ctx, code, cfg)
        except Exception as e:
            if cli.aborted():
                raise
            print(f"    [s4] {chunk.id} run {run_i+1}/{runs_n} failed: {e}",
                  file=sys.stderr)
            _errlog.log("s4", chunk.id, e, scope="run",
                        run=run_i + 1, runs_total=runs_n)
            runs.append(set())
            continue

        runs_ok += 1
        keys = set()
        for f in findings:
            k = f.canonical_key(line_bucket)
            keys.add(k)
            prev = by_key.get(k)
            if prev is None or f.confidence > prev.confidence:
                by_key[k] = f
        runs.append(keys)
        print(f"    [s4] {chunk.id} run {run_i+1}/{runs_n}: "
              f"{len(findings)} raw findings", file=sys.stderr)

    # A chunk where EVERY run failed produced no findings for a reason (timeout,
    # socket drop, parse error) — surface it as a failure so run() records the
    # coverage gap, rather than returning [] indistinguishable from a clean
    # chunk that simply found nothing. (One successful run, even with zero
    # findings, is a legitimate completed chunk.)
    if runs_n > 0 and runs_ok == 0:
        raise RuntimeError(
            f"all {runs_n} run(s) failed for chunk {chunk.id}")

    # ── Vote ─────────────────────────────────────────────────────────────
    votes = Counter(k for run_keys in runs for k in run_keys)
    survivors: list[Finding] = []
    for k, n in votes.items():
        if n >= threshold:
            f = by_key[k]
            f.votes = n
            survivors.append(f)

    return survivors


def _collapse_across_chunks(findings: list[Finding], line_bucket: int) -> list[Finding]:
    """
    Per-chunk voting can't see that risk-chunk-03 and spec-crypto-01 both
    flagged foo.py:142. Collapse on canonical_key globally, keeping the
    highest-confidence representative.
    """
    best: dict[tuple, Finding] = {}
    for f in findings:
        k = f.canonical_key(line_bucket)
        if k not in best or f.confidence > best[k].confidence:
            best[k] = f
    if len(best) < len(findings):
        print(f"  [s4] cross-chunk collapse: {len(findings)} → {len(best)}",
              file=sys.stderr)
    return list(best.values())


def _single_run(chunk: Chunk, ctx: ContextPackage, code: str, cfg) -> list[Finding]:
    user = _build_prompt(chunk, ctx, code)

    try:
        raw = prompt(
            user,
            model=cfg.models.deepdive,
            system_prompt=SYSTEM,
            max_tokens=getattr(cfg.step4, "max_tokens", None),
            timeout=getattr(cfg.step4, "timeout", 1800),
            output_format="json",
            tag=f"s4 {chunk.id}",
        )
    except GuardrailBlocked as e:
        print(f"    [s4] {chunk.id}: GUARDRAIL-BLOCKED — "
              f"{str(e)[:120]}", file=sys.stderr)
        raise

    data = extract_json(raw)
    raw_findings = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(raw_findings, list):
        raw_findings = []

    findings: list[Finding] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            print(f"    [s4] dropped non-object finding: {type(item).__name__}",
                  file=sys.stderr)
            _errlog.log("s4", chunk.id,
                        f"dropped non-object finding: {type(item).__name__}",
                        scope="item")
            continue
        item.setdefault("chunk_id", chunk.id)
        vc = item.get("vuln_class", "other")
        if vc not in {v.value for v in VulnClass}:
            item["vuln_class"] = "other"
        cwe_raw = str(item.get("cwe") or "").strip()
        m = re.search(r"\bCWE[-\s]?(\d{1,5})\b", cwe_raw, re.I)
        item["cwe"] = f"CWE-{m.group(1)}" if m else None
        try:
            findings.append(Finding.model_validate(item))
        except Exception as e:
            print(f"    [s4] dropped malformed finding: {e}", file=sys.stderr)
            _errlog.log("s4", chunk.id, e, scope="item",
                        file=str(item.get("file", "")))

    cap = getattr(cfg.step4, "max_findings_per_run", None)
    if cap and len(findings) > cap:
        findings.sort(key=lambda f: f.confidence, reverse=True)
        print(f"    [s4] {chunk.id}: capping {len(findings)} → {cap} by confidence",
              file=sys.stderr)
        findings = findings[:cap]
    return findings


def _trust_context_block(ctx: ContextPackage) -> str:
    """Compact exposure/trust-boundary summary so the researcher can apply
    OUT-OF-SCOPE rule A (NO REAL ATTACKER) itself instead of emitting FPs the
    verifier must drop."""
    ap = ctx.app_profile
    tm = ctx.threat_model
    if not ap and not tm:
        return ""
    lines = ["TRUST CONTEXT (use this to decide if input is attacker-controlled):"]
    if ap:
        lines.append(f"  - Externally facing: {'YES' if ap.externally_facing else 'NO — internal only'}")
        sens = [t for t, on in (("PCI", ap.pci_scoped), ("PAN", ap.processes_pan),
                                ("PII", ap.pii)) if on]
        if sens:
            lines.append(f"  - Data sensitivity: {', '.join(sens)}")
    if tm:
        if tm.system_context:
            ctx_short = tm.system_context.split("\n\n")[0][:400]
            lines.append(f"  - System: {ctx_short}")
        if tm.trust_boundaries:
            lines.append("  - UNTRUSTED entry points (only these cross a trust boundary):")
            for b in tm.trust_boundaries[:8]:
                lines.append(f"      • {b.entry_point}")
    lines.append("  - Operator argv/env on the operator's OWN host is TRUSTED. "
                 "But CI job parameters, scheduler args, shared config/CSV/"
                 "test-data files editable by other principals, and "
                 "framework-overridable variables ARE attack surface even on "
                 "an internal app — report those (typically LOW). See OUT-OF-"
                 "SCOPE rule A.")
    return "\n".join(lines) + "\n"


def _build_prompt(chunk: Chunk, ctx: ContextPackage, code: str) -> str:
    cve_block = ""
    if chunk.related_cves:
        relevant = [c for c in ctx.known_cves if c.id in chunk.related_cves]
        cve_block = "\nRELATED CVEs (hunt for variants/siblings):\n" + "\n".join(
            f"  - {c.id}: {c.summary}" for c in relevant
        ) + "\n"

    return f"""RESEARCH LENS:
{build_research_lens(chunk, code)}

CHUNK: {chunk.id}  SIZE: {chunk.size.value}
HYPOTHESIS: {chunk.hypothesis}
FOCUS ENTRY POINTS: {", ".join(chunk.focus_entry_points) or "(none)"}
{_trust_context_block(ctx)}{cve_block}
SOURCE CODE:
{code}

Analyze this code and respond with ONLY the JSON findings object."""


# ─────────────────────────────────────────────────────────────────────────────
# Code loading (same as SDK version — CLI single-shot needs code in the prompt)
# ─────────────────────────────────────────────────────────────────────────────

# Mask them (keep BIN prefix + length so the researcher can still flag "test PAN in
# source" findings) before the code leaves the process.
_PAN_RX = re.compile(r"\b(?:\d[\s\-]?){13,19}\b")

# A card-context keyword sitting just before the digit run (e.g. `pan =`,
# `cardNumber:`, `acct_no`, `credit_card`). Matched in a short window preceding
# the match so a labelled-but-non-Luhn test PAN is still caught.
_CARD_CTX = re.compile(
    r"(?i)\b(pan|card(?:[\s_-]*(?:no|num|number))?"
    r"|cc(?:[\s_-]*(?:no|num|number))?|credit[\s_-]*card"
    r"|acct|account(?:[\s_-]*(?:no|num|number))?)\b")


def _mask_pan(m: re.Match) -> str:
    s = m.group(0)
    digits = re.sub(r"\D", "", s)
    if len(digits) < 13:
        return s
    # Card-likeness gate (option B): mask only when the run is Luhn-valid (every
    # issued PAN satisfies the Luhn check digit, regardless of IIN/prefix) OR a
    # card keyword sits immediately before it. This keeps real cards + labelled
    # test PANs masked before egress to the external LLM provider (CWE-201)
    # while no longer clobbering ordinary 13-19 digit literals — nanosecond
    # timestamps, Snowflake/DB ids, account/version numbers — that a length-only
    # gate mangled. Layer 2 (the shared IIN+Luhn-gated redactor in report.redact)
    # still runs after this and is unchanged. First 4 digits + length + layout
    # are preserved so a researcher can still flag "card/secret literal here".
    window = m.string[max(0, m.start() - 48): m.start()]
    if not (_luhn(digits) or _CARD_CTX.search(window)):
        return s
    kept = 0
    out = []
    for c in s:
        if c.isdigit():
            out.append(c if kept < 4 else "X")
            kept += 1
        else:
            out.append(c)
    return "".join(out)


def _redact_source(text: str, rel: str) -> str:
    """Mask sensitive data BEFORE source is packed into the prompt and sent to
    the model. A provider/gateway PII guard rejects requests containing live
    PII (e.g. SSNs), so this is both a privacy control and a hard requirement
    for the request to succeed.

    Two layers: (1) the partial PAN mask keeps the BIN prefix + length so the
    researcher can still flag "test card in source" findings, and catches any
    Luhn-valid card (any prefix) plus card-keyword-labelled non-Luhn test PANs;
    (2) the shared redactor masks SSNs, credentials, keys,
    JWTs and Luhn/IIN-valid cards the prefix mask doesn't cover. Both preserve
    line structure (no newlines added/removed) so finding line numbers stay
    accurate. redact_counts() is used (not redact()) because s4 runs chunks
    concurrently and must not race on the shared count side-channel."""
    # Count only runs actually masked: _mask_pan now returns non-card runs
    # unchanged, so subn's match count would over-report. nonlocal closure keeps
    # the tally local to this call (no cross-chunk race).
    n_pan = 0
    def _count_mask(m: re.Match) -> str:
        nonlocal n_pan
        repl = _mask_pan(m)
        if repl != m.group(0):
            n_pan += 1
        return repl
    masked = _PAN_RX.sub(_count_mask, text)
    masked, counts = redact_counts(masked)
    n_other = sum(counts.values())
    if n_pan or n_other:
        detail = (" [" + ", ".join(f"{k}:{v}" for k, v in sorted(counts.items())) + "]"
                  if counts else "")
        print(f"    [s4] redacted {n_pan} PAN-prefix + {n_other} sensitive "
              f"token(s) in {rel}{detail}", file=sys.stderr)
    return masked


def _load_chunk_code(chunk: Chunk, repo_root: Path) -> str:
    if chunk.size != ChunkSize.LARGE:
        return _load_files_full(chunk.files, repo_root)
    return _load_sliding_window(chunk, repo_root)


# ─────────────────────────────────────────────────────────────────────────────
# Neighbor context: callers/callees that live OUTSIDE this chunk. Gives the
# researcher enough upstream/downstream visibility to rule out FPs ("input is
# already validated in the caller") and confirm TPs ("callee passes it to
# Runtime.exec") without paying for the whole other chunk.
# ─────────────────────────────────────────────────────────────────────────────

def _neighbor_context(chunk: Chunk, ctx: ContextPackage, repo_root: Path,
                      cfg) -> str:
    n_lines = getattr(cfg.step4, "neighbor_context_lines", 12)
    max_neighbors = getattr(cfg.step4, "neighbor_context_max", 20)
    if n_lines <= 0:
        return ""

    chunk_files = set(chunk.files)
    fwd = ctx.call_graph or {}
    rev: dict[str, list[str]] = defaultdict(list)
    for caller, callees in fwd.items():
        for cal in callees:
            rev[cal].append(caller)

    # bare-name → [(file, line)] from s1's def-site scan, for excerpt anchors.
    def_line: dict[tuple[str, str], int] = {}
    for fn, locs in (ctx.call_graph_files or {}).items():
        for loc in locs:
            f, _, ln = loc.rpartition(":")
            def_line[(f or loc, fn)] = int(ln) if ln.isdigit() else 0

    in_chunk_qns = {qn for qn in set(fwd) | set(rev)
                    if q_file(qn) in chunk_files}
    focus = set(chunk.focus_entry_points or ())
    in_chunk_qns.update(qn for qn in set(fwd) | set(rev)
                        if q_name(qn) in focus and q_file(qn) in chunk_files)

    want: list[tuple[str, str, str]] = []  # (relation, neighbor_qn, anchor_qn)
    for qn in in_chunk_qns:
        for caller in rev.get(qn, ()):
            if q_file(caller) not in chunk_files:
                want.append(("CALLS", caller, qn))
        for callee in fwd.get(qn, ()):
            if q_file(callee) not in chunk_files:
                want.append(("CALLED BY", callee, qn))

    seen: set[tuple[str, int]] = set()
    parts: list[str] = []
    for relation, neighbor_qn, anchor_qn in want:
        if len(parts) >= max_neighbors:
            break
        nfile = q_file(neighbor_qn)
        nname = q_name(neighbor_qn)
        if not nfile or nfile in chunk_files:
            continue
        nline = def_line.get((nfile, nname), 0)
        excerpt, lo = _excerpt(repo_root / nfile, nname, nline, n_lines)
        if excerpt is None or (nfile, lo) in seen:
            continue
        seen.add((nfile, lo))
        parts.append(
            f"-- {nfile}:{lo}  [{nname} {relation} {q_name(anchor_qn)}] --\n"
            f"{excerpt}\n"
        )
    if not parts:
        return ""
    print(f"    [s4] {chunk.id}: +{len(parts)} neighbor-context excerpts",
          file=sys.stderr)
    return ("\n=== NEIGHBOR CONTEXT (callers/callees OUTSIDE this chunk — "
            "read-only, do NOT report findings in these files) ===\n"
            + "\n".join(parts))


def _excerpt(p: Path, fn: str, hint_line: int, n: int) -> tuple[str | None, int]:
    try:
        lines = _redact_source(
            p.read_text(encoding="utf-8", errors="replace"), str(p)
        ).splitlines()
    except OSError:
        return None, 0
    anchor = hint_line - 1 if 0 < hint_line <= len(lines) else None
    if anchor is None:
        for i, ln in enumerate(lines):
            if fn and fn in ln and "(" in ln:
                anchor = i
                break
    if anchor is None:
        return None, 0
    lo, hi = max(0, anchor - 2), min(len(lines), anchor + n)
    body = "\n".join(f"{i+1:5d}| {lines[i]}" for i in range(lo, hi))
    return body, lo + 1


def _load_files_full(files: list[str], repo_root: Path) -> str:
    parts = []
    for rel in files:
        p = repo_root / rel
        if not p.is_file():
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        text = _redact_source(text, rel)
        numbered = "\n".join(f"{i+1:5d}| {ln[:MAX_LINE_CHARS]}"
                             for i, ln in enumerate(text.splitlines()))
        parts.append(f"=== {rel} ===\n{numbered}\n")
    return "\n".join(parts)


def _load_sliding_window(chunk: Chunk, repo_root: Path) -> str:
    parts = []
    for rel in chunk.files:
        p = repo_root / rel
        if not p.is_file():
            print(f"    [s4] WARN: file not found: {rel}", file=sys.stderr)
            parts.append(f"=== {rel} ===\n[FILE NOT FOUND]\n")
            continue
        # Degrade per-file on an unreadable LARGE file (OSError: permission,
        # transient FS error, special file) instead of aborting the whole
        # chunk — mirrors _load_files_full's read-error guard.
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"    [s4] WARN: read error on {rel}: {e}", file=sys.stderr)
            parts.append(f"=== {rel} ===\n[READ ERROR: {e}]\n")
            continue
        lines = [ln[:MAX_LINE_CHARS] for ln in _redact_source(text, rel).splitlines()]
        windows = _windows_for_entrypoints(lines, chunk.focus_entry_points)
        if not windows:
            # No entry-point anchors → tile the entire file so nothing is skipped.
            step = WINDOW_LINES - WINDOW_OVERLAP
            windows = [(lo, min(lo + WINDOW_LINES, len(lines)))
                       for lo in range(0, max(len(lines), 1), step)]
        for (lo, hi) in windows:
            slice_lines = lines[lo:hi]
            numbered = "\n".join(f"{i+lo+1:5d}| {ln}" for i, ln in enumerate(slice_lines))
            parts.append(f"=== {rel} [lines {lo+1}-{hi}] ===\n{numbered}\n")
    return "\n".join(parts)


def _windows_for_entrypoints(lines: list[str], entry_fns: list[str]) -> list[tuple[int, int]]:
    if not entry_fns:
        return []
    anchors: list[int] = []
    for i, ln in enumerate(lines):
        for fn in entry_fns:
            if fn in ln and "(" in ln:
                anchors.append(i)
                break
    if not anchors:
        return []
    half = WINDOW_LINES // 2
    raw = [(max(0, a - half), min(len(lines), a + half)) for a in sorted(set(anchors))]
    merged = [raw[0]]
    for lo, hi in raw[1:]:
        plo, phi = merged[-1]
        if lo <= phi + WINDOW_OVERLAP:
            merged[-1] = (plo, max(phi, hi))
        else:
            merged.append((lo, hi))
    return merged
