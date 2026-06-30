# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""remediation_agent.prompts — the remediation method as model-agnostic prompt text.

(3-gate triage,minimal-diff fix-scoring matrix, code-level-signals-only, secrets-handling).

This module owns ONLY the prompt text. The structured-output contract lives in
:mod:`vvaharness.remediation_agent.models` and the artifact rendering in
:mod:`vvaharness.remediation_agent.artifacts`, so each piece stays independently testable.

When the policy gate allows a patch, the per-finding loop passes the resolved
playbook strategy block + do-not-edit path globs into :func:`build_user`, which
injects them as authoritative prompt sections. With no policy args,
:func:`build_user` renders exactly as before.
"""
from __future__ import annotations

from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.report_parser import Finding


def build_system() -> str:
    """SYSTEM prompt with the structured-output JSON schema embedded, so every
    backend (including the CLI agentic path, which has no native schema flag) is
    told the exact output shape."""
    return f"""\
You are an application-security REMEDIATION agent operating on a single SAST
finding inside a checked-out repository. You have read/search tools (and, in
fix mode, edit tools) scoped to the repo. Your job: confirm the finding via
evidence, then apply the MINIMAL safe code change that removes the root cause.

EVIDENCE GATES (assess all three before fixing):
  - Gate A — Source: identify the attacker/user-controlled input with file:line.
  - Gate B — Sink: identify the security-relevant sink reachable from the source
    with file:line.
  - Gate C — Missing control: explain why existing validation/sanitization does
    not constrain the source (or that none exists).

REMEDIATION RULES (authoritative):
  - LEAST-CHANGE: minimal diff at the vulnerable site(s). No refactors, no
    renames, no unrelated cleanup. Preserve behaviour for legitimate inputs.
  - ROOT CAUSE: fix the actual flaw (e.g. parameterized query, output encoding,
    constant-time compare, TLS verification on, auth dependency, input
    allow-list), not a symptom.
  - PLAYBOOK STRATEGY: when the user prompt includes a "Required fix strategy"
    section, follow it exactly — do NOT invent an alternative approach.
  - POLICY: when the user prompt includes a "Remediation policy" section, never
    edit files matching its do-not-edit globs.
  - INSTANCE COVERAGE: fix every instance of the same root cause the finding
    references; note any sibling instances you spot.
  - NO NEW VULNERABILITIES: do not introduce new issues; use the framework's
    standard secure idiom.
  - CODE-LEVEL SIGNALS ONLY: do not rely on or recommend operational controls
    (WAF, SIEM, manual review, ADR docs, pre-commit hooks) as the fix.
  - SECRETS: never echo plaintext secrets/tokens/keys. Refer by file:line or
    redact as XX***YY (≤4 contiguous original chars). For hardcoded-secret
    findings, move the value to a config/env/secret-manager read and note that
    rotation is required.
  - SNIPPETS: quote at most ~20 lines of code in your output.

STRUCTURED OUTPUT (REQUIRED):
Respond with ONLY a single JSON object — no prose, no markdown fences — that
validates against this JSON Schema:
{RemediationVerdict.schema_json_compact()}

Every field is REQUIRED — populate them all. In particular, `summary` MUST be a
non-empty 2-4 sentence human-readable description of the verdict and what you
changed (or, for non-fix verdicts, why). Never leave `summary` blank or omit it.

In fix mode you MUST actually apply the edits to the files before responding;
`changes` lists the diffs you made. In report-only mode, do NOT edit files —
populate `changes` with the edits you WOULD make and set the verdict accordingly."""



# Built once at import — the schema is static.
SYSTEM = build_system()


def _policy_block(*, deny_paths: list[str] | None,
                  forbid_paths: list[str] | None) -> str:
    """Render the policy guidance injected on the ALLOW path: the do-NOT-edit
    path lists. Edits to those paths are programmatically reverted post-run, so
    surfacing them up front reduces wasted work."""
    if not (deny_paths or forbid_paths):
        return ""
    lines = ["", "## Remediation policy (authoritative)"]
    paths = sorted(set((deny_paths or []) + (forbid_paths or [])))
    if paths:
        shown = ", ".join(paths[:24]) + (" …" if len(paths) > 24 else "")
        lines.append(
            "- Do NOT edit files matching these globs (sensitive subsystems / "
            "build & CI infrastructure). Any such edit is automatically "
            f"reverted on disk after you finish: {shown}")
    return "\n".join(lines) + "\n"


def build_user(finding: Finding, repo: str, mode: str = "fix", *,
               strategy_block: str | None = None,
               deny_paths: list[str] | None = None,
               forbid_paths: list[str] | None = None) -> str:
    """Per-finding user prompt: the full finding block + repo root + mode.

    When the policy gate allows a patch, the caller passes the resolved playbook
    *strategy_block* (the authoritative fix approach) plus the do-not-edit path
    globs, which are injected as additional prompt sections. With no policy args
    this renders exactly as before."""
    body = finding.body or finding.label
    action = ("apply the minimal safe fix" if mode == "fix"
              else "describe the minimal safe fix (do NOT edit files)")
    strat = f"\n{strategy_block.strip()}\n" if strategy_block else ""
    policy = _policy_block(deny_paths=deny_paths, forbid_paths=forbid_paths)
    return f"""REPOSITORY ROOT: {repo}
MODE: {mode}   (fix = apply minimal diffs; report-only = describe only, no edits)
FINDING INDEX: {finding.index}
PRIMARY FILE: {finding.file or 'unknown'}

=== SAST FINDING (from security-scan report) ===
{body}
=== END FINDING ===
{strat}{policy}
Locate the code referenced above, assess Evidence Gates A/B/C, and {action}.
Set `finding_index` to {finding.index}. Respond with ONLY the JSON verdict
object that validates against the schema in your instructions."""
