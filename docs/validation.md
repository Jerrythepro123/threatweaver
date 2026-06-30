<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Validation panel (`validate` / `s11` — step 11)

The canonical reference for the agentic validation command. It grades the fixes
the [Remediation Agent](remediation.md) (step 10) produced. For the trust model
see [security.md](security.md); for config knobs see
[configuration.md](configuration.md#step_validate--validator-s11).

## What it does

`vvaharness validate` (alias `vvaharness s11`) runs two phases over the
remediation DTOs under `<repo>/security-remediation/<NN_slug>/remediate_report.json`:

1. **discover** *(deterministic, no model spend)* — locate DTOs in a
   validatable state (`status` = `awaiting_validation`, `needs_review`, or
   `validation_failed`).
2. **s11 — panel** — an agentic adversarial panel (bundled Claude Agent SDK,
   Python ≥3.10) scores each fix and writes the verdict back into the DTO.

> **Default-on.** With the shipped `default.yaml` (`step_validate.enabled: true`)
> this runs automatically as **Step 11** at the end of `vvaharness scan`, right
> after step-10 remediation. It is also a standalone command (below).

## The panel

Three persona subagents (`vvaharness/validation/subagents/`):

| Persona | When | Role |
|---|---|---|
| `security-architect` | always on | Reviews the fix design / root-cause coverage. |
| `penetration-tester` | always on | Adversarial: tries to bypass the fix. (Per-CWE bypass cheatsheets from `./inputs/validator_hints.yaml` are injected into the shared session launch prompt's finding-details block, available to the whole panel — not scoped to this persona.) |
| `cross-repo-analyzer` | only when a fix spans **2+ repositories** | Checks cross-repo coverage. |

All three default to `models.validate`; each is independently overridable via an
optional per-persona key — `validate_security_architect`,
`validate_penetration_tester`, `validate_cross_repo_analyzer`.

**Anthropic-only:** `models.validate` (and any per-persona override) must resolve
to `via: cli` or `via: sdk`. A `via: openai` validate model is **refused at the
start of the validate step** — before discovery or any model spend — by the
model-env check (`validation/cli/_model.py`, exit code 2). Run standalone
(`vvaharness validate`), the command exits non-zero and does nothing; run as the
last step of a `scan`, Step 11 prints `[s11] WARN: validation exited with code 2`
and is skipped, leaving the s1–s9 report and s10 remediation intact. This is
*not* gated by the scan startup preflight, which only probes backend
connectivity — so with an all-OpenAI config you are not warned until the scan
reaches Step 11.

## Scoring → verdict

The panel scores each fix against four weighted gates:

| Gate | Weight |
|---|---|
| `root_cause` | 0.43 |
| `instance_coverage` | 0.2467 |
| `no_new_vulnerabilities` | 0.1867 |
| `security_best_practices` | 0.1366 |

The weighted score maps to a verdict:

| Score | Verdict |
|---|---|
| ≥ 0.80 | **Fixed** |
| ≥ 0.50 | **Partially Fixed** |
| < 0.50 | **Not Fixed** |
| — | **UNVERIFIABLE** |

**Critical-gate cap.** `no_new_vulnerabilities` is a load-bearing gate: even a score ≥ 0.80 is capped to **Partially Fixed** when that gate is `fail` or `partial` (it cannot be out-weighted by the other gates).

**UNVERIFIABLE is returned (not scored) when** the agent's criteria set is malformed (a required gate is missing or duplicated), the evaluated (non-`skip`) gate weight falls below the 0.50 coverage floor, or the critical `no_new_vulnerabilities` gate is left unevaluated (`skip`/invalid). A `skip` is weight-neutral (dropped from the denominator), so by-design partial coverage (e.g. the cross-repo 2-skip path) still scores.

The verdict is written into the DTO and `status` is set to one of:

- `validated` — fix passed
- `validation_failed` — fix did not pass (re-validatable)
- `needs_review` — the session could not produce a verdict

## Running it standalone

```bash
# Claude Agent SDK ships with vvaharness (Python >=3.10) — no extra install needed
vvaharness validate --repo /path/to/target
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-remediation/` DTOs are validated. **Required.** |
| `--config <file>` | Config profile path; else the packaged `default.yaml`. |
| `--finding <id>` | Validate this finding id (repeatable); these exact ids only, no cap. |
| `--all` | Validate every validatable finding (`awaiting_validation` / `needs_review` / `validation_failed`); bypasses the `max_findings` cap. |
| `--max-findings <n>` | Cap to the top-N validatable findings by CVSS (overrides `step_validate.max_findings`). |
| `--workspace <path>` | Staging root for per-finding copies. **Ephemeral** — removed on completion; a non-empty path is refused. Default `<repo>/security-remediation/validation`. |
| `--resume` | Skip findings already validated in a prior run (cached verdict reprinted). |
| `--scan-report <file>` | Combined report (`.md`) to enrich with validation results; defaults to the newest report under `<repo>/security-remediation/`. |

Re-runs **re-validate by default**: only DTOs already marked `validated` are
skipped. `needs_review` and `validation_failed` are validatable states, so they
are re-checked on a plain re-run. Pass `--resume` to additionally skip any
finding that was already validated earlier in the same run (its cached verdict
is reprinted).

## Configuration (`step_validate:`)

| Key | Default | Effect |
|---|---|---|
| `enabled` | `true` | Run the validator (also as Step 11 of a scan). |
| `effort` | `high` | Reasoning effort for the panel. |
| `max_turns` | `50` | Tool-loop cap. |
| `max_budget_usd` | `15.0` | Per-run soft cap. |
| `max_findings` | `20` | Top-N validatable by CVSS, for a standalone `vvaharness validate` run; `--all` bypasses, `--finding` ignores. **Note:** when validation runs as **Step 11 of a `scan`** it always validates *all* validatable findings (the stage passes `--all`), so this cap does **not** apply on the scan path. |
| `allowed_tools` | `[Read, Grep, Glob]` | Reviewer-persona tools. Bash and `Edit`/`NotebookEdit` are always denied; `Write` is gated to the panel's own output files only (`validation_report.json` / `synthesized_gates.json` under the workspace); `Agent`/orchestration tools are permitted. |

(The Claude binary is selected by the `VVAHARNESS_CLAUDE_BINARY` env var, not a
config field.)

## Trust model & outputs

The panel runs inside the **Claude Agent SDK permission sandbox**: it reads the
repo to judge each fix and writes **only** its own artifacts — it never applies
a patch, mutates source, or runs Docker. Per DTO it writes:

- the `validation` block merged back into `remediate_report.json` (with `status`)
- `validation_report.json` — the panel's per-DTO findings
- `synthesized_gates.json` — the weighted gate scores behind the verdict

See [security.md](security.md) for the full validation trust model.
