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

# Changelog

## [1.1.0] — 2026-06-30

This release extends vvaharness past detection into a full remediate-and-validate
workflow, hardens how scan state is stored, and reorganises the shipped profiles.
The nine-stage detection pipeline (S1–S9) is unchanged apart from default tuning
and a redaction fix; everything new is layered on top of it.

### Added
- **`remediate` — a new command that proposes per-finding fixes (pipeline stage
  S10).** It reads the
  findings a prior `scan` wrote under `<repo>/security-scan/` and walks them one at
  a time on a dedicated `models.remediate` role, writing a per-finding DTO and
  evidence (`diff.patch`, summary, triage) under
  `<repo>/security-remediation/<NN_slug>/`. `--mode fix` (default) applies a minimal
  diff to the working tree; `--mode report-only` proposes without editing. Other
  flags: `--top N` (or `all`/`*`) to cap by CVSS, `-i/--interactive` to pick
  findings from a menu, `--resume`, and `-v/--verbose` (live agent trace).
- **`validate` — a new command (pipeline stage S11, alias `s11`) that grades
  remediation fixes.** A
  Claude Agent SDK adversarial panel — a security architect and a penetration
  tester, plus a cross-repo reviewer when a fix spans more than one repository —
  scores each fix against four weighted gates (`root_cause`, `instance_coverage`,
  `no_new_vulnerabilities`, `security_best_practices`) and labels it **Fixed**,
  **Partially Fixed**, **Not Fixed**, or **UNVERIFIABLE**, writing the verdict back
  into the fix report. Per-CWE adversarial bypass hints can be supplied via
  `./inputs/validator_hints.yaml`. Re-runs are idempotent.
- **`gc` — a new command that prunes old run state** from the SQLite database
  (`--keep-runs` / `--max-age-days` / `--run <path>` / `--dry-run`). Reports and
  SARIF under `<repo>/security-scan/` are never touched.
- **Remediation and validation run by default at the end of `scan`.** The shipped
  default profile sets `step_remediate.enabled` and `step_validate.enabled`, so a
  plain `scan` continues past S9 into **S10 — Remediate** (fix mode: it edits source
  files in the target repo) and **S11 — Validate**. New scan flags `--remediate`
  (force it on) and `--top N`; pass `--stop-after s9` for detection only.
- **New configuration surface.** `step_remediate` / `step_validate` profile blocks
  (enabled flags, budgets, turn caps, `allowed_tools`, finding caps), new
  `models.remediate` / `models.validate` roles with per-persona overrides, and a new
  `step1.auto_exclude` key — on by default in the shipped profiles, disable with
  `--no-auto-step1`.
- **Optional remediation policy gate with an emergency kill-switch.** With
  `enforce_policy: true`, every fix passes through a gate driven by
  `inputs/remediation_policy.yaml` and `inputs/remediation_playbook.yaml`
  (deny/allow CWE maps, forbidden-path globs, a diff post-gate that reverts edits to
  forbidden paths). A kill-switch forces guidance-only output when
  `VVAHARNESS_REMEDIATE_DISABLE` is truthy or a `./.vvaharness-remediate-off` file is
  present.
- **Claude Agent SDK backend.** A new `via: sdk` backend supports file-mutating
  roles (remediation fix mode) through a sandboxed Read/Glob/Grep/Edit/Write
  tool-loop. `claude-agent-sdk` is now a core runtime dependency and ships with
  vvaharness (Python ≥ 3.10); `pydantic-settings` and `typing_extensions` were added
  as well.
- **Remediation results enrich the scan report** — fixes are reflected back into the
  Markdown report and SARIF output.

### Changed
- **Profiles reorganised.** The all-CLI `cli.yaml` profile was renamed to
  **`sdk.yaml`** and repurposed as a true all-SDK layout (every role `via: sdk`, with
  S4 majority voting on). No shipped profile grants Bash. `vvaharness setup`/`doctor`
  now recommends `sdk` when only an SDK key is present. In the default profile, scan
  roles use a high-volume tier and the post-scan remediate/validate roles use a
  higher reasoning tier.
- **The default profile now runs single-pass.** S4 majority voting is off by
  default (matching the CLI backend, which has no temperature control); the verifier
  confidence floor and neighbour-context budget were trimmed. The `full` profile
  enables S4 voting and repoints its model roles.
- **Scan resume state moved to a single SQLite store** under `~/.vvaharness/state`,
  serialised as JSON. State is validated on load and is never read from the scanned
  repo.
- **`security-remediation/` is preserved on cleanup** alongside the existing scan
  outputs.
- **Reports derive a CWE from the vulnerability class** when a finding carries none.

### Removed
- **The all-CLI `cli.yaml` profile.** Use `sdk.yaml` (all-SDK) or the `default`
  profile instead, and update any `cp …/cli.yaml config.yaml` step.
- **Reading of legacy pickle (`.pkl`) checkpoints.** Pre-upgrade resume state is not
  migrated, so `--resume` on a run started before this release begins again from S1.

### Fixed
- **Source redaction no longer over-masks ordinary numbers.** Card-number masking is
  now gated on card-likeness (a Luhn check, or a card keyword such as `card`/`acct`
  nearby), so timestamps, database IDs, and version numbers in the code the model
  sees are left intact. Real and clearly-labelled test card numbers are still masked
  before any source leaves for the model.
- **Batch mode no longer skips repositories whose names share a common tail**, and
  ambiguous agent-emitted file paths are dropped instead of being misattributed to
  the wrong finding.
- **`--max-budget-usd` is forwarded to the Claude CLI only when the installed build
  supports it**, and CLI permission-mode capability detection no longer false-matches
  help text.

### Security
- **Eliminated a code-execution risk (CWE-502).** Scan state is now stored as JSON
  in a SQLite database, never as Python pickle — validated on load and never
  deserialised from the scanned repo.
- **No agentic stage gets host-shell access.** No shipped profile grants Bash, the
  CLI backend no longer force-adds it, and on `via: sdk` the agent gate denies Bash
  even if re-added; the CLI permission mode defaults to `acceptEdits` rather than a
  blanket bypass.
- **The validation panel runs strictly read-only** — it never applies a patch or
  runs Docker — and its verdicts are computed fail-closed, so missing or hedged
  gates cannot inflate a result.
- **Remediation and diff writes are confined to the repository**, with symlinks
  rejected and UNC/network input paths refused (preventing NTLM credential leakage
  over SMB; CWE-22 path containment on the remediation-applied check).
- **Agent narrative, tool output, and persisted session logs are redacted** before
  they are stored or sent upstream.
- **Operator/CMDB and batch-summary fields are escaped** in reports to block
  Markdown/table injection, and a loud warning is emitted when TLS verification is
  disabled on the SDK/OpenAI backends.

## [1.0.0] — 2026-06-09

Initial open-source release.

### What's included
- 9-stage agentic SAST pipeline: repository survey → threat model →
  decompose → deep-dive → pre-filter → adversarial verify → dedup →
  chain → SARIF 2.1.0
- Multi-model: works with the Claude CLI, Anthropic SDK, or any
  OpenAI-compatible endpoint; mix backends per role
- Precision controls: call-graph validation, taint-flow analysis,
  multi-agent voting, CVSS 3.1 scoring
- Batch mode: clone and scan multiple repositories from a CSV manifest
- Three shipped configuration profiles: CLI-first default, Bash-enabled
  CLI, and multi-backend
