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

# Features & Combinations

A single reference for **everything you can combine** when running
`vvaharness`, and **how config lets the team mix and match models per stage
without touching code**.

```
s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

The standalone `vvaharness validate` command runs separately (s11 agentic
panel — which first discovers the DTOs awaiting validation, then runs the
panel) over the remediation DTOs written by the `remediate` command (Step 10) — see [§2](#2-pipeline-stages) and [§6](#6-commands--run-time-options).

The core idea: **every LLM stage is a config switch.** Each role picks its own
`{id, via}` in `config.yaml: models`, and the dispatcher (`backends/llm.py`)
routes on `via:`. **Swapping a role is config-only — no code change.**

---

## 1. The two axes you combine

A run is defined by combining choices on two axes:

1. **Per-role backend** (`via:`) — `cli`, `sdk`, or `openai`, chosen
   independently for each scan LLM role. (The `validate` command's role is
   Anthropic-only — `via: cli` or `via: sdk`.)
2. **Per-stage tuning** (`step1:`…`step4:`, `step5_prefilter:`,
   `step6_verify:`, `step7_dedup:`, `step8:`, `step_remediate:`,
   `step_validate:`, `inject:`, `batch:`, `output:`) — cost / depth / precision knobs, plus CLI flags at
   runtime.

---

## 2. Pipeline stages

| Step | Role | Backend? | Output |
|---|---|---|---|
| auto-step1 | `autoexclude` | yes | AI-derived Step-1 exclusion overlay (`--auto-step1`) |
| s1 preprocess | `preprocess` | yes (agentic) | repo survey + call graph → `ContextPackage` |
| s2 threatmodel | `threatmodel` | yes | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | yes | risk / taint / specialist chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | yes | per-chunk findings (single pass by default; ×N runs + majority vote when enabled) |
| s5 prefilter | (`dedup`) | **deterministic gates** | drops low-confidence / unproven findings; runs one optional semantic pre-dedup call (the `dedup` role) when survivors ≥ `step7_dedup.pre_verify_threshold` (default 25) and `step7_dedup.semantic` is on |
| s6 verify | `verify` | yes (agentic) | adversarial TRUE / FALSE_POSITIVE + CVSS per finding |
| s7 dedup | `dedup` | yes | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | yes | exploit-chain analysis + re-rank → `FinalReport` |
| s9 SARIF | — | **deterministic** | parses the Markdown report → SARIF 2.1.0 |

Each `scan` stage checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`);
`--resume` skips completed stages. `s9` uses no model. `s5`'s gates are
deterministic, but it also fires one optional semantic pre-dedup call (the
`dedup` role) when the survivor count reaches `step7_dedup.pre_verify_threshold`.

The standalone **`vvaharness validate`** command runs two further stages over
the remediation DTOs the `remediate` command writes: **s10** discovers DTOs
awaiting validation (no model spend), and **s11** runs an agentic adversarial
panel (Claude Agent SDK: two always-on personas `security-architect` +
`penetration-tester`, plus a conditional `cross-repo-analyzer` spawned only when
a fix spans 2+ repositories) that fills each DTO's `validation` block. `models.validate` must be a Claude model
(`via: cli` or `via: sdk`); a `via: openai` validate model is refused at the
start of the validate step, before any model spend — the standalone `validate`
command exits non-zero, and inside a `scan` Step 11 is skipped with a warning
while the rest of the scan is unaffected. The Claude
Agent SDK ships as a core dependency (Python ≥3.10).

These same two stages also run automatically at the **end of a `scan`** —
Step 10 (remediate) then Step 11 (validate) — when `step_remediate.enabled` /
`step_validate.enabled` are set, which all three shipped profiles default to `true`.
Run the standalone command to re-validate (or validate findings remediated out
of band) on its own.

---

## 3. Backends (`via:`)

| `via:` | Transport | Auth | Tools | Honours | TLS / mTLS |
|---|---|---|---|---|---|
| `cli` *(default profile)* | `claude` CLI subprocess | run `claude` → `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | Read · Glob · Grep · **Bash** | `max_budget_usd`, `effort` | `ca_cert` → `NODE_EXTRA_CA_CERTS`; **no mTLS** |
| `sdk` | Anthropic Python SDK | `ANTHROPIC_SDK_API_KEY` | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `thinking_budget`, `betas`, `max_turns` | `ca_cert` + **`client_cert` (mTLS)** |
| `openai` | OpenAI-compatible Chat Completions | `OPENAI_API_KEY` (+ `OPENAI_BASE_URL`) | Read · Glob · Grep *(sandboxed, no Bash)* | `temperature`, `max_turns` | `ca_cert`; no mTLS |

**Every role runs on every backend** — only **Bash** is `cli`-exclusive. A
bare-string model id (e.g. `deepdive: some-model`) defaults to `via: cli` for
backward compatibility.

### Combination rules that actually matter

| Rule | Why |
|---|---|
| **Bash** is available only in agentic stages (`preprocess`, `verify`) when that role is `via: cli`. | Only the CLI backend exposes Bash; re-add `- Bash` to `allowed_tools` when you switch. |
| **s4 majority-vote** (`step4.runs > 1`) engages only when `deepdive` is `via: sdk` or `via: openai` *and* the model accepts `temperature`. | Voting is auto-forced to single-pass on `via: cli` and on temp-rejecting **`via: sdk`** models; the s5 prefilter becomes the main FP defence. (On `via: openai` a temp-rejecting model is *not* auto-collapsed — the runs proceed but the endpoint drops `temperature`, so you pay N× for identical samples; point `deepdive` at a temperature-capable model to make voting effective.) |
| **mTLS** (`client_cert`) works only on `via: sdk` roles. | `cli` (Node has no env path) and `openai` don't support client certs — route at least one role via `sdk` for an mTLS-gated gateway. |
| **`cli` ignores** `temperature`; **honours** `max_budget_usd` / `effort`, and `max_turns` when the installed CLI supports it. | The CLI manages its own tool loop; `--max-turns` is forwarded only when the binary advertises it (probe-gated), else `--max-budget-usd` / the timeout bound the loop. |
| **`cli` agentic stages** drive the CLI with `--output-format stream-json --verbose`. | Recent Claude CLI builds reject `--print` + `stream-json` without `--verbose`; the pairing is mandatory and emitted unconditionally. Requires a `claude` build that accepts `--verbose` with stream-json (every supported 2.x does). |
| `sdk` / `openai` auto-drop and retry params the model rejects. | Lets you mix model generations without config churn. |

---

## 4. How config helps the team — recipe profiles

The `models:` block is where the team encodes its trade-offs. Six common
shapes:

### 4.1 Quick start — Claude Code login (the shipped `default.yaml`)

Every role on one Claude model via the `claude` CLI subprocess. No SDK key —
it reuses your existing Claude Code login. (`sdk.yaml` is an all-SDK variant —
every role `via: sdk` with `ANTHROPIC_SDK_API_KEY`, and s4 majority voting on.)

```yaml
models:
  autoexclude: {id: claude-sonnet-4-6, via: cli}
  preprocess:  {id: claude-sonnet-4-6, via: cli}
  threatmodel: {id: claude-sonnet-4-6, via: cli}
  decompose:   {id: claude-sonnet-4-6, via: cli}
  deepdive:    {id: claude-sonnet-4-6, via: cli}
  verify:      {id: claude-sonnet-4-6, via: cli}
  dedup:       {id: claude-sonnet-4-6, via: cli}
  chain:       {id: claude-sonnet-4-6, via: cli}
```

### 4.2 Multi-backend — the example `full.yaml`

Mix vendors per role: reasoning/voting on the Anthropic SDK, exploration/Bash on
the CLI, threat-model/decompose/verify on an OpenAI-compatible endpoint.

```yaml
models:
  autoexclude: {id: claude-opus-4-8, via: cli}
  preprocess:  {id: claude-opus-4-8, via: sdk}
  threatmodel: {id: gpt-5.5,         via: openai}
  decompose:   {id: gpt-5.5,         via: openai}
  deepdive:    {id: claude-sonnet-4-6, via: sdk, temperature: 0.4}  # T0.4 → s4 voting on
  verify:      {id: gpt-5.5,         via: openai}
  dedup:       {id: claude-opus-4-8, via: sdk}
  chain:       {id: claude-opus-4-8, via: cli}
```

### 4.3 Other shapes

| Recipe | Shape | Unlocks / trade-off |
|---|---|---|
| **Max precision (voting)** | shipped on in `sdk.yaml` (deepdive `temperature: 0.4`, `step4.runs: 3`, `vote_threshold: 2`); raise toward `temperature: 1.0` / `runs: 4` / `vote_threshold: 3` for more | Majority-vote FP filtering; higher cost. Forced to single-pass on `via: cli` or temp-rejecting models. |
| **Bash-powered recon** | `preprocess` + `verify` → `cli` (add `- Bash`), rest `sdk` | Shell-based repo inventory & evidence retrieval. |
| **Air-gapped + mTLS** | all `sdk` with `ca_cert` + `client_cert` | Private gateway behind mutual TLS (sdk-only). |
| **Cost-lean** | all `openai` | Cheapest endpoint; no Bash, single-pass deepdive. |

**To use any of these:** save the block as `./config.yaml` (or copy
`vvaharness/config/profiles/full.yaml` and edit), then run
`vvaharness doctor` to live-probe exactly the models the config will use
before spending a token.

---

## 5. Credentials per combination

Which credentials a run needs is the **union of the backends any role uses**:

| If any role is… | You need |
|---|---|
| `via: sdk` | `ANTHROPIC_SDK_API_KEY` (when sdk is the *only* backend, `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` are accepted as a fallback) (+ optional `ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_SDK_CA_CERT`, `ANTHROPIC_SDK_CLIENT_CERT` for mTLS) |
| `via: openai` | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`, `OPENAI_CA_CERT`) |
| `via: cli` | Claude CLI logged in — run `claude` → `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (+ optional `CLAUDE_CLI_CA_CERT`) |

All TLS keys are optional: with just an API key the public endpoint is used and
no certificate is required. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for the full
when-is-a-cert-needed matrix.

---

## 6. Commands & run-time options

| Command | Purpose |
|---|---|
| `vvaharness setup` | Guided readiness check (Python/git, AI agents, keys, gateway, config); read-only unless `--write-env`, optional `--install-agents`. (Alias: `init`.) |
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and propose a minimal fix per finding (Remediation Agent, s10). On by default in a scan. |
| `vvaharness validate --repo <path>` | Run the agentic panel over remediation DTOs (s10 discover + s11). Uses the bundled Claude Agent SDK. On by default in a scan (`step_validate.enabled`). (Alias: `s11`.) |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and live-probe the models the config will use. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview. Spends nothing. |
| `vvaharness gc […]` | Prune old checkpoint runs (`--keep-runs` / `--max-age-days` / `--dry-run`). |

| Flag | Effect |
|---|---|
| `--repo` / `--repo-file` | Single local checkout, or batch CSV/TXT (clone + scan each). One required, mutually exclusive. |
| `--config <file>` | Use a specific config YAML (default `./config.yaml`, else packaged `default.yaml`). |
| `--repo-name <name>` | Module / repository name used for report + SARIF filenames and the report title (single-repo mode only; default: target dir name). |
| `--application-id <id>` | Drives CMDB AppProfile lookup, VulContextSeverity scoring, SARIF `applicationId`. |
| `--group-by-app` | Batch: clone every repo sharing an AppId under one dir → one report per application. |
| `--resume` | Reuse on-disk checkpoints instead of re-running completed stages. |
| `--stop-after <step>` | `scan`: stop after `clone`/`s1`…`s11`. |
| `--auto-step1` / `--no-auto-step1` | Force AI auto-exclude on (survey each target to derive its Step-1 overlay) / hard-disable it for this run, overriding the profile's `step1.auto_exclude`. Mutually exclusive. |
| `--workspace <dir>` | Batch: directory to clone remote repos into (default `./batch-workspace`). |
| `--remediate` / `--top <N\|all\|*>` | Run the Remediation Agent (s10) after the scan; `--top` caps it to the N highest-CVSS findings. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay (exclude dirs/exts/globs, `max_file_kb`, `config_dedup`). |
| `--keep-clones` / `--skip-preflight` | Keep cloned repos after scanning / skip the startup readiness probe. |
| `--force` | Override safety refusals (currently: the s10 git-SHA staleness check when HEAD moved since the scan). |

`validate` accepts `--repo` (required), `--config`, `--finding` (repeatable),
`--all`, `--max-findings`, `--workspace`, `--resume`, and `--scan-report`.

```bash
vvaharness estimate --repo /path/to/target                      # preview scope/cost, no spend
vvaharness scan --repo /path/to/target --application-id 12345
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

---

## 7. Per-stage tuning knobs

| Block | Key knobs |
|---|---|
| `step1` *(intake & inventory)* | `max_budget_usd`, `max_turns`, `allowed_tools`, `exclude_dirs/exts/globs`, `max_file_kb`, call-graph hardening (`validate`/`supplement`/`rounds`/`max_targets`), `config_dedup` (collapse per-env configs, never dropping secrets). |
| `step2` *(threat model)* | `enabled`, `max_threats`, `baseline` (`auto`/`owasp`/`none`), evidence caps (`max_modules`, `max_entry_points`, `max_config_reps`, `max_api_artefacts`). |
| `step3` *(decompose)* | `taint_chunks` + `taint_max_hops/chunks/files_per_hop`, `pack_by` (`loc`/`tokens`), `catchall_enabled`, `specialists[]` (crypto · logic-bug · access-control · batch-etl · iac), chunk LOC caps. |
| `step4` *(deep-dive)* | `parallel`, `runs` + `vote_threshold`, `specialist_runs`, `max_findings_per_run`, `neighbor_context_lines/max`, `timeout`, `max_tokens`. |
| `step5_prefilter` | `min_pre_confidence`, `require_evidence`. |
| `step6_verify` | `parallel`, `min_confidence`, `max_budget_usd`, `max_turns`, `allowed_tools`. |
| `step7_dedup` | `line_tolerance`, `semantic` (toggle LLM dedup), `max_tokens`. |
| `step8` | chain `timeout`, `max_tokens`. |
| `step_remediate` *(`remediate` cmd / `--remediate`)* | `enabled` (on by default), `top_n_findings`, `max_budget_usd`, `max_turns`, `allowed_tools` (`Read/Glob/Grep/Edit/Write`, no Bash), `enforce_policy`, `policy_file`/`playbook_file`. |
| `step_validate` *(`validate` cmd)* | `enabled`, `effort`, `max_turns`, `max_budget_usd`, `max_findings`, `allowed_tools`. (The Claude binary is the `VVAHARNESS_CLAUDE_BINARY` env var, not a config field.) |
| `inject` | `cve_file`, `controls_file`, `cmdb_file` (CMDB-driven VulContextSeverity scoring). |
| `batch` | `git_token`, `git_base_url`, `skip_repo_patterns` (never clone UI-test/automation repos). |
| `output` | `preserve_on_cleanup`. |

See [configuration.md](configuration.md) for the full reference.

---

## 8. Capabilities that ride on top

These work regardless of backend choice:

- **Taint analysis** — entry→sink data-flow chunks walked across the call graph, ranked above plain risk chunks.
- **Specialist passes** — repo-wide crypto, logic-bug, access-control, batch-etl & IaC sweeps (IaC auto-gated to repos with Terraform/Docker/k8s).
- **Majority-vote FP filter** — run a chunk N× at T>0; a finding must appear in ≥ threshold runs to survive (`sdk`/`openai` + `temperature`).
- **Adversarial verification** — one verifier per finding renders TRUE / FALSE_POSITIVE with its own evidence and a CVSS 3.1 score.
- **CVSS + CMDB scoring** — CVSS 3.1 base on every finding, plus optional VulContextSeverity + OffensivePriority from a CMDB export.
- **SARIF 2.1.0 output** — machine-ingestible SARIF (`tool.driver.name = "Agentic SAST"`) alongside the Markdown report, with a `tool.driver.rules[]` catalog, a CWE taxonomy referenced via `supportedTaxonomies`, and an `invocations[]` entry that marks a degraded run (`executionSuccessful=false`).
- **Secret / PII redaction** — card numbers (Luhn+IIN), SSNs, and credential material masked at the Markdown/SARIF write boundary.
- **Batch & group-by-app** — clone + scan many repos from a CSV, one report per AppId, with a `batch_summary.md`.
- **Resume + auditable runs** — checkpoints per stage; every run writes `run_manifest.json` (version, roles, config hash, git SHA, timing).

---

## 9. Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings are triage candidates, not confirmed vulnerabilities — human review is required. Two runs may differ.
- **Voting needs `sdk`/`openai` + `temperature`.** Models that reject `temperature` and the `cli` backend always run single-pass; the deterministic s5 prefilter is then the main FP defence.
- **Severity is CVSS-derived.** Findings are labelled Critical / High / Medium / Low / Info, with the scored tiers taken straight from the CVSS 3.1 base-score band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9) so the label never disagrees with the vector; Info covers findings with no demonstrated exploit path. The base score (0–10) is reported verbatim.
- **Token-hungry.** Caps are per-stage / per-finding, not global. Use `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **Validation is Anthropic-only, and so is remediation _fix mode_.** The `validate` panel refuses a `via: openai` role (aborts with exit code 2); remediation _fix mode_ needs the `Edit`/`Write` tools only the `via: cli` / `via: sdk` (Anthropic) backends expose, so a `via: openai` remediate role can only run `--mode report-only`. Detection (S1–S9) and report-only remediation run on any backend.
- **Elevated privilege; trusted targets only.** vvaharness assumes an authorized operator running against a repository they trust; scanning untrusted or malicious code can expose host credentials, files, or other risk. If you must scan a less-trusted or sensitive target, apply the compensating controls in [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.
