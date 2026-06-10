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

The core idea: **every LLM stage is a config switch.** Each role picks its own
`{id, via}` in `config.yaml: models`, and the dispatcher (`backends/llm.py`)
routes on `via:`. **Swapping a role is config-only — no code change.**

---

## 1. The two axes you combine

A run is defined by combining choices on two axes:

1. **Per-role backend** (`via:`) — `cli`, `sdk`, or `openai`, chosen
   independently for each of the 8 LLM roles.
2. **Per-stage tuning** (`step1:`…`step8:`, `inject:`, `batch:`, `output:`) —
   cost / depth / precision knobs, plus CLI flags at runtime.

---

## 2. Pipeline stages

| Step | Role | Backend? | Output |
|---|---|---|---|
| auto-step1 | `autoexclude` | yes | AI-derived Step-1 exclusion overlay (`--auto-step1`) |
| s1 preprocess | `preprocess` | yes (agentic) | repo survey + call graph → `ContextPackage` |
| s2 threatmodel | `threatmodel` | yes | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | yes | risk / taint / specialist chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | yes | per-chunk findings (×N runs + majority vote) |
| s5 prefilter | — | **deterministic** | drops low-confidence / unproven findings |
| s6 verify | `verify` | yes (agentic) | adversarial TRUE / FALSE_POSITIVE + CVSS per finding |
| s7 dedup | `dedup` | yes | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | yes | exploit-chain analysis + re-rank → `FinalReport` |
| s9 SARIF | — | **deterministic** | parses the Markdown report → SARIF 2.1.0 |

Each stage checkpoints to `<target>/checkpoints/`; `--resume` skips completed
stages. `s5` and `s9` use no model — they run the same regardless of backend.

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
| **s4 majority-vote** (`step4.runs > 1`) engages only when `deepdive` is `via: sdk` *and* the model accepts `temperature`. | Voting is auto-forced to single-pass otherwise (e.g. Opus 4.7+ reject `temperature`); the s5 prefilter becomes the main FP defence. |
| **mTLS** (`client_cert`) works only on `via: sdk` roles. | `cli` (Node has no env path) and `openai` don't support client certs — route at least one role via `sdk` for an mTLS-gated gateway. |
| **`cli` ignores** `temperature`; **honours** `max_budget_usd` / `effort`, and `max_turns` when the installed CLI supports it. | The CLI manages its own tool loop; `--max-turns` is forwarded only when the binary advertises it (probe-gated), else `--max-budget-usd` / the timeout bound the loop. |
| **`cli` agentic stages** drive the CLI with `--output-format stream-json --verbose`. | Claude CLI ≥2.1.119 rejects `--print` + `stream-json` without `--verbose`; the pairing is mandatory and emitted unconditionally. Requires a `claude` build that accepts `--verbose` with stream-json (every supported 2.x does). |
| `sdk` / `openai` auto-drop and retry params the model rejects. | Lets you mix model generations without config churn. |

---

## 4. How config helps the team — recipe profiles

The `models:` block is where the team encodes its trade-offs. Six common
shapes:

### 4.1 Quick start — Claude Code login (the shipped `default.yaml`)

Every role on one Claude model via the `claude` CLI subprocess. No SDK key —
it reuses your existing Claude Code login. (`cli.yaml` is the same layout with
`Bash` added to the agentic stages' `allowed_tools`.)

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
  threatmodel: {id: gpt-4o,          via: openai}
  decompose:   {id: gpt-4o,          via: openai}
  deepdive:    {id: claude-opus-4-8, via: sdk}
  verify:      {id: gpt-4o,          via: openai}
  dedup:       {id: claude-opus-4-8, via: sdk}
  chain:       {id: claude-opus-4-8, via: cli}
```

### 4.3 Other shapes

| Recipe | Shape | Unlocks / trade-off |
|---|---|---|
| **Max precision (voting)** | all `sdk`, `step4.runs: 4`, `vote_threshold: 3` | Majority-vote FP filtering; higher cost. |
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
| `via: sdk` | `ANTHROPIC_SDK_API_KEY` (+ optional `ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_SDK_CA_CERT`, `ANTHROPIC_SDK_CLIENT_CERT` for mTLS) |
| `via: openai` | `OPENAI_API_KEY` (+ optional `OPENAI_BASE_URL`, `OPENAI_CA_CERT`) |
| `via: cli` | Claude CLI logged in — run `claude` → `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (+ optional `CLAUDE_CLI_CA_CERT`) |

All TLS keys are optional: with just an API key the public endpoint is used and
no certificate is required. See [SETUP_GUIDE.md](SETUP_GUIDE.md) for the full
when-is-a-cert-needed matrix.

---

## 6. Commands & run-time options

| Command | Purpose |
|---|---|
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and live-probe the models the config will use. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview. Spends nothing. |

| Flag | Effect |
|---|---|
| `--repo` / `--repo-file` | Single local checkout, or batch CSV/TXT (clone + scan each). One required, mutually exclusive. |
| `--config <file>` | Use a specific config YAML (default `./config.yaml`, else packaged `default.yaml`). |
| `--application-id <id>` | Drives CMDB AppProfile lookup, VulContextSeverity scoring, SARIF `applicationId`. |
| `--group-by-app` | Batch: clone every repo sharing an AppId under one dir → one report per application. |
| `--resume` | Reuse on-disk checkpoints instead of re-running completed stages. |
| `--stop-after <step>` | Stop after `clone`/`s1`…`s9` (debugging). |
| `--auto-step1` | AI-survey each target to derive its Step-1 exclusion overlay automatically. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay (exclude dirs/exts/globs, `max_file_kb`, `config_dedup`). |
| `--keep-clones` / `--skip-preflight` | Keep cloned repos after scanning / skip the startup readiness probe. |

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
| `inject` | `cve_file`, `controls_file`, `cmdb_file` (CMDB-driven VulContextSeverity scoring). |
| `batch` | `git_token`, `git_base_url`, `skip_repo_patterns` (never clone UI-test/automation repos). |
| `output` | `preserve_on_cleanup`. |

See [configuration.md](configuration.md) for the full reference.

---

## 8. Capabilities that ride on top

These work regardless of backend choice:

- **Taint analysis** — entry→sink data-flow chunks walked across the call graph, ranked above plain risk chunks.
- **Specialist passes** — repo-wide crypto, logic-bug, access-control, batch-etl & IaC sweeps (IaC auto-gated to repos with Terraform/Docker/k8s).
- **Majority-vote FP filter** — run a chunk N× at T>0; a finding must appear in ≥ threshold runs to survive (`sdk` + `temperature`).
- **Adversarial verification** — one verifier per finding renders TRUE / FALSE_POSITIVE with its own evidence and a CVSS 3.1 score.
- **CVSS + CMDB scoring** — CVSS 3.1 base on every finding, plus optional VulContextSeverity + OffensivePriority from a CMDB export.
- **SARIF 2.1.0 output** — machine-ingestible SARIF (`tool.driver.name = "Agentic SAST"`) alongside the Markdown report, with a `tool.driver.rules[]` catalog, a CWE taxonomy referenced via `supportedTaxonomies`, and an `invocations[]` entry that marks a degraded run (`executionSuccessful=false`).
- **Secret / PII redaction** — card numbers (Luhn+IIN), SSNs, and credential material masked at the Markdown/SARIF write boundary.
- **Batch & group-by-app** — clone + scan many repos from a CSV, one report per AppId, with a `batch_summary.md`.
- **Resume + auditable runs** — checkpoints per stage; every run writes `run_manifest.json` (version, roles, config hash, git SHA, timing).

---

## 9. Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings are triage candidates, not confirmed vulnerabilities — human review is required. Two runs may differ.
- **Voting needs `sdk` + `temperature`.** Models that reject `temperature` (e.g. Opus 4.7+) and the `cli` backend always run single-pass; the deterministic s5 prefilter is then the main FP defence.
- **Severity is CVSS-derived.** Findings are labelled Critical / High / Medium / Low / Info, with the scored tiers taken straight from the CVSS 3.1 base-score band (Critical 9.0–10.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9) so the label never disagrees with the vector; Info covers findings with no demonstrated exploit path. The base score (0–10) is reported verbatim.
- **Token-hungry.** Caps are per-stage / per-finding, not global. Use `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **No published accuracy numbers yet.** Precision/recall measurement is a TODO.
