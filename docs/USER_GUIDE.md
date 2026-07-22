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

# vvaharness — User Guide

Agentic SAST pipeline. It surveys a code repo, threat-models it, decomposes it
into analysis chunks, deep-dives each, adversarially verifies findings,
deduplicates, analyses exploit chains, and emits a Markdown report + SARIF
2.1.0. A separate `validate` command verifies remediations with an agentic
adversarial panel.

> **Read this first:** findings are **LLM-generated triage candidates, not
> confirmed vulnerabilities.** Human review is required. Runs are
> non-deterministic — two scans of the same repo may differ. See *Limitations*.

For full installation and credential/config setup, see
**[SETUP_GUIDE.md](SETUP_GUIDE.md)**.

---

## Quick install (per OS)

Requires Python ≥ 3.10. Any path below puts the **`vvaharness`** command on
your PATH (no need to type `python -m vvaharness …`).

**Recommended — `pipx` (isolated, no virtualenv to activate):**
```bash
pipx install .        # gives a global `vvaharness` command in its own env
```

> **Is a virtualenv required? No.** A venv just *isolates* dependencies; `pipx`
> already does that for you, and `pip install .` / `pip install --user .` work
> without one. Use a venv only if you prefer manual isolation or can't use
> pipx. Pick **one** of the paths below — don't combine them.

**Linux / macOS — venv (alternative):**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
```

**Windows — PowerShell**
```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install .
```

**Windows — cmd.exe**
```bat
python -m venv .venv & .\.venv\Scripts\activate.bat
pip install .
```

Prefer an isolated global tool? `pipx install .`. No venv/pipx? `pip install
--user .` (ensure the user-scripts dir is on PATH). See
[SETUP_GUIDE.md](SETUP_GUIDE.md) for all options, credentials, TLS/proxy, and
config profiles.

---

## 1. Commands

`vvaharness` exposes these subcommands (a bare invocation prints help):

| Command | Purpose |
|---|---|
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness remediate --repo <path>` | Walk a prior scan's findings and propose a minimal fix per finding (Remediation Agent, s10). Writes DTOs under `<repo>/security-remediation/`. See [§2b](#2b-remediate--propose-fixes). |
| `vvaharness validate --repo <path>` | Verify remediation DTOs with an agentic adversarial panel (s10 discover + s11). Uses the bundled Claude Agent SDK. (Alias: `s11`.) |
| `vvaharness setup [--install-agents] [--write-env]` | Readiness wizard; `--install-agents` drops agent instructions (AGENTS.md / CLAUDE.md + skill / copilot / GEMINI.md) for your installed AI agent; `--write-env` scaffolds `.env`. (Alias: `init`.) |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and run a live connectivity probe against the models the config will actually use. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview (file count, bytes, ~input tokens). Spends nothing. |
| `vvaharness gc [--keep-runs N] [--max-age-days N] [--run <path>] [--dry-run]` | Prune old checkpoint runs from the SQLite state DB (defaults: keep 100 runs / 5 days). `--run <path>` instead fully evicts the single run for that repo path (its `run_id` is path-derived). |
| `vvaharness test [--root <checkout>] [pytest flags]` | Run every test module under `tests/`, covering s1–s9, ASAN, adaptive verification planning, CLI, orchestration, reports, remediation, and validation. Returns pytest's exit code. |

A `.env` found from the current directory upward (the first match in the cwd or
any ancestor) is loaded automatically (variables you export yourself take
precedence), so no manual `source` step is required. The file actually loaded is
printed as a `[env] loaded …` line.

---

## 2. `scan` — flags

| Flag | Effect |
|---|---|
| `--repo <path>` | Scan a single local checkout. **Mutually exclusive** with `--repo-file`; one of the two is required. |
| `--repo-file <file>` | Batch mode. A `.csv` with header `AppId,RepoName[,Path]` (see [repos-csv.md](repos-csv.md)) or a `.txt` with one `application_id,repository_name,path` per line. Each entry is cloned/scanned in sequence with a fresh context. |
| `--config <file>` | Use a specific config YAML. Default: `./config.yaml` if present, else the packaged `default.yaml` profile. |
| `--repo-name <slug>` | Module / `repositoryName` tag for report filenames and SARIF `run.properties` (single-repo mode; defaults to the directory name). |
| `--application-id <id>` | Application / asset identifier — drives CMDB AppProfile lookup, VulContextSeverity environmental scoring, and SARIF `run.properties.applicationId`. |
| `--workspace <dir>` | Where remote repos are cloned in batch mode. Default `./batch-workspace`. |
| `--group-by-app` | Batch mode: clone every repo sharing an AppId under `<workspace>/<AppId>/` and run **one** scan over that directory (one report per application instead of one per repo). |
| `--keep-clones` | Don't delete cloned repos after scanning (batch mode). |
| `--resume` | Reuse on-disk checkpoints (SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db`, default `~/.vvaharness/state/…`) instead of re-running completed stages. **Assumes the source is unchanged since the checkpointed run** — vvaharness does not detect code edits here. If the target changed, omit `--resume` (a fresh scan is clean) or run `vvaharness gc --run <path>` first to evict stale state. |
| `--experimental-streaming-verification` | Experimental latency mode: as each s4 chunk completes voting, candidates that pass finding-local s5 policy gates begin s6 static verification while remaining chunks continue; each high-confidence static true positive immediately enters the serialized shared-build ASAN session when ASAN is enabled. The complete s4 population still passes through authoritative s5 dedup before verifier results are accepted. The legacy batch flow remains the default. Disabled with `--stop-after s4` or `s5` to avoid unexpected verifier spend. |
| `--stop-after <step>` | Stop after `clone`/`s1`/…/`s9` (debugging). `clone` stops right after acquiring repos in batch mode and implies `--keep-clones`. |
| `--skip-preflight` | Skip the startup credential/backend readiness probe. Does **not** bypass model/API authentication. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay YAML (exclude_dirs/exts/globs, max_file_kb, config_dedup). Lists **append** to the config's `step1`. Mutually exclusive with `--auto-step1` (this wins). |
| `--auto-step1` | After clone, AI-survey each target to derive its Step-1 overlay; writes `$VVAHARNESS_STATE_DIR/checkpoints/<run_id>/step1.yaml` and applies it before s1. Ignored when `--step1-config` is given. Reused on `--resume`. **Also enabled via `step1.auto_exclude` in config — on by default in the shipped `default` profile.** To opt a run out, use a profile with `step1.auto_exclude: false`. |
| `--no-auto-step1` | Hard-disable AI auto-exclude for this run, **irrespective of `step1.auto_exclude` in the default/sdk/full profile**. Wins over `--auto-step1` and any config default (mutually exclusive with `--auto-step1`). Use this to say "no" from the command line without editing a profile. |

### Examples

```bash
# Preview scope/cost (spends nothing)
vvaharness estimate --repo /path/to/target

# Scan a local checkout
vvaharness scan --repo /path/to/target --application-id 12345

# Batch — clone + scan many repos, one report per AppId
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

---

## 2a. `validate` — verify remediations

`vvaharness validate` is a standalone command that scores remediations produced
by the `remediate` command. It discovers each finding's DTO under
`<repo>/security-remediation/<NN_slug>/remediate_report.json` (s10 — discovery
only, no model spend) and runs an agentic adversarial panel (s11) that fills the
DTO's `validation` block and sets `status` to `validated` (fix passed),
`validation_failed` (fix did not pass; re-validatable), or `needs_review` (no
verdict produced). Re-runs are idempotent: only `validated` DTOs are skipped;
`validation_failed` and `needs_review` stay re-validatable, so a corrected patch
is re-driven on the next run with no manual DTO edit.

```bash
# Claude Agent SDK ships with vvaharness (Python >=3.10) — no extra install needed
vvaharness validate --repo /path/to/target
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-remediation/` DTOs are validated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml` if present, else the packaged `default.yaml`. |
| `--finding <id>` | Validate this finding id (repeatable); these exact ids only, no cap. |
| `--all` | Validate every awaiting finding (bypasses the `max_findings` cap). |
| `--max-findings <n>` | Cap to the top-N awaiting findings by CVSS (overrides `step_validate.max_findings`). |
| `--workspace <path>` | Staging root for per-finding copies. **Ephemeral** — removed on completion; a non-empty path is refused. Default `<repo>/security-remediation/validation`. |
| `--resume` | Skip findings already validated in a prior run (cached verdict reprinted). |
| `--scan-report <file>` | Combined report (`.md`) to enrich with validation results; defaults to the newest report under `<repo>/security-remediation/`. |

The panel uses Claude Agent SDK subagents (`security-architect` +
`penetration-tester`, plus a conditional `cross-repo-analyzer`) and scores each
fix against weighted gates → a Fixed / Partially Fixed / Not Fixed /
UNVERIFIABLE verdict. It is **Anthropic-only** (`models.validate` must be
`via: cli` or `via: sdk`) and runs inside the SDK permission sandbox (read-only,
no patch application, no Docker).

**See [validation.md](validation.md)** for the full reference — gate weights,
verdict bands, per-persona model overrides, `step_validate` knobs, and the
trust model.

---

## 2b. `remediate` — propose fixes

`vvaharness remediate` reads a prior scan's findings from
`<repo>/security-scan/` and walks them with the Remediation Agent (step 10),
running the configured `models.remediate` role per finding. For each finding it
writes a DTO under `<repo>/security-remediation/<NN_slug>/remediate_report.json`
(consumed later by `validate`). It runs only when invoked as a standalone command.

```bash
# Standalone: remediate the findings of a completed scan
vvaharness remediate --repo /path/to/target

# Only the 10 highest-CVSS findings, interactive picker, report-only (no edits)
vvaharness remediate --repo /path/to/target --top 10 -i --mode report-only
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-scan/` findings are remediated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml`, else packaged `default.yaml`. |
| `--mode fix\|report-only` | `fix` (default) applies minimal diffs via Edit/Write — **requires an Anthropic backend (`via: cli`/`via: sdk`)**, as `via: openai` has no edit tools; `report-only` proposes without touching files and works on any backend. |
| `--top <N\|all\|*>` | Remediate only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` does every finding). |
| `-i`, `--interactive` | Pick which findings to remediate from a menu. |
| `--resume` | Skip findings already remediated in a prior run. |
| `-v`, `--verbose` | Print the prompt + raw LLM response per finding. |

The fix-mode tool set is `Read/Glob/Grep/Edit/Write` (cwd-confined) — **Bash is
denied** so a prompt-injected agent can't reach a host shell.

**See [remediation.md](remediation.md)** for the full reference — modes, the
`step_remediate` knobs, the policy gate, and the kill-switch.

---

## 3. Pipeline stages

| Step | Role | Output |
|---|---|---|
| s1 preprocess | `preprocess` (+ `autoexclude` for `--auto-step1`) | repo survey → `ContextPackage` |
| s2 threatmodel | `threatmodel` | assets, trust boundaries, ranked threats |
| s3 decompose | `decompose` | analysis chunks → `TaskManifest` |
| s4 deepdive | `deepdive` | per-chunk findings (×N runs + majority vote when enabled) |
| s5 prefilter | — (deterministic) | drops low-confidence / unproven findings |
| s6 verify | `verify` | adversarial TRUE/FALSE_POSITIVE verdict + CVSS per finding |
| s7 dedup | `dedup` | deterministic + semantic dedup → canonical findings |
| s8 chain | `chain` | exploit-chain analysis + re-ranking → `FinalReport` |
| s9 SARIF | — (deterministic) | parses the Markdown report → SARIF 2.1.0 |

Each step checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`;
`run_id` is derived from the absolute target path); `--resume` skips
completed steps. A scan **without** `--resume` clears that run's prior
checkpoints first, so a fresh scan never inherits stale state. `--resume`
**trusts that the source is unchanged** since the checkpointed run — it does
**not** detect code edits, so resume only after a clean/aborted run on the same
code; if the code changed, omit `--resume` or run `vvaharness gc --run <path>`
to evict the run. Run `vvaharness gc` to prune old runs. See
[architecture.md](architecture.md) for the data flow and
[models.md](models.md) for how roles map to backends.

---

## 4. Backends

Each model role picks its own `{id, via}` in `config.yaml: models`:

| `via:` | Transport | Auth | Tools |
|---|---|---|---|
| `cli` *(default profile)* | `claude` CLI subprocess | run `claude` then `/login` (or `CLAUDE_CODE_OAUTH_TOKEN` via `claude setup-token`) | Read/Glob/Grep (the only backend that *can* also run **Bash** — but no shipped profile grants it; add `- Bash` to a role's `allowed_tools` to enable) |
| `sdk` | Anthropic Python SDK | `ANTHROPIC_SDK_API_KEY` | Read/Glob/Grep (sandboxed) — honours `temperature`, `max_turns` |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | Read/Glob/Grep (sandboxed) |

### Shipped profiles & how to switch (modes)

Three ready profiles live in `vvaharness/config/profiles/`. Run
`vvaharness setup` — it **recommends** the one matching the credentials you
have. Select a profile per run with `--config`; with no flag, a `./config.yaml`
in the working dir wins, else the packaged `default.yaml`.

| Profile | Backend(s) | Use when… | Run |
|---|---|---|---|
| `default.yaml` | all `cli` (Read/Glob/Grep) | you have Claude Code auth (`claude login` / OAuth token) — **no SDK key needed**. The built-in default. | *(no flag)* |
| `sdk.yaml` | all `sdk` (Anthropic Python SDK; sandboxed Read/Glob/Grep, no Bash) | you have `ANTHROPIC_SDK_API_KEY` (not Claude Code auth), or you want s4 majority voting (deepdive @ `temperature: 0.4`, `runs: 3`/`vote_threshold: 2`) | `--config vvaharness/config/profiles/sdk.yaml` |
| `full.yaml` | mixed `cli`+`sdk`+`openai` | multi-provider; set `ANTHROPIC_SDK_API_KEY` for SDK roles and `OPENAI_API_KEY` for OpenAI roles | `--config vvaharness/config/profiles/full.yaml` |

To pin your own choice, copy a profile to `./config.yaml` and edit it:
```bash
cp vvaharness/config/profiles/sdk.yaml ./config.yaml   # then `vvaharness scan` uses it automatically
```

For the full walkthrough — config resolution order, `config.local.yaml`
overrides, secrets in `.env`, and every tunable knob — see
[configuration.md → Setting up your config](configuration.md#setting-up-your-config).

### Setting / changing the models

Edit the `models:` block of your config. Each of the 8 scan-pipeline roles
(plus `remediate` and `validate`) takes `{id, via}` — change either
independently; it's config-only, no code change. **Exception:** `validate`
(and its `validate_*` personas) is **Anthropic-only** — `via` must be `cli`
or `sdk`; a `via: openai` validate role aborts the validate stage with exit
code 2. **Also:** `remediate` in **fix mode** needs an Anthropic backend
(`via: cli` or `via: sdk`) — only those expose the `Edit`/`Write` tools that
apply a fix; a `via: openai` remediate role is limited to `--mode report-only`
(it can read and propose, but cannot edit files).
```yaml
models:
  deepdive:   {id: claude-opus-4-8,  via: sdk}     # SDK on a public Opus
  verify:     {id: claude-sonnet-4-6, via: cli}    # ← flip one role to the CLI
  threatmodel:{id: gpt-4o,           via: openai}  # ← or to OpenAI
  # …autoexclude, preprocess, decompose, dedup, chain…
```
- `id` is whatever your endpoint accepts (a public id, a dated id, or a CLI
  alias like `sonnet`/`opus`).
- After editing, run `vvaharness doctor --config <file>` — it live-probes every
  unique model so a bad id/credential fails *before* a scan spends tokens.

### Internal gateway (if your key is a Claude-Code/JWT token)
Set the endpoint in your shell or `.env` (NOT in source); `setup` auto-detects
and prints the exact lines:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem   # only if a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway rejects beta flags (HTTP 400)
```

**TLS / private gateways.** All three backends carry an optional `verify_ssl` /
`ca_cert` block in the profile — including a `cli:` block whose CA bundle
(`${CLAUDE_CLI_CA_CERT}`) is propagated into the `claude` subprocess. Every TLS
setting is **optional**: with only an API key set, the public official endpoint
is used and **no certificate is required**. A CA bundle is needed only behind a
private gateway or a TLS-intercepting proxy whose cert chains to an internal CA.
Mutual TLS (mTLS client certs) is supported on **`via: sdk` only**, not `via: cli`
or `via: openai`. See **[SETUP_GUIDE.md](SETUP_GUIDE.md)** for the full
when-is-a-cert-needed matrix and env-var names.

**Pinning the `claude` executable (shared/CI hosts).** `via: cli` roles (and the
`validate` command) launch the `claude` CLI; by default it is resolved to an
absolute path via `PATH`. On a shared or CI host where `PATH` may include a
directory another user can write, set **`VVAHARNESS_CLAUDE_BINARY=/abs/path/to/claude`**
to pin the exact executable and bypass `PATH` resolution entirely (prevents a
planted `claude` from running under the harness with your credentials).

### Environment variables

Backend **credentials and endpoints** (`ANTHROPIC_SDK_API_KEY`,
`ANTHROPIC_SDK_BASE_URL`, `OPENAI_API_KEY`, `CLAUDE_CODE_OAUTH_TOKEN`,
`ANTHROPIC_BASE_URL`, `NODE_EXTRA_CA_CERTS`, …) go in `.env` — see
[`configuration.md`](configuration.md) and [`SETUP_GUIDE.md`](SETUP_GUIDE.md).
The harness-specific `VVAHARNESS_*` knobs are:

| Variable | Default | Effect |
|---|---|---|
| `VVAHARNESS_STATE_DIR` | `~/.vvaharness/state` | Root for the SQLite state DB (`vvaharness.db`), checkpoints, and the batch staging area. Reports under `<repo>/security-scan/` are unaffected. |
| `VVAHARNESS_DEBUG` | unset | On a fatal scan error, print the full Python traceback to stderr (otherwise a one-line redacted message + a pointer to `*_errors.jsonl`). Set to any value. |
| `VVAHARNESS_JSON_LOGS` | unset | Emit structured JSON stage events (`stage_start`/`stage_ok`/`stage_fail`) instead of the `▶`/`✓`/`✗` lines. Accepts `1`/`true`/`yes`. |
| `VVAHARNESS_CLAUDE_BINARY` | `claude` (on `PATH`) | Absolute path to the `claude` executable, bypassing `PATH` (see *Pinning the `claude` executable* above). |
| `VVAHARNESS_ALLOW_CWD_CONFIG` | unset (gate active) | Opt out of the trust gate that refuses a `--config` / `.env` located **inside the scan target** (which otherwise falls back to the packaged default / is ignored). Set only for a target you trust. |
| `VVAHARNESS_NO_LOCAL_CONFIG` | unset (overlay applied) | Skip the `config.local.yaml` overlay for a reproducible run that honours **only** the selected config. |
| `VVAHARNESS_REMEDIATE_DISABLE` | unset | Kill-switch for autonomous remediation: when truthy (`1`/`true`/`yes`/`on`), the remediation gate returns guidance-only for **every** finding (active when `step_remediate.enforce_policy: true`; a `./.vvaharness-remediate-off` file is an equivalent sentinel). See [`remediation.md`](remediation.md). |
| `VVAHARNESS_GHE_TOKEN` / `VVAHARNESS_GHE_ARCHIVED_TOKEN` | unset | GitHub Enterprise tokens passed to the `validate` agent for `gh api` calls (surfaced to the session as `GH_ENTERPRISE_TOKEN` / `GH_ARCHIVED_TOKEN`). |

> The `validate`/`s11` subsystem also reads a family of overrides
> (`VVAHARNESS_MODEL`, `VVAHARNESS_EFFORT`, `VVAHARNESS_VIA`, `VVAHARNESS_MAX_TURNS`,
> `VVAHARNESS_MAX_BUDGET_USD`, `VVAHARNESS_MAX_FINDINGS`, `VVAHARNESS_VALIDATE_TOOLS`,
> and the per-persona `VVAHARNESS_{SECURITY_ARCHITECT,PENETRATION_TESTER,CROSS_REPO_ANALYZER}_MODEL`).
> **Don't set these by hand** — the validation CLI exports them automatically from
> your profile's `models.validate` / `step_validate` block. Tune the profile, not
> the environment.

---

## 5. Output

Per target, under `<target>/security-scan/`:

| File | Contents |
|---|---|
| `<module>_<ts>_report.md` | successful findings that survived verification; canonical input for SARIF and remediation |
| `<module>_<ts>_unconfirmed.md` | statically verified vulnerabilities that ASAN did not runtime-confirm; rendered with the same full evidence detail as confirmed findings |
| `<module>_<ts>_report.sarif` | SARIF 2.1.0 for tooling ingestion |
| `<module>_<ts>_errors.jsonl` | non-fatal errors |

The `validate` command writes per-DTO under
`<repo>/security-remediation/<NN_slug>/`: the `validation` block is merged back
into `remediate_report.json` (with `status` set to
`validated`/`validation_failed`/`needs_review`), plus a redacted
`validation_session_<finding>.jsonl` transcript. The agent's
`validation_report.json` and `synthesized_gates.json` are written into an
ephemeral staging workspace, consumed for host-side scoring, and removed on
completion — they are **not** persisted under the DTO folder.

Batch runs also write `<workspace>/batch_summary.md`. Every run writes
`run_manifest.json` in the current working directory (tool version, model
roles, config hash, target git SHA, timing) so each scan is auditable. See [outputs.md](outputs.md) for the
full report/SARIF anatomy.

### Progress & logs
On an interactive terminal each stage shows a **live spinner** with the X/11
counter and elapsed time, replaced by a green `✓` + duration when it finishes
(`✗` on failure). On CI / non-TTY it prints plain `▶`/`✓`/`✗` lines. For
machine-readable output set **`VVAHARNESS_JSON_LOGS=1`** — each stage then emits
a structured JSON event (`stage_start` / `stage_ok` / `stage_fail` with timing)
instead, alongside the existing JSON artifacts (`run_manifest.json`,
`*_errors.jsonl`, SARIF).

---

## 6. Limitations (important)

- **Non-deterministic & LLM-judged.** Treat findings as leads to verify, not
  ground truth. Majority-vote false-positive filtering only engages on `via: sdk` or
  `via: openai` deep-dive models whose runs actually diverge (a model that
  accepts `temperature`); the `via: cli` backend has no temperature control and
  SDK models that reject it run single-pass, and the deterministic s5 pre-filter is the main FP defence.
- **Severity is derived from the CVSS base-score band, not judged separately.**
  Findings are labelled Critical / High / Medium / Low / Info. The four scored
  tiers come straight from the CVSS 3.1 qualitative band — Critical (9.0–10.0),
  High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9) — so the label can never
  disagree with the reported vector, while Info covers findings with no
  demonstrated exploit path. The base score (0–10) and full vector are reported
  verbatim on each finding.
- **Token-hungry.** Cost caps are per-stage / per-finding, not global. Use
  `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **Validation is Anthropic-only; remediation _fix mode_ is too.** The `validate`
  panel refuses a `via: openai` role (aborts with exit code 2). Remediation _fix
  mode_ needs the `Edit`/`Write` tools that only the `via: cli`/`via: sdk`
  (Anthropic) backends expose — under `via: openai` it can only run
  `--mode report-only`. Detection (S1–S9) and report-only remediation run on any
  backend.
- **Elevated privilege; trusted targets only.** vvaharness assumes an authorized
  operator running against a repository they trust. Scanning untrusted or
  malicious code can expose host credentials, files, or other risk. If you must
  scan a less-trusted or sensitive target, apply the compensating controls in
  [`security.md` → Hardening for less-trusted or sensitive targets](security.md#hardening-for-less-trusted-or-sensitive-targets).
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: vvaharness` | use `pipx install .`, or run `python3 -m vvaharness …` |
| `ANTHROPIC_SDK_API_KEY not set` | put it in `.env` (auto-loaded) or export it; re-run `vvaharness doctor` |
| `claude` CLI not found / not logged in | install the Claude Code CLI, then run `claude` and use `/login` (or `claude setup-token`) |
| Scan too slow / costly on a huge repo | add exclusions in the config `step1` section or use `--auto-step1` |
| Re-run only later stages | `--resume` (reuses checkpoints in `$VVAHARNESS_STATE_DIR/vvaharness.db`) |

See the other guides in this folder for [configuration](configuration.md),
[models](models.md), [outputs](outputs.md), and [batch-CSV](repos-csv.md) details.
