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
2.1.0.

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

`vvaharness` exposes three subcommands (`scan` is the default if omitted):

| Command | Purpose |
|---|---|
| `vvaharness scan …` | Run the full pipeline against one repo or a batch. |
| `vvaharness setup [--install-agents] [--write-env]` | Readiness wizard; `--install-agents` drops agent instructions (AGENTS.md / CLAUDE.md + skill / copilot / GEMINI.md) for your installed AI agent; `--write-env` scaffolds `.env`. |
| `vvaharness doctor [--config <file>]` | Report credential/backend readiness and run a live connectivity probe against the models the config will actually use. |
| `vvaharness estimate --repo <path>` | Print a rough scope/cost preview (file count, bytes, ~input tokens). Spends nothing. |

`.env` in the working directory is loaded automatically (variables you export
yourself take precedence), so no manual `source` step is required.

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
| `--resume` | Reuse on-disk checkpoints (`<target>/checkpoints/*.pkl`) instead of re-running completed stages. |
| `--stop-after <step>` | Stop after `clone`/`s1`/…/`s9` (debugging). `clone` stops right after acquiring repos in batch mode and implies `--keep-clones`. |
| `--skip-preflight` | Skip the startup credential/backend readiness probe. Does **not** bypass model/API authentication. |
| `--step1-config <file>` | Apply an explicit Step-1 overlay YAML (exclude_dirs/exts/globs, max_file_kb, config_dedup). Lists **append** to the config's `step1`. Mutually exclusive with `--auto-step1` (this wins). |
| `--auto-step1` | After clone, AI-survey each target to derive its Step-1 overlay; writes `<target>/checkpoints/step1.yaml` and applies it before s1. Ignored when `--step1-config` is given. Reused on `--resume`. |

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

Each step checkpoints to `<target>/checkpoints/`; `--resume` skips completed
steps. See [architecture.md](architecture.md) for the data flow and
[models.md](models.md) for how roles map to backends.

---

## 4. Backends

Each model role picks its own `{id, via}` in `config.yaml: models`:

| `via:` | Transport | Auth | Tools |
|---|---|---|---|
| `cli` *(default profile)* | `claude` CLI subprocess | run `claude` then `/login` (or `CLAUDE_CODE_OAUTH_TOKEN` via `claude setup-token`) | Read/Glob/Grep/**Bash** |
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
| `cli.yaml` | all `cli`, **+ Bash** | same as default, but you want the agentic stages (`preprocess`, `verify`) to shell out via Bash | `--config vvaharness/config/profiles/cli.yaml` |
| `full.yaml` | mixed `cli`+`sdk`+`openai` | multi-provider; set `ANTHROPIC_SDK_API_KEY` for SDK roles and `OPENAI_API_KEY` for OpenAI roles | `--config vvaharness/config/profiles/full.yaml` |

To pin your own choice, copy a profile to `./config.yaml` and edit it:
```bash
cp vvaharness/config/profiles/cli.yaml ./config.yaml   # then `vvaharness scan` uses it automatically
```

For the full walkthrough — config resolution order, `config.local.yaml`
overrides, secrets in `.env`, and every tunable knob — see
[configuration.md → Setting up your config](configuration.md#setting-up-your-config).

### Setting / changing the models

Edit the `models:` block of your config. Each of the 8 roles takes `{id, via}`
— change either independently; it's config-only, no code change:
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

---

## 5. Output

Per target, under `<target>/security-scan/`:

| File | Contents |
|---|---|
| `<module>_<ts>_report.md` | findings + dropped-findings appendix |
| `<module>_<ts>_report.sarif` | SARIF 2.1.0 for tooling ingestion |
| `<module>_<ts>_errors.jsonl` | non-fatal errors |

Batch runs also write `<workspace>/batch_summary.md`. Every run writes
`run_manifest.json` (tool version, model roles, config hash, target git SHA,
timing) so each scan is auditable. See [outputs.md](outputs.md) for the
full report/SARIF anatomy.

### Progress & logs
On an interactive terminal each stage shows a **live spinner** with the X/9
counter and elapsed time, replaced by a green `✓` + duration when it finishes
(`✗` on failure). On CI / non-TTY it prints plain `▶`/`✓`/`✗` lines. For
machine-readable output set **`VVAHARNESS_JSON_LOGS=1`** — each stage then emits
a structured JSON event (`stage_start` / `stage_ok` / `stage_fail` with timing)
instead, alongside the existing JSON artifacts (`run_manifest.json`,
`*_errors.jsonl`, SARIF).

---

## 6. Limitations (important)

- **Non-deterministic & LLM-judged.** Treat findings as leads to verify, not
  ground truth. Majority-vote false-positive filtering only engages on SDK
  models that accept `temperature`; models that reject it (e.g. Opus 4.7+) run
  single-pass, and the deterministic s5 pre-filter is the main FP defence.
- **Severity is derived from the CVSS base-score band, not judged separately.**
  Findings are labelled Critical / High / Medium / Low / Info. The four scored
  tiers come straight from the CVSS 3.1 qualitative band — Critical (9.0–10.0),
  High (7.0–8.9), Medium (4.0–6.9), Low (0.1–3.9) — so the label can never
  disagree with the reported vector, while Info covers findings with no
  demonstrated exploit path. The base score (0–10) and full vector are reported
  verbatim on each finding.
- **Token-hungry.** Cost caps are per-stage / per-finding, not global. Use
  `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **No published accuracy numbers yet.** Precision/recall measurement is a TODO.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: vvaharness` | use `pipx install .`, or run `python3 -m vvaharness …` |
| `ANTHROPIC_SDK_API_KEY not set` | put it in `.env` (auto-loaded) or export it; re-run `vvaharness doctor` |
| `claude` CLI not found / not logged in | install the Claude Code CLI, then run `claude` and use `/login` (or `claude setup-token`) |
| Scan too slow / costly on a huge repo | add exclusions in the config `step1` section or use `--auto-step1` |
| Re-run only later stages | `--resume` (reuses `<target>/checkpoints/`) |

See the other guides in this folder for [configuration](configuration.md),
[models](models.md), [outputs](outputs.md), and [batch-CSV](repos-csv.md) details.
