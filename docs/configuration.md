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

# Configuration Reference

All knobs live in `config.yaml`. Secrets are read from env vars via `${VAR}`
expansion — the CLI auto-loads a `.env` (searched from the working directory
upward through parent directories) — so never commit tokens into `config.yaml`.

## Setting up your config

`vvaharness` ships ready-to-run **profiles** — you do **not** author a config
from a blank file. "Setting up your config" means: **pick a shipped profile,
point the tool at it, and put your secrets in `.env`.** Customise only by
*copying* a profile and editing the knobs you care about — starting from a
shipped profile (never hand-writing one) is the supported path.

### 1. Which file the tool loads (resolution order)

The active config is resolved once, in this order:

1. **`--config <path>`** — an explicit profile/file (highest precedence).
2. **`./config.yaml`** — auto-detected if present in the directory you run from.
3. **the packaged `default.yaml`** — the built-in fallback.

Then, if a **`config.local.yaml`** sits next to the chosen file, its keys are
deep-merged on top (git-ignored — your machine-local overrides). Partial files
are fine: any step-knob you omit is filled from built-in defaults, so a config
never has to be exhaustive.

> The overlay can change security-relevant settings (model routing, `base_url`,
> TLS `ca_cert`, tool permissions), so the merge is **announced** on every
> command — the loader logs `config overlay: <path> applied (overrides: …)` with
> the top-level keys it changed, and its SHA-256 is recorded in
> `run_manifest.json`. It resolves next to your `--config` path (operator-owned),
> never the scanned target. For a reproducible run that honours **only** the
> selected config, set **`VVAHARNESS_NO_LOCAL_CONFIG`** (to any value) to skip
> the overlay.

> **Trust boundary — config/`.env` inside the scan target is refused.** The
> scanned repository is untrusted input. If the resolved `config.yaml` (or a
> `.env` discovered by the upward search) lives **at or under the `--repo`
> target**, it is ignored — the tool falls back to the packaged default and
> prints a `WARN` — so a config committed into a repo you are scanning cannot
> redirect your model endpoints, credentials, or TLS settings. Your own
> copy-then-edit `./config.yaml` in an operator-owned directory is unaffected
> (only paths *inside the target* are refused). To deliberately load config
> from inside a target you trust, set `VVAHARNESS_ALLOW_CWD_CONFIG=1`. The
> effective config path, any applied `config.local.yaml` overlay, and the
> loaded `.env` are echoed to stderr, and the SHA-256s of the config profile and
> the `config.local.yaml` overlay are recorded in `run_manifest.json` for
> auditability.

### 2. Pick a shipped profile

All three live in `vvaharness/config/profiles/`:

| Profile | Backends | Auth you need | Use when |
|---|---|---|---|
| **`default.yaml`** | every role `via: cli` (the `claude` subprocess); scan/verify roles get Read/Glob/Grep only (the default-on `step_remediate` role also gets `Edit`/`Write` to apply fixes) | Claude Code login / OAuth (no SDK key) | The built-in default. You have Claude Code auth and don't need the agent to shell out. |
| **`sdk.yaml`** | every role `via: sdk` (Anthropic Python SDK), sandboxed Read/Glob/Grep (no Bash) | `ANTHROPIC_SDK_API_KEY` | You have an SDK key (not Claude Code auth), or you want **s4 majority voting** — its deepdive role at `temperature: 0.4` activates `step4.runs`/`vote_threshold`. |
| **`full.yaml`** | mixed per role (`cli` + `sdk` + `openai`) | a key/auth per backend used (Claude Code login for its `via: cli` roles + Anthropic SDK + OpenAI) | You want to spread roles across backends, or template your own mix. |

> **No shipped profile grants `Bash`.** Only the `cli` backend can shell out; to
> enable it, add `- Bash` to a `via: cli` role's `allowed_tools` (e.g. `step1`,
> `step6_verify`) in your own copy — and only for a target you trust.

Not sure which? Run **`vvaharness setup`** — it inspects the credentials you
have and recommends a profile.

### 3a. Run a profile as-is

```bash
# Use a specific profile:
vvaharness scan --repo /path/to/target --config vvaharness/config/profiles/sdk.yaml

# Or omit --config to use the packaged default.yaml:
vvaharness scan --repo /path/to/target
```

### 3b. Customise it (copy-then-edit)

```bash
cp vvaharness/config/profiles/full.yaml ./config.yaml
# edit ./config.yaml — e.g. swap model ids, change a role's `via`, tune step4.runs
vvaharness scan --repo /path/to/target        # ./config.yaml is auto-detected
```

The most common edit is the `models:` block — each role is `{id: <model>, via: cli|sdk|openai}`. See [models.md](models.md) for the role/backend matrix.

### 4. Secrets go in `.env`, never in the YAML

The profiles reference env vars with `${VAR}` (or `${VAR:-default}`); an unset
var expands to empty (or the default), so a profile with no gateway/cert vars
set just runs against the public endpoint. Copy `.env.example` to `.env` and
fill in what your chosen profile needs:

| Backend / area | Env vars |
|---|---|
| SDK (`via: sdk`) | `ANTHROPIC_SDK_API_KEY` (required), `ANTHROPIC_SDK_BASE_URL`, `ANTHROPIC_SDK_CA_CERT`, `ANTHROPIC_SDK_CLIENT_CERT` |
| CLI (`via: cli`) | `CLAUDE_CODE_OAUTH_TOKEN` (or run `claude` → `/login`), `CLAUDE_CLI_CA_CERT` |
| OpenAI (`via: openai`) | `OPENAI_API_KEY` (required), `OPENAI_BASE_URL`, `OPENAI_CA_CERT` |
| Batch / git clone | `GITHUB_TOKEN`, `GIT_BASE_URL` |

Only `*_API_KEY` (for the backends your profile actually uses) are required;
the `*_BASE_URL` / `*_CA_CERT` / `*_CLIENT_CERT` vars are for private gateways
and mutual TLS — see [Backend transport](#backend-transport-sdk--openai--cli).

### 5. Validate before scanning

```bash
vvaharness doctor    # checks credentials + does a live backend connectivity probe
vvaharness setup     # full readiness report + profile recommendation
```

`doctor` resolves the **same** config a scan would (it honours `--config`), so
what it validates is exactly what the scan will run. 

## Top-level sections

| Section | Purpose | See |
|---|---|---|
| `models:` | Per-role `{id, via}` model + backend routing | [models.md](models.md) |
| `sdk:` / `openai:` / `cli:` | Backend transport (TLS/proxy). See [Backend transport](#backend-transport-sdk--openai--cli) below. | [SETUP_GUIDE.md](SETUP_GUIDE.md) |
| `step1:` … `step8:` | Per-stage scan tuning (cost, depth, precision) | below |
| `step_remediate:` / `step_validate:` | Remediation Agent (s10) and validator (s11) tuning | below |
| `inject:` | `cve_file`, `controls_file`, `cmdb_file` | [outputs.md](outputs.md#cmdb-enrichment) |
| `batch:` | `git_token`, `git_base_url`, `skip_repo_patterns` | [repos-csv.md](repos-csv.md) |
| `output:` | `preserve_on_cleanup` | [outputs.md](outputs.md) |

## Backend transport (`sdk:` / `openai:` / `cli:`)

Each backend has its own transport block holding TLS/proxy knobs. **Every key
is optional** — when its `${...}` env var is unset it expands to empty and
injects nothing, so the default profile runs with just an API key. The blocks
are only consulted by roles routed to that backend (`via: sdk`, `via: openai`,
`via: cli`).

| Key | `sdk:` | `openai:` | `cli:` |
|---|---|---|---|
| `api_key` | `${ANTHROPIC_SDK_API_KEY}` | `${OPENAI_API_KEY}` | — (CLI native auth) |
| `base_url` | `${ANTHROPIC_SDK_BASE_URL}` | `${OPENAI_BASE_URL}` | — (CLI native, `ANTHROPIC_BASE_URL`) |
| `verify_ssl` | `true` (set `false` to disable TLS verification) | `true` | `true` |
| `ca_cert` | `${ANTHROPIC_SDK_CA_CERT}` | `${OPENAI_CA_CERT}` | `${CLAUDE_CLI_CA_CERT}` |
| `client_cert` (mTLS) | `${ANTHROPIC_SDK_CLIENT_CERT}` | not supported | not supported — use `via: sdk` |
| `no_proxy` | comma-separated hosts to bypass the proxy | same | exported as `NO_PROXY`/`no_proxy` into the subprocess |

`verify_ssl` accepts a native YAML boolean or a string boolean (`"false"`,
`"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). A string is coerced to a real
boolean, so an environment-templated value like `verify_ssl: ${VERIFY_SSL:-false}`
disables verification as intended rather than being read as a CA-bundle path.
Any other string is treated as a CA-bundle path.

The `cli:` block tunes TLS/proxy for the `claude` **subprocess** only:

- `ca_cert` → exported as `NODE_EXTRA_CA_CERTS` into the subprocess env.
- `verify_ssl: false` → exports `NODE_TLS_REJECT_UNAUTHORIZED=0` (insecure;
  throwaway/test environments only).
- `client_cert` / mTLS is **not** available on `cli:` (Node exposes no env
  path — the backend emits a warning if one is set). mTLS-gated gateways must
  use a `via: sdk` role.
- Auth and endpoint stay delegated to the CLI's own precedence: run `claude`
  then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` is
  honoured if already exported. The CLI defaults to `api.anthropic.com` when
  no base URL is set.
- `effort` (e.g. `high`) pins the reasoning effort for the `claude -p`
  subprocess so a scan never inherits the operator's interactive `/effort`
  default (some models reject `xhigh`). Accepted values are typically
  `high|low|max|medium`.

**When is a cert needed?**

- Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API
  key → nothing TLS-related needed.
- Private gateway or a TLS-intercepting proxy whose server cert chains to an
  internal root CA not in the OS trust store → set the per-backend CA bundle
  env var (`ANTHROPIC_SDK_CA_CERT`, `OPENAI_CA_CERT`, or `CLAUDE_CLI_CA_CERT`).
- Gateway requires mutual TLS → `ANTHROPIC_SDK_CLIENT_CERT` (`via: sdk` only).

If only the API key is set and no base URL is given, `sdk:` defaults to
`api.anthropic.com` and `openai:` to `api.openai.com` — neither fails for lack
of a URL.

## `step1:` — repo intake & file inventory

The deterministic repo walk that feeds s3/s4 applies, in order:

1. **symlink containment** — a symlinked file whose target resolves
   **outside the repository root** is skipped (its content would otherwise be
   off-tree host data pulled into LLM prompts). In-tree symlinks (e.g. a
   monorepo linking shared source) are still scanned. This containment check is
   **unconditional**: `step1.follow_symlinks: true` no longer re-enables
   out-of-root links — they are dropped regardless (the key is still accepted
   for back-compat, with a warning that off-root targets remain blocked).
2. **`exclude_dirs` / `exclude_exts` / `exclude_globs`** — built-in defaults
   plus `config.yaml: step1:` plus any overlay (`--step1-config` /
   `--auto-step1`). Lists **append**.
3. **`max_file_kb`** — any file larger than this (default 1024 KB) is
   skipped outright; data dumps and generated blobs never reach the LLM.

After the walk, a separate pass applies:

4. **`config_dedup`** — content-based collapse of near-duplicate per-env
   config files (below).

Everything excluded — including skipped out-of-root symlinks — is itemised in
the report's *Excluded from scan* section and in the s1 checkpoint, so each
run is fully auditable.

Overlay merge semantics: top-level `exclude_*` lists **append**; nested
dicts like `config_dedup` deep-merge with **replace** (the latest
overlay's `config_dedup.exts` wins outright).

| Key | Effect |
|---|---|
| `auto_exclude` | `true` (shipped default). After each clone, AI-survey the target to derive a per-target Step-1 exclusion overlay before s1 — same as `--auto-step1`. Flag and config OR together; `--no-auto-step1` or `auto_exclude: false` opts out, `--step1-config` overrides. |
| `auto_exclude_max_tokens` | Output cap for the auto-exclude survey call (`models.autoexclude`). Default `8000`. |
| `max_budget_usd` | Hard $ cap on agentic exploration (`via: cli` only). Default `25.0`. |
| `max_turns` | Tool-loop cap (`via: sdk` / `via: openai`). Default `40`. |
| `allowed_tools` | `[Read, Glob, Grep]` — re-add `Bash` only on `via: cli`. |
| `follow_symlinks` | `false` (default). Accepted for back-compat but no longer re-enables out-of-root symlinks: links whose target resolves outside the repo root are dropped unconditionally (host-file disclosure guard), even when this is `true`. In-tree symlinks are always followed. |
| `call_graph_validate` / `_supplement` / `_rounds` / `_max_targets` | Deterministic call-graph hardening after the agentic pass. |

### `step1.config_dedup`

Repos with per-environment configs (e.g. `service/<svc>/<env>/config.yml`,
`application-{dev,qa,prod}.yml`, `values-{env}.yaml`) often carry
thousands of structurally identical files. The dedup pass:

- shape-hashes each `.yml/.yaml/.json/.toml/.ini/.properties/.conf/.cfg/.env`
  by its **key structure only** (values stripped) and clusters identical
  shapes;
- keeps **one representative per cluster** (per top-level dir, prod
  preferred) and drops the rest;
- runs a **secret / insecure-value safety net** over every file about to
  be dropped — any file with a literal credential, private key, AWS key,
  JWT, `verify: false`, `auth: none`, `debug: true`, etc. that the
  cluster rep *doesn't* already have is promoted back into scope;
- never drops a file that is unique, unparseable, oversized, or in a
  cluster smaller than `min_cluster_size`.

```yaml
step1:
  config_dedup:
    enabled: true
    min_cluster_size: 5
    keep_per_top_dir: true
    promote_on_secret_hit: true
    promote_on_insecure_value: true
    max_file_kb: 512   # dedup-pass oversize cut (distinct from step1.max_file_kb); files larger than this are kept, never dropped
    exts: [.yml, .yaml, .json, .toml, .ini, .properties, .conf, .cfg, .env]
```

## `step2:` — threat model

`enabled`, `max_tokens`, `max_threats`, `baseline` (`auto`/`owasp`/`none`),
`max_doc_chars`, `max_manifest_chars`, evidence caps
(`max_modules`, `max_entry_points`, `max_config_reps`,
`max_api_artefacts`).

## `step3:` — decompose

`taint_chunks`, `taint_max_hops`, `taint_max_chunks`,
`taint_files_per_hop`, `pack_by` (`loc`|`tokens`),
`chunk_token_budget`, `chunk_overhead_tokens`, `risk_chunk_loc`,
`catchall_enabled`, `catchall_chunk_loc`, `catchall_max_files`,
`max_files_per_chunk`, `specialists[]`, `specialist_chunk_loc`,
`timeout`, `max_tokens`.

## `step4:` — deep-dive

`parallel`, `runs`, `vote_threshold`, `specialist_runs`, `line_bucket`,
`max_findings_per_run`, `neighbor_context_lines`,
`neighbor_context_max`, `timeout`, `max_tokens`.

## `step5_prefilter:` / `step6_verify:`

`min_pre_confidence`, `require_evidence` · `parallel`, `min_confidence`,
`max_budget_usd`, `max_turns`, `allowed_tools`.

## `step7_dedup:` / `step8:`

`line_tolerance`, `semantic`, `pre_verify_threshold` (when ≥N findings survive
s5, run a semantic dedup pass *before* s6 verify to cut cost; default 25),
`max_tokens` · `max_tokens`, `timeout`.

## `step_remediate:` — Remediation Agent (s10)

Tunes the `remediate` command (and a scan's `--remediate` pass). **On by
default** (`enabled: true`); set `enabled: false` to opt out (`--remediate`
forces it on).

| Key | Effect |
|---|---|
| `enabled` | `true` (default). Run the Remediation Agent. |
| `top_n_findings` | Remediate only the top-N findings by CVSS (default `5`). Source of truth for the cap; `--top N` overrides it; `all`/`*`/`null` remediates every finding. |
| `max_budget_usd` | Per-repo soft cap (default `10.0`). |
| `max_turns` | Tool-loop cap for `via: sdk` / `via: openai` (default `40`). |
| `allowed_tools` | Fix-mode tools: `[Read, Glob, Grep, Edit, Write]` — `Edit`/`Write` apply diffs without a host shell. **Bash is omitted by design.** On `via: sdk` the SDK gate denies Bash even if re-added; on the default `via: cli` route there is no such gate, so re-adding it *would* grant a host shell — don't. |
| `enforce_policy` | `false` (opt-in). Deny-list/playbook gate + diff post-gate (reverts forbidden-path edits). |
| `policy_file` / `playbook_file` | Override paths to `remediation_policy.yaml` / `remediation_playbook.yaml` (default: shipped `inputs/`). |

The remediation model is the `models.remediate` role (see [models.md](models.md)).
Full command reference — modes, policy gate, kill-switch — in
[remediation.md](remediation.md).

## `step_validate:` — validator (s11)

Tunes the `validate` / `s11` command. **On by default** (`enabled: true`).

| Key | Effect |
|---|---|
| `enabled` | `true` (default). |
| `effort` | Reasoning effort for the panel (default `high`). |
| `max_turns` | Tool-loop cap (default `50`). |
| `max_budget_usd` | Per-run soft cap (default `15.0`). |
| `max_findings` | Top-N validatable findings by CVSS (default `20`); `--all` bypasses, `--finding` ignores. |
| `allowed_tools` | Read-only reviewer tools: `[Read, Grep, Glob]`. The session runs under a deny-by-default permission gate: `Bash` and `Edit`/`NotebookEdit` are always denied; `Write` is permitted only to the two validation output files under the target dir; read/orchestration tools (`Read`/`Grep`/`Glob`/`Agent`/`Task`/`TodoWrite`/`Skill` and `mcp__*`) are allowed. |

Full command reference — gate weights, verdict bands, per-persona overrides,
trust model — in [validation.md](validation.md).

## `inject:` — optional context inputs

| Key | Effect |
|---|---|
| `cve_file` | Known-CVE feed — raises threat likelihood / focuses the hunt. |
| `controls_file` | Design controls — downranks exploitability (demands bypass proof at s6). |
| `cmdb_file` | CMDB export — enables AppProfile lookup + VulContextSeverity scoring. |

Any file that is unset or absent is simply skipped — the pipeline still runs.
