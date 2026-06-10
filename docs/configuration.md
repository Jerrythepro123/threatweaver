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
> loaded `.env` are echoed to stderr, and their SHA-256s are recorded in
> `run_manifest.json` for auditability.

### 2. Pick a shipped profile

All three live in `vvaharness/config/profiles/`:

| Profile | Backends | Auth you need | Use when |
|---|---|---|---|
| **`default.yaml`** | every role `via: cli` (the `claude` subprocess), Read/Glob/Grep only | Claude Code login / OAuth (no SDK key) | The built-in default. You have Claude Code auth and don't need the agent to shell out. |
| **`cli.yaml`** | every role `via: cli`, **with `Bash`** added to the agentic stages | Claude Code login / OAuth (no SDK key) | Same as default, but you want shell-powered recon/evidence retrieval (`Bash` in `step1`/`step6_verify`). |
| **`full.yaml`** | mixed per role (`cli` + `sdk` + `openai`) | a key per backend used (Anthropic SDK + OpenAI) | You want to spread roles across backends, or template your own mix. |

Not sure which? Run **`vvaharness setup`** — it inspects the credentials you
have and recommends a profile.

### 3a. Run a profile as-is

```bash
# Use a specific profile:
vvaharness scan --repo /path/to/target --config vvaharness/config/profiles/cli.yaml

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
| `step1:` … `step8:` | Per-stage tuning (cost, depth, precision) | below |
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

1. **`exclude_dirs` / `exclude_exts` / `exclude_globs`** — built-in defaults
   plus `config.yaml: step1:` plus any overlay (`--step1-config` /
   `--auto-step1`). Lists **append**.
2. **`max_file_kb`** — any file larger than this (default 1024 KB) is
   skipped outright; data dumps and generated blobs never reach the LLM.
3. **`config_dedup`** — content-based collapse of near-duplicate per-env
   config files (below).
4. **symlink containment** — a symlinked file whose target resolves
   **outside the repository root** is skipped (its content would otherwise be
   off-tree host data pulled into LLM prompts). In-tree symlinks (e.g. a
   monorepo linking shared source) are still scanned. Set
   `step1.follow_symlinks: true` to also follow out-of-root links (not
   recommended when scanning untrusted repositories).

Everything excluded — including skipped out-of-root symlinks — is itemised in
the report's *Excluded from scan* section and in the s1 checkpoint, so each
run is fully auditable.

Overlay merge semantics: top-level `exclude_*` lists **append**; nested
dicts like `config_dedup` deep-merge with **replace** (the latest
overlay's `config_dedup.exts` wins outright).

| Key | Effect |
|---|---|
| `max_budget_usd` | Hard $ cap on agentic exploration (`via: cli` only). |
| `max_turns` | Tool-loop cap (`via: sdk` / `via: openai`). |
| `allowed_tools` | `[Read, Glob, Grep]` — re-add `Bash` only on `via: cli`. |
| `follow_symlinks` | `false` (default). When `true`, also follow symlinks whose target resolves outside the repo root. Leave off for untrusted targets. |
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
    exts: [.yml, .yaml, .json, .toml, .ini, .properties, .conf, .cfg, .env]
```

## `step2:` — threat model

`enabled`, `max_threats`, `baseline` (`auto`/`owasp`/`none`),
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
