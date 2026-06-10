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

# vvaharness — Setup Guide

Detailed install and configuration. For day-to-day usage and the full flag
reference, see **[USER_GUIDE.md](USER_GUIDE.md)**.

---

## 1. Prerequisites

| Need | Why |
|---|---|
| **Python ≥ 3.10**, 64-bit | runtime. The CLI also checks this at startup and exits with a clear message on older interpreters. |
| **git** on `PATH` | only for batch clone mode (`--repo-file`). |
| **Claude Code CLI, logged in** | the default profile (`default.yaml` / `cli.yaml`) runs every stage through the `claude` subprocess — run `claude` then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN`. |
| **An Anthropic API key / OpenAI key** | only if you switch roles to `via: sdk` / `via: openai` (e.g. the `full.yaml` profile — see §5). |

---

## 2. Install

`vvaharness` is distributed as a source tree with a `pyproject.toml` — it is
**not** published to PyPI, so you install it **from this folder** rather than by
name. Installing it (any option below) builds the package into your environment
and puts the **`vvaharness`** command on your PATH, so you don't have to type
`python -m vvaharness …` each time. Run the commands from the project root
(where `pyproject.toml` lives). Pick the option that fits your platform.

### Option A — pipx (recommended; fully isolated)

```bash
pipx install .
```

### Option B — virtual environment (recommended when pipx isn't available)

A venv keeps the install isolated; `vvaharness` is on your PATH whenever the
venv is active.

**Linux / macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install .
vvaharness --help
```

**Windows — PowerShell**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
vvaharness --help
```

**Windows — cmd.exe**
```bat
python -m venv .venv
.\.venv\Scripts\activate.bat
pip install .
vvaharness --help
```

### Development install

```bash
pip install -e .     # editable — code changes take effect without reinstalling
```

All installs expose one command, **`vvaharness`**, and bundle all three
backends (Anthropic SDK, Claude CLI, OpenAI-compatible) — you only need
credentials for the ones your config actually uses. Dependencies (`pydantic`,
`PyYAML`, `anthropic`, `openai`, `httpx`, `urllib3`, `python-dotenv`) are
declared in `pyproject.toml` and resolved by pip; there is no separate
requirements file.

> **`vvaharness: command not found`?** The script directory isn't on your PATH.
> Use a venv (Option B), or fall
> back to `python3 -m vvaharness …` (works from any install, any OS).

---

## 3. Credentials & `.env`

```bash
cp .env.example .env
$EDITOR .env          # fill in the keys for the backends you use
```

`vvaharness` **auto-loads** a `.env` found from the current directory upward at
startup, so you do **not** need to `source` it. Variables you export in your
shell take precedence over `.env` (handy for CI). The `.env.example` template
lists every supported variable:

| Variable | Backend / use |
|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | `via: cli` — the default profile (alternative to interactive `claude` → `/login`) |
| `ANTHROPIC_SDK_API_KEY` | `via: sdk` roles (e.g. the `full.yaml` profile) |
| `ANTHROPIC_SDK_BASE_URL` | optional gateway/region override for `via: sdk` |
| `ANTHROPIC_SDK_CA_CERT` / `ANTHROPIC_SDK_CLIENT_CERT` | optional TLS CA bundle / mTLS client cert for `via: sdk` |
| `CLAUDE_CLI_CA_CERT` | optional TLS CA bundle for `via: cli` (→ `NODE_EXTRA_CA_CERTS` on the `claude` subprocess) |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_CA_CERT` | `via: openai` |
| `GITHUB_TOKEN` / `GIT_BASE_URL` | batch clone (`--repo-file`) of private repos / URL derivation |

Verify everything is wired up (this also runs a live connectivity probe against
the configured models):

```bash
vvaharness doctor
```

`doctor` honours `--config`, so `vvaharness doctor --config ./my.yaml` checks
the exact profile that scan will use.

### Claude Code CLI auth (the default profile, and any `via: cli` role)

Install the Claude Code CLI, then authenticate one of two ways:

- **Interactive:** run `claude`, then type `/login` inside the REPL.
- **Unattended / CI:** generate a token with `claude setup-token` and set
  `CLAUDE_CODE_OAUTH_TOKEN`.

### Endpoints & TLS — base URLs and certificates

> **Public / subscription users: you can skip this whole section.** With just an
> Anthropic API key (`ANTHROPIC_SDK_API_KEY=sk-ant-…`) or `claude login`, the
> public endpoints are used automatically — **no base URL, no CA certificate,
> no extra flags.** This section is only for users behind a **private corporate
> AI gateway** (e.g. an internal endpoint with its own
> root CA). If that's not you, jump to *§4 Configuration profiles*.
>
> **Enterprise gateway, in short:** export `ANTHROPIC_BASE_URL=https://<gateway>/`,
> add `NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem` if it uses a private CA, and
> `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if it returns `400 invalid beta flag`.
> `vvaharness setup` auto-detects a gateway token and prints these exact lines.

**Base URLs are optional.** If you set only the API key(s) and leave the
`*_BASE_URL` variables unset, vvaharness uses the official public endpoints
automatically — it does **not** fail:

- Anthropic (`via: sdk`) → `https://api.anthropic.com`
- OpenAI (`via: openai`) → `https://api.openai.com/v1`

Set a base URL only to point at an internal gateway, a specific region, or any
OpenAI-compatible endpoint.

**A certificate is _never_ required.** All TLS settings — the `ca_cert` /
`client_cert` config keys, `verify_ssl`, and every `*_CA_CERT` /
`*_CLIENT_CERT` env var — are **optional** across all three backends. When
their env vars are unset they expand to empty and inject **nothing**: no custom
HTTP client on the SDK/OpenAI side, no environment change on the `claude`
subprocess. The default all-`cli` profile runs with just your Claude Code login
(and an SDK/OpenAI profile with just an API key). You only add a cert when
something in front of the endpoint demands it.

**When is a certificate needed?** Only behind a private gateway or a
TLS-intercepting corporate proxy whose server certificate chains to an
**internal root CA that isn't in your OS trust store**. For the public official
APIs (`api.anthropic.com`, `api.openai.com`) you need **no certificate and no CA
bundle at all** — the system trust store validates them.

| Situation | What to set | Applies to |
|---|---|---|
| Public endpoint (`api.anthropic.com` / `api.openai.com`) + a normal API key | **nothing** TLS-related | all backends |
| Private gateway / intercepting proxy whose server cert chains to an **internal root CA** | the per-backend CA bundle env var (see table below) | sdk, openai, cli |
| Gateway requires **mutual TLS (mTLS)** | `ANTHROPIC_SDK_CLIENT_CERT` | **`via: sdk` only** |
| Throwaway/test env where you must skip verification (**insecure**) | `verify_ssl: false` in the backend's config block | sdk, openai, cli |

Per-backend env vars / config keys:

| Backend (`via:`) | CA bundle (private/internal root CA) | mTLS client cert | Disable verification (insecure) |
|---|---|---|---|
| `sdk` (Anthropic) | `ANTHROPIC_SDK_CA_CERT` | `ANTHROPIC_SDK_CLIENT_CERT` | `verify_ssl: false` in the `sdk:` block |
| `openai` | `OPENAI_CA_CERT` | **not supported** | `verify_ssl: false` in the `openai:` block |
| `cli` (`claude` subprocess) | `CLAUDE_CLI_CA_CERT` → `NODE_EXTRA_CA_CERTS` | **not supported** (Node exposes no env path) | `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0` on the subprocess |

Notes:
- **mTLS is `via: sdk` only.** Neither the OpenAI backend nor the `claude` CLI
  backend exposes a client-certificate path — the CLI backend simply has no
  Node env var for it and emits a warning if one is configured. A gateway that
  enforces mTLS must therefore be reached through a `via: sdk` role.
- The `via: cli` backend injects TLS settings into the `claude` **subprocess**
  environment: `CLAUDE_CLI_CA_CERT` becomes `NODE_EXTRA_CA_CERTS`, and
  `verify_ssl: false` becomes `NODE_TLS_REJECT_UNAUTHORIZED=0`. Auth and
  endpoint are left to the CLI's own precedence (run `claude` then `/login`, or
  `CLAUDE_CODE_OAUTH_TOKEN`; `ANTHROPIC_BASE_URL` if already exported).
- A CA-cert path takes precedence over `verify_ssl`. If the path is set but the
  file is missing, vvaharness **warns and falls back** to normal verification
  rather than failing.
- `verify_ssl` accepts a native YAML boolean (`true` / `false`) **or** a string
  boolean (`"false"`, `"true"`, `"0"`, `"1"`, `"no"`, `"yes"`, …). This matters
  when the value is supplied via an environment template such as
  `verify_ssl: ${VERIFY_SSL:-false}` (which expands to a string): the string is
  coerced to a real boolean, so `"false"` disables verification rather than
  being mistaken for a CA-bundle path. Any other string is still treated as a
  CA-bundle path.
- When a custom CA, verify-off, or mTLS is configured, the `sdk` / `openai`
  backends build their HTTP client via the SDK's own `DefaultHttpxClient`, so
  the tuned timeouts (~600 s) and the larger connection pool are preserved
  (robustness detail; no user-facing config).

---

## 4. Configuration profiles

`vvaharness` ships three profiles under `vvaharness/config/profiles/`:

- **`default.yaml`** — every role through the `claude` CLI (`via: cli`) on
  `claude-sonnet-4-6`, with the sandboxed Read/Glob/Grep tools (no Bash). It
  reuses your Claude Code login, so no `ANTHROPIC_SDK_API_KEY` is needed. Used
  automatically when no `./config.yaml` is present.
- **`cli.yaml`** — the same all-`cli` layout, but with **Bash** added to the
  agentic stages' `allowed_tools` (`step1`, `step6_verify`) for shell-powered
  recon and evidence retrieval.
- **`full.yaml`** — an example multi-backend layout (Claude CLI + OpenAI + SDK
  roles) you can copy and edit:

  ```bash
  cp vvaharness/config/profiles/full.yaml ./config.yaml
  $EDITOR ./config.yaml
  ```

`vvaharness` automatically picks up a `./config.yaml` in the working directory
(it overrides the packaged default); `--config <file>` selects an explicit one.
A git-ignored `config.local.yaml` next to your config is deep-merged on top, for
machine-specific overrides you don't commit.

Key sections (full reference in [configuration.md](configuration.md)):

- `models` — the `{id, via}` per role (see §5).
- `step1` … `step8` — per-stage budgets, exclusions, and tuning knobs.
- `inject` — paths to optional context inputs (see §6).
- `batch` — clone token / base URL / skip patterns for `--repo-file` mode.
- `output.preserve_on_cleanup` — folders kept when a clone is purged.

---

## 5. Backends & swapping roles

| `via:` | Transport | Auth | Notes |
|---|---|---|---|
| `cli` | `claude` CLI subprocess | run `claude` then `/login`, or `CLAUDE_CODE_OAUTH_TOKEN` | the default profile; only backend with **Bash** |
| `sdk` | Anthropic Python SDK | `ANTHROPIC_SDK_API_KEY` | honours `temperature`, `max_turns`; sandboxed Read/Glob/Grep; only backend with **mTLS** |
| `openai` | OpenAI-compatible API | `OPENAI_API_KEY` | any compatible endpoint via `OPENAI_BASE_URL`; sandboxed Read/Glob/Grep |

Swapping is config-only — no code change:

```yaml
models:
  deepdive: {id: <model-id>, via: openai}
  verify:   {id: <model-id>, via: sdk}
```

See [models.md](models.md) for the role→backend matrix.

---

## 6. Optional context inputs

The `inject` block points at optional files that enrich findings. Only the
`*.example.*` templates ship; copy them to the real names referenced by the
config (or point `inject.*` at your own paths):

```bash
cp inputs/cmdb.example.csv          inputs/cmdb.csv
cp inputs/known_cves.example.json   inputs/known_cves.json
cp inputs/design_controls.example.yaml inputs/design_controls.yaml
```

If a file is absent the pipeline still runs — the corresponding enrichment is
simply skipped (e.g. without a CMDB export, base CVSS + OffensivePriority are
still computed; only VulContextSeverity environmental scoring is skipped). The
real-data filenames (`inputs/cmdb.csv`, `inputs/repos.csv`,
`inputs/design_controls.yaml`, `inputs/known_cves.json`) are git-ignored, so
they aren't committed by an ordinary `git add` — only the shipped
`*.example.*` templates are tracked. (A `git add -f` can still force one in,
so don't override the ignore for a file holding real internal data.)

For batch scanning, see [repos-csv.md](repos-csv.md) and the worked
example at `inputs/repos.example.csv`.

---

## 7. Verifying the install

```bash
vvaharness --help
vvaharness doctor
vvaharness estimate --repo /path/to/some/repo
```

If `doctor` reports all configured backends present and reachable, you're ready
to `vvaharness scan` (see [USER_GUIDE.md](USER_GUIDE.md)).
