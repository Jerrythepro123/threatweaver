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

# Model Selection & Backends

Each role in `config.yaml: models` chooses its own `{id, via}`; the dispatcher
(`vvaharness/backends/llm.py`) routes on `via:`. **Every role runs on every
backend** — only Bash is `cli`-exclusive.

## Default role → backend mapping

The shipped **default profile** (`vvaharness/config/profiles/default.yaml`) runs every
role through the `claude` CLI (`via: cli`) on `claude-sonnet-4-6`, so it works
with your existing Claude Code login — no `ANTHROPIC_SDK_API_KEY` required.

| Step | Role | Default (`default.yaml`) | Switchable to |
|---|---|---|---|
| auto-step1 | `autoexclude` | `cli` | cli ⇄ sdk ⇄ openai |
| s1 preprocess | `preprocess` | `cli` | cli ⇄ sdk ⇄ openai (agentic; Bash on `cli` only) |
| s2 threatmodel | `threatmodel` | `cli` | cli ⇄ sdk ⇄ openai |
| s3 decompose | `decompose` | `cli` | cli ⇄ sdk ⇄ openai |
| s4 deepdive | `deepdive` | `cli` | cli ⇄ sdk ⇄ openai |
| s5 prefilter | — | local | — |
| s6 verify | `verify` | `cli` | cli ⇄ sdk ⇄ openai (agentic; Bash on `cli` only) |
| s7 dedup | `dedup` | `cli` | cli ⇄ sdk ⇄ openai |
| s8 chain | `chain` | `cli` | cli ⇄ sdk ⇄ openai |
| s9 SARIF | — | local | — |

Two other profiles ship under `vvaharness/config/profiles/`:

- **`cli.yaml`** — the same all-`cli` layout as `default.yaml`, but with **Bash**
  added to the agentic stages' `allowed_tools` (`step1`, `step6_verify`) so the
  explorer/verifier can shell out.
- **`full.yaml`** — an example **multi-backend** layout (a mix of `cli`, `sdk`,
  and `openai` roles) you can copy to `./config.yaml` and edit. To run roles on
  the Anthropic SDK set `ANTHROPIC_SDK_API_KEY`; for OpenAI roles set
  `OPENAI_API_KEY`.

## Backends

| `via:` | Transport | Tools | Honours |
|---|---|---|---|
| `cli` | `claude` subprocess | Read Glob Grep **Bash** | `max_budget_usd`, `effort`, `max_turns` (when the installed CLI advertises `--max-turns`) |
| `sdk` | Anthropic Python SDK | Read Glob Grep (sandboxed `backends/localtools.py`) | `temperature`, `thinking_budget`, `betas`, `max_turns` |
| `openai` | OpenAI Chat Completions (any compatible endpoint) | Read Glob Grep (sandboxed `backends/localtools.py`) | `temperature`, `max_turns` |

`via: sdk` / `via: openai` auto-drop and retry params the model rejects
(e.g. `temperature` on models that don't support it). `via: cli` is the only
backend with **Bash** — re-add `- Bash` to `step1.allowed_tools` if you switch
`preprocess` to `cli`. The `openai` client is bundled, so `via: openai` works
out of the box — it only needs `OPENAI_API_KEY`.

`via: cli` reads the optional `cli:` config block (`verify_ssl`, `ca_cert`) and
propagates TLS/proxy settings into the `claude` subprocess environment: `ca_cert`
→ `NODE_EXTRA_CA_CERTS`, `verify_ssl: false` → `NODE_TLS_REJECT_UNAUTHORIZED=0`,
and `no_proxy` → `NO_PROXY`/`no_proxy`. Auth and endpoint stay delegated to the
CLI's native precedence. All of these are optional — when their env vars are
unset they inject nothing. mTLS client certs are **`sdk`-only**
(`ANTHROPIC_SDK_CLIENT_CERT`); `via: cli` cannot use them (Node exposes no env
path — `configure()` emits a warning), and neither can `via: openai`.

A bare-string model id (e.g. `deepdive: some-model-id`) defaults to `via: cli`
for backward compatibility.

## Swapping a role

```yaml
models:
  autoexclude: {id: <model-id>, via: sdk}
  preprocess:  {id: <model-id>, via: cli}   # ← flip to get Bash in s1
  decompose:   {id: <model-id>, via: openai}
```

No code change — `backends/llm.py` `resolve()` reads `{id, via, temperature,
thinking_budget, betas}` and routes to `backends/{claude_cli,sdk,oai}.py`.
