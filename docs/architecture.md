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

# Architecture

Module map and data flow for the `vvaharness` package.

## Module layout

```
vvaharness/
  cli.py              — console entry point: setup / doctor / estimate / scan; loads .env,
                        checks the Python floor, resolves --config
  orchestrator/       — pipeline driver package:
                        entry.py (argparse + main), scan.py (single-repo driver),
                        batch.py (clone + group-by-app), preflight.py (backend
                        configure/probe), checkpoints.py, cleanup.py, cmdb.py,
                        enrich_findings.py, config_paths.py
  agentdoc.py         — AGENTS.md / CLAUDE.md / skill text for `setup --install-agents`
  manifest.py         — run-level run_manifest.json (version, roles, config hash, timing)
  models.py           — pydantic data contracts (ContextPackage, Finding, FinalReport, …)
  config/             — config loader (${ENV} expansion, local override, step1 overlays)
    profiles/         — bundled profiles: default.yaml (all-CLI, Read/Glob/Grep),
                        cli.yaml (all-CLI + Bash), full.yaml (multi-backend)
  pipeline/stages/    — the analysis stages:
                        s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
                        s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain
  backends/           — LLM transport layer:
                        llm.py        — dispatcher; routes on `via:`
                        sdk.py        — Anthropic Python SDK
                        oai.py        — OpenAI-compatible API
                        claude_cli.py — `claude` CLI subprocess
                        localtools.py — sandboxed Read/Glob/Grep tool-loop for sdk/openai
  report/             — enrich.py (CVSS env scoring, CMDB, Markdown→SARIF),
                        cvss.py, cwe.py, redact.py (secret/PII redaction at write time)
  injectors/          — cve_feed.py, design_controls.py (optional context loaders)
  util/               — environment (setup/doctor checks), tokens, metrics, errlog,
                        prompts, json_extract, status (progress spinner)
  lang/               — language hints (EXT_TO_LANG, LANG_HINTS, SPECIALIST_HINTS)

inputs/               — example context inputs (*.example.*)
scripts/              — developer helper scripts (not part of the installed package)
tests/                — smoke tests
```

## Stages (data flow)

```
        repo  +  optional inputs (known_cves, design_controls, cmdb)
                              │
   s1 preprocess  ── repo survey, call graph ─────────► ContextPackage
   s2 threatmodel ── assets, trust boundaries, threats ─► ThreatModel
   s3 decompose   ── risk/taint/specialist chunks ─────► TaskManifest
   s4 deepdive    ── per-chunk findings (×N + vote) ───► Finding[]
   s5 prefilter   ── deterministic confidence/evidence gates
   s6 verify      ── adversarial TRUE/FALSE_POSITIVE + CVSS per finding
   s7 dedup       ── deterministic + semantic dedup ───► canonical Finding[]
   s8 chain       ── exploit-chain analysis + re-rank ─► FinalReport
   s9 SARIF       ── parse the Markdown report ────────► *_report.sarif
                              │
            <target>/security-scan/<module>_<ts>_report.{md,sarif}
                          + <module>_<ts>_errors.jsonl
```

Each stage checkpoints to `<target>/checkpoints/`; `vvaharness scan --resume`
skips completed stages. The whole run is summarised in `run_manifest.json`.

## LLM transport layer

All model calls go through `backends/llm.py`, which reads the per-role
`{id, via, …}` config node via `resolve()` and dispatches to the matching
backend:

| `via:` | Module | Transport |
|---|---|---|
| `sdk` | `backends/sdk.py` | Anthropic Python SDK |
| `openai` | `backends/oai.py` | OpenAI-compatible Chat Completions |
| `cli` | `backends/claude_cli.py` | `claude` CLI subprocess |

`sdk` and `openai` run their agentic Read/Glob/Grep tool-loop through
`backends/localtools.py` (sandboxed to the target repo, no Bash); `cli` uses the
CLI's native tools (including Bash). Roles are swapped in config alone — see
[models.md](models.md).

## Cross-cutting concerns

- **Config** (`config/`): `${ENV:-default}` expansion, optional
  `config.local.yaml` deep-merge, and per-scan `step1` overlays.
- **Redaction** (`report/redact.py`): card/PII/credential material is masked at
  the Markdown and SARIF write boundary so it never lands on disk. Card numbers
  are Luhn+IIN gated and SSNs area/group/serial gated for precision; values
  following a strong credential keyword (`password`, `api_key`, `access_key`,
  `client_secret`, `auth_token`) are always masked, while a short lowercase word
  after a prose-ambiguous keyword (`secret`, `token`) is left as ordinary text.
- **Token & cost accounting** (`util/tokens.py`, `util/metrics.py`): per-stage
  buckets feed the run summary and the `step*.max_budget_usd` caps.
- **Error log** (`util/errlog.py`): non-fatal errors are appended to the
  per-scan `*_errors.jsonl`.
