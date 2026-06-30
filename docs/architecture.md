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
  cli.py              — console entry point: setup / doctor / estimate / gc /
                        scan / remediate / validate;
                        loads .env, checks the Python floor, resolves --config
  orchestrator/       — pipeline driver package:
                        entry.py (argparse + main), scan.py (single-repo driver),
                        batch.py (clone + group-by-app), preflight.py (backend
                        configure/probe), checkpoints.py, store.py (SQLite
                        state store), cleanup.py, cmdb.py,
                        enrich_findings.py, config_paths.py
  agentdoc.py         — AGENTS.md / CLAUDE.md / .github/copilot-instructions.md /
                        GEMINI.md / Claude skill text for `setup --install-agents`
  manifest.py         — run-level run_manifest.json (version, roles, config hash, target git SHA, timing)
  models.py           — pydantic data contracts (ContextPackage, Finding, FinalReport, …)
  config/             — config loader (${ENV} expansion, local override, step1 overlays)
    profiles/         — bundled profiles: default.yaml (all-CLI, Read/Glob/Grep),
                        sdk.yaml (all-SDK, s4 voting on), full.yaml (multi-backend)
  pipeline/stages/    — the scan analysis stages:
                        s1_preprocess, s1_autoexclude, s2_threatmodel, s3_decompose,
                        s4_deepdive, s5_prefilter, s6_verify, s7_dedup, s8_chain,
                        s11_validate (thin wrapper hooking the validation/ package
                        into the pipeline)
  remediation_agent/  — Step 10 (the `remediate` command / --remediate): proposes
                        and applies a minimal fix per verified finding and writes
                        per-finding DTOs under <repo>/security-remediation/
  validation/         — Step 11 (the `validate` command; uses the bundled Claude
                        Agent SDK): DTO discovery (no model spend) feeds the s11
                        agentic panel — a Claude Agent SDK panel of two always-on
                        personas (security-architect + penetration-tester) plus a
                        conditional cross-repo-analyzer (spawned only when a fix
                        spans 2+ repos) that scores each DTO against weighted
                        fix-quality gates inside the SDK permission sandbox
  (operator input)    — ./inputs/validator_hints.yaml (per-CWE bypass cheatsheets
                        injected into the validation session launch prompt)
  backends/           — LLM transport layer:
                        llm.py        — dispatcher; routes on `via:`
                        sdk.py        — Anthropic Python SDK
                        agent_sdk.py  — Claude Agent SDK backend for the mutating
                                        remediation `fix` role (delegated to from
                                        sdk.py under `via: sdk`); native
                                        Read/Glob/Grep/Edit/Write inside a
                                        deny-by-default (no-Bash) permission sandbox
                        oai.py        — OpenAI-compatible API
                        claude_cli.py — `claude` CLI subprocess
                        localtools.py — sandboxed Read/Glob/Grep tool-loop for sdk/openai
  report/             — enrich.py (CVSS env scoring, CMDB, Markdown→SARIF),
                        cvss.py, cwe.py, redact.py (secret/PII redaction at write time)
  injectors/          — cve_feed.py, design_controls.py (optional context loaders)
  util/               — environment (setup/doctor checks), tokens, metrics, errlog,
                        prompts, json_extract, status (progress spinner)
  lang/               — language hints (EXT_TO_LANG, LANG_HINTS, SPECIALIST_HINTS)

inputs/               — context inputs: *.example.* samples plus operator-editable
                        validator_hints.yaml / remediation_policy.yaml / remediation_playbook.yaml
scripts/              — developer helper scripts (not part of the installed package)
tests/                — smoke tests
```

## Stages (data flow)

```
        repo  +  optional inputs (known_cves, design_controls, cmdb)
                              │
   s1 preprocess  ── repo survey, call graph ─────────► ContextPackage
   s2 threatmodel ── assets, trust boundaries, threats ─► ThreatModel
   s3 decompose   ── risk/taint/catch-all/specialist chunks ► TaskManifest
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

The standalone `vvaharness validate` command runs separately, over the
remediation DTOs the `remediate` command leaves under
`<repo>/security-remediation/<NN_slug>/remediate_report.json`:

```
   remediation DTOs (status: awaiting_validation, finding + patch.diff)
                              │
   discover       ── locate DTOs awaiting validation (no model spend)
   s11 panel      ── Claude Agent SDK adversarial panel — two always-on personas
                     (security-architect + penetration-tester) plus a conditional
                     cross-repo-analyzer (only when a fix spans 2+ repos) →
                     weighted gate scores → verdict
                              │
       each DTO's `validation` block filled; status → validated | validation_failed
              | needs_review  (+ validation_report.json, synthesized_gates.json)
```

Each stage checkpoints to the SQLite state DB at
`$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/…`) —
never inside the scanned repo; `vvaharness scan --resume` skips completed
stages. `vvaharness gc` prunes old runs. The whole run is summarised in
`run_manifest.json`.

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
  after a prose-ambiguous keyword (`secret`, `token`, `credential`) is left as ordinary text.
- **Token & cost accounting** (`util/tokens.py`, `util/metrics.py`): per-stage
  buckets feed the run summary and the `step*.max_budget_usd` caps.
- **Error log** (`util/errlog.py`): non-fatal errors are appended to the
  per-scan `*_errors.jsonl`.
