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

# vvaharness — Features & Capabilities (one-page)

**Agentic SAST** — a 9-stage LLM pipeline · 3 interchangeable backends · 42 languages · **config-driven**.
Surveys a repo → threat-models → decomposes → deep-dives → verifies → dedups → chains exploits → emits enriched **Markdown + SARIF 2.1.0**. Every stage is a config switch — swap a model/backend with **no code change**.

> Full reference: **[features.md](features.md)** · shipped profiles: **`vvaharness/config/profiles/`** (`default.yaml`, `cli.yaml`, `full.yaml`)

---

## 9-stage pipeline  (checkpointed · `--resume`)

```
s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

| Stage | Role | Model (best blend) | Output |
|---|---|---|---|
| s1 | preprocess | Sonnet 4.6 | repo survey + call graph → ContextPackage |
| s2 | threatmodel | Opus 4.8 | assets, trust boundaries, ranked threats |
| s3 | decompose | Opus 4.8 | risk / taint / specialist chunks |
| s4 | deepdive | Sonnet 4.6 · T0.4 | per-chunk findings, **×3 majority vote** |
| s5 | prefilter | *(deterministic)* | confidence + evidence gates |
| s6 | verify | Opus 4.8 | adversarial TRUE / FALSE_POSITIVE + CVSS |
| s7 | dedup | Sonnet 4.6 | deterministic + semantic dedup |
| s8 | chain | Opus 4.8 | exploit-chain analysis + re-rank → report |
| s9 | SARIF | *(deterministic)* | parse report.md → SARIF 2.1.0 |

*(auto-step1 `autoexclude` role runs on Haiku 4.5 — a cheap one-shot exclusion survey.)*

> The "best blend" column is a **recommendation**, not the shipped default. The
> packaged `default.yaml`/`cli.yaml` run every role on `claude-sonnet-4-6` via the
> `claude` CLI; mix models/backends per role in `config.yaml` to taste.

---

## 3 interchangeable backends  (`via:`)

| via: | Transport | Tools | Honours | Auth |
|---|---|---|---|---|
| `cli` *(default profile)* | `claude` subprocess | Read · Glob · Grep · **Bash** | `max_budget_usd`, `effort` | `claude /login` / `CLAUDE_CODE_OAUTH_TOKEN` |
| `sdk` | Anthropic Python SDK | Read · Glob · Grep | `temperature`, `thinking_budget`, `betas`, **mTLS** | `ANTHROPIC_SDK_API_KEY` |
| `openai` | OpenAI-compatible | Read · Glob · Grep | `temperature` | `OPENAI_API_KEY` |

**Best generic-Claude blend (2M LOC):** Opus 4.8 for reasoning/low-volume (threatmodel, decompose, verify, chain) · Sonnet 4.6 for high-volume + voting (preprocess, deepdive, dedup) · Haiku 4.5 for the survey.
**Voting note:** s4 majority vote needs `via: sdk` or `via: openai` + `temperature > 0`; `via: cli` and temp-rejecting models (Opus 4.7+) → single-pass.

---

## Inputs → Outputs

| Inputs | Effect | Outputs |
|---|---|---|
| target repo / batch CSV | code under scan | `<module>_report.md` |
| `known_cves.json` | **raises** threat likelihood / focuses the hunt | `<module>_report.sarif` (2.1.0) |
| `design_controls.yaml` | **downranks** exploitability (demands bypass proof at s6) | `errors.jsonl` |
| `cmdb.csv` | environmental VulContextSeverity scoring | `run_manifest.json` · `batch_summary.md` |

---

## 6 cross-cutting specialists  (auto-gated — skip when no matching surface)

| Specialist | Focuses on |
|---|---|
| `crypto` | weak/abusable crypto, key handling, JWT alg-confusion, IV reuse, non-CSPRNG |
| `logic-bug` | TOCTOU races, state-machine flaws, sentinel/overflow *(always on)* |
| `access-control` | IDOR/BOLA, missing authz, priv-esc, mass assignment, tenant leakage |
| `deserialization` | untrusted `readObject`/`pickle`/`yaml.load`/`BinaryFormatter` → RCE |
| `batch-etl` | pipeline path traversal, COMP-3/EBCDIC parsing, CSV formula injection |
| `iac` | wildcard IAM, public exposure, root containers, CI command injection |

---

## Core capabilities

- **Taint analysis** — entry→sink data-flow chunks across the call graph, ranked first.
- **Majority-vote FP filter** — N runs at T>0; a finding must appear in ≥ threshold runs.
- **Adversarial verification** — one verifier per finding → TRUE / FALSE_POSITIVE + CVSS.
- **CVSS 3.1 + CMDB scoring** — base CVSS + VulContextSeverity + OffensivePriority.
- **CWE taxonomy** — per-finding CWE → MITRE name + URL (77 ids mapped); SARIF taxa.
- **SARIF 2.1.0** — machine-ingestible; `tool.driver.name = "Agentic SAST"`, with a `tool.driver.rules[]` catalog, CWE `supportedTaxonomies`, and a degraded-run `invocations[].executionSuccessful` flag.
- **Secret / PII redaction** — cards (Luhn+IIN), SSNs, credentials masked at write time.
- **Batch & group-by-app** — clone+scan many repos from CSV, one report per AppId.
- **Resume + audit manifest** — per-stage checkpoints; `run_manifest.json` (version, roles, config hash, git SHA, timing).

---

## 42 language lenses  (per-language researcher hints, auto-selected by file type)

| Family | Languages |
|---|---|
| **Systems** | C/C++ · Rust · Go · Zig · Nim · Crystal · Assembly |
| **JVM / .NET** | Java · Kotlin · Scala · Groovy · C# · VB.NET · F# |
| **Scripting** | Python · JavaScript · TypeScript · PHP · Ruby · Perl · Lua · R · Shell · PowerShell · Batch |
| **Functional** | Haskell · OCaml · Clojure · Elixir · Erlang |
| **Mobile** | Swift · Objective-C · Dart |
| **Enterprise / Mainframe** | COBOL · JCL · ABAP · SQL/PL-SQL/T-SQL |
| **Web / IaC / Cloud** | Web-templates · Terraform/HCL · Ansible · Solidity · Julia |

---

> **Limitations:** findings are LLM-generated **triage candidates** — human review required. Runs are non-deterministic. Severity is labelled None / Low / Medium / High / Critical per the CVSS 3.1 bands; the base score (0–10) is reported verbatim.

*© 2026 Visa, Inc. · Apache-2.0*
