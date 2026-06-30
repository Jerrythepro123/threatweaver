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

**Agentic SAST** — a 9-stage LLM scan pipeline · 3 interchangeable backends · 42 languages · **config-driven**.
Surveys a repo → threat-models → decomposes → deep-dives → verifies → dedups → chains exploits → emits enriched **Markdown + SARIF 2.1.0**. A `remediate` command proposes fixes and an agentic `validate` command verifies them — both also run **in-scan by default** (see below). Every scan stage is a config switch — swap a model/backend with **no code change**.

> Full reference: **[features.md](features.md)** · shipped profiles: **`vvaharness/config/profiles/`** (`default.yaml`, `sdk.yaml`, `full.yaml`)

---

## 9-stage scan pipeline  (checkpointed · `--resume`)

```
s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → s9 SARIF
```

| Stage | Role | Model tier (best blend) | Output |
|---|---|---|---|
| s1 | preprocess | high-volume | repo survey + call graph → ContextPackage |
| s2 | threatmodel | reasoning | assets, trust boundaries, ranked threats |
| s3 | decompose | reasoning | risk / taint / specialist chunks |
| s4 | deepdive | high-volume · T0.4 | per-chunk findings, single pass (majority vote opt-in) |
| s5 | prefilter | *(deterministic)* | confidence + evidence gates |
| s6 | verify | reasoning | adversarial TRUE / FALSE_POSITIVE + CVSS |
| s7 | dedup | high-volume | deterministic + semantic dedup |
| s8 | chain | reasoning | exploit-chain analysis + re-rank → report |
| s9 | SARIF | *(deterministic)* | parse report.md → SARIF 2.1.0 |

*(exact model IDs are pinned per role in the active profile, not hard-coded here. The auto-step1 `autoexclude` role is a cheap one-shot exclusion survey; in the shipped profiles it runs on the high-volume tier in `default`/`sdk` and the reasoning tier in `full`.)*

> **The shipped `default` profile runs past s9.** Because `step_remediate.enabled`
> and `step_validate.enabled` are both true, a plain `vvaharness scan` continues
> into **s10 remediate** (fix mode — **edits source files in the target repo**)
> and **s11 validate** (the panel below) — an 11-step run. Pass `--stop-after s9`
> for detection only, or set those flags false in your profile.

### Standalone `validate` command  (agentic remediation verification)

Run separately over the remediation DTOs the `remediate` command writes. Uses the bundled Claude Agent SDK (Python ≥3.10) and an Anthropic model.

| Stage | Role | Model | Output |
|---|---|---|---|
| s10 | *(discovery)* | *(no model spend)* | locate DTOs awaiting validation |
| s11 | validate | mixed panel — `security-architect` on the reasoning tier, `penetration-tester` & `cross-repo-analyzer` on the high-volume tier (same split in every shipped profile); backend `via: cli` (default) or `via: sdk` (sdk, full) | agentic panel → weighted gate scores → Fixed / Partially Fixed / Not Fixed / UNVERIFIABLE |

> The "best blend" column is a **recommendation**, not the shipped default. The
> packaged `default.yaml` runs every **detection** role (s1–s8 + autoexclude) on
> the high-volume tier via the `claude` CLI, with `remediate` on the reasoning
> tier and the s11 `validate` panel mixed (`security-architect` on the reasoning
> tier, `penetration-tester` & `cross-repo-analyzer` on the high-volume tier) —
> all via the CLI (`sdk.yaml` runs the same detection roles via the Anthropic
> SDK, with s4 voting on); mix models/backends per role in `config.yaml` to taste.

---

## 3 interchangeable backends  (`via:`)

| via: | Transport | Tools | Honours | Auth |
|---|---|---|---|---|
| `cli` *(default profile)* | `claude` subprocess | Read · Glob · Grep · **Bash** | `max_budget_usd`, `effort` | `claude /login` / `CLAUDE_CODE_OAUTH_TOKEN` |
| `sdk` | Anthropic Python SDK | Read · Glob · Grep | `temperature`, `thinking_budget`, `betas`, **mTLS** | `ANTHROPIC_SDK_API_KEY` |
| `openai` | OpenAI-compatible | Read · Glob · Grep | `temperature` | `OPENAI_API_KEY` |

**Best generic-Claude blend (2M LOC):** the reasoning tier for low-volume reasoning roles (threatmodel, decompose, verify, chain) · the high-volume tier for high-throughput roles + voting (preprocess, deepdive, dedup) and the auto-step1 survey.
**Voting note:** s4 majority vote needs `via: sdk` or `via: openai` + `temperature > 0`; `via: cli` and temp-rejecting models → single-pass.

---

## Inputs → Outputs

| Inputs | Effect | Outputs |
|---|---|---|
| target repo / batch CSV | code under scan | `<module>_<timestamp>_report.md` |
| `known_cves.json` | **raises** threat likelihood / focuses the hunt | `<module>_<timestamp>_report.sarif` (2.1.0) |
| `design_controls.yaml` | **downranks** exploitability (demands bypass proof at s6) | `<module>_<timestamp>_errors.jsonl` |
| `cmdb.csv` | environmental VulContextSeverity scoring | `run_manifest.json` · `batch_summary.md` |
| remediation DTOs *(`validate`)* | agentic panel fills each DTO's `validation` block | `remediate_report.json` updated (status → validated / failed) |

---

## Cross-cutting specialists  (auto-gated — skip when no matching surface)

Six specialist lenses are defined; **five are active by default**
(`step3.specialists: crypto, logic-bug, access-control, batch-etl, iac`).
`deserialization` is defined and available but **opt-in** — add it to
`step3.specialists` to enable it.

| Specialist | Default | Focuses on |
|---|---|---|
| `crypto` | ✅ | weak/abusable crypto, key handling, JWT alg-confusion, IV reuse, non-CSPRNG |
| `logic-bug` | ✅ | TOCTOU races, state-machine flaws, sentinel/overflow |
| `access-control` | ✅ | IDOR/BOLA, missing authz, priv-esc, mass assignment, tenant leakage |
| `batch-etl` | ✅ | pipeline path traversal, COMP-3/EBCDIC parsing, CSV formula injection |
| `iac` | ✅ | wildcard IAM, public exposure, root containers, CI command injection |
| `deserialization` | ⬚ opt-in | untrusted `readObject`/`pickle`/`yaml.load`/`BinaryFormatter` → RCE |

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

> **Limitations:** findings are LLM-generated **triage candidates** — human review required. Runs are non-deterministic. Severity is labelled Critical / High / Medium / Low / Info per the CVSS 3.1 bands; the base score (0–10) is reported verbatim.

*© 2026 Visa, Inc. · Apache-2.0*
