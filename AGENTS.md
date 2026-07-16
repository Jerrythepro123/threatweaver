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
# AGENTS.md — How to operate vvaharness (for AI coding agents)

You are running **vvaharness**, a *released* command-line security-scanning
product. Your job is to **operate it**, not to develop or repair it.

This file is the operating manual for AI agents (Claude Code, GitHub Copilot,
Cursor, Codex, etc.). Read it fully before doing anything in this repo.

---

## 🔴 The three rules (most important)

1. **Do NOT modify the product's source to make a scan run.** Files under
   `vvaharness/` are the shipped tool. If a scan won't start, that is an
   environment problem to fix (below) or a bug to report — never a reason to
   edit `claude_cli.py`, a stage, or any package file. Hand-edited source =
   non-reproducible, unsupported results.
2. **Do NOT hand-write config files.** Everything needed is in the shipped
   profiles (`vvaharness/config/profiles/*.yaml`). Pick a profile with
   `--config`; never create a bespoke `config-*.yaml` to work around an error.
3. **When anything fails, run `vvaharness setup` (or `doctor`) and fix the
   environment it points to** — then re-run the same command. Do not improvise.

If the tool genuinely misbehaves after `setup` is green, report it as a bug
(stack trace via `VVAHARNESS_DEBUG=1`). Don't patch around it.

---

## What this tool does
A 9-stage LLM SAST pipeline: survey → threat-model → decompose → deep-dive →
pre-filter → adversarial-verify → dedup → chain → SARIF. It emits a Markdown
report + SARIF 2.1.0.

`scan` always stops after s9. It does not remediate, validate, or edit target
source files. `remediate` and `validate` are standalone commands:
`vvaharness remediate`
proposes/applies fixes over a prior scan's findings, and `vvaharness validate`
runs the agentic adversarial panel over the remediation DTOs (s11 panel —
which first discovers the DTOs awaiting validation, then runs the panel). See `docs/SKILLS.md` for the analysis capabilities and
`docs/USER_GUIDE.md` for the full command/flag reference.

## First run — always start here
```bash
pipx install .            # or: pip install .   (one command on PATH: vvaharness)
vvaharness setup         # checks Python, agents, keys, gateway, config
```
`setup` tells you exactly what (if anything) is missing and how to fix it. Do
what it says, then re-run `setup` until it prints **Ready ✓**.

To run the product's complete source test suite, use `vvaharness test` from this
checkout (or `vvaharness test --root /path/to/threatweaver`). It runs every
`tests/test_*.py` module, including s1–s9, ASAN, adaptive verification planning,
and persistent experience tests.

## Choosing a profile (don't guess — `setup` recommends one)
| You have… | Use | How |
|---|---|---|
| Claude Code auth (`claude login` / gateway token) | `default` | default — no flag |
| `ANTHROPIC_SDK_API_KEY` (sk-ant-…) | `sdk` | `--config vvaharness/config/profiles/sdk.yaml` |
| Multi-provider (Anthropic SDK + `OPENAI_API_KEY`) | `full` | `--config vvaharness/config/profiles/full.yaml` |

No shipped profile enables `Bash`. To let a `via: cli` role shell out, add
`- Bash` to its `allowed_tools` in your own copy (trusted targets only).

### Internal gateway note (common cause of 401)
If `ANTHROPIC_API_KEY` is a JWT (`eyJ…`) you are using a gateway/Claude-Code
token. It will **401 against the public API** unless you set the gateway:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem   # if it needs a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway returns "400 invalid beta flag"
```
`vvaharness setup` auto-detects this and prints the exact lines **when the active profile uses a `via: sdk` role** (e.g. `sdk`/`full`). The shipped default profile is all `via: cli`, so `setup` will not auto-print these — set them yourself if your gateway token needs them. Set them in
your shell or `.env` — **do not** edit the package to work around it.

## Running a scan
```bash
vvaharness estimate --repo /path/to/target          # scope/cost preview, no spend
vvaharness scan --repo /path/to/target --application-id <id> [--config <profile>]
```
- Progress prints per stage (`▶ … / ✓ … (Ns)`). The counter runs to **9**.
- Output: `<target>/security-scan/*_report.md`, `*.sarif`, `*_errors.jsonl`.
- A scan does not write `<target>/security-remediation/` or edit source files.
- A `run_manifest.json` (written in the current working directory, not under `security-scan/`) records models/config/timing for the run.
- After s9 completes, ASAN-confirmed bugs are copied into the persistent,
  human-editable archive at `~/.vvaharness/experience/asan/` (override with
  `VVAHARNESS_EXPERIENCE_DIR`). No experience is saved before the entire scan
  completes. Use `vvaharness experience list/show/remove/restore/validate` to
  curate it; removed entries stay rejected across future scans.
- Findings are **triage candidates, not confirmed vulnerabilities** — say so
  when you summarize them.

## When a scan fails
1. Read the one-line `✗ scan failed: …` message.
2. Run `vvaharness doctor` — fix any ✗ it reports (usually a credential or the
   gateway base-URL).
3. Re-run the same scan command. For a full stack trace: `VVAHARNESS_DEBUG=1`.
4. Still failing with a green `doctor`? **Report a bug. Do not edit source.**

## Cost & safety
- Scans spend real model tokens; large repos are expensive. Use `estimate`
  first and scope with `--repo <subdir>` or `--stop-after s3`.
- Scan only code you are authorized to scan.
- The tool never prints credential values; keep it that way.
- **Validation is a standalone command.**
  `vvaharness validate --repo <path>`
  discovers remediation DTOs written by the `remediate` command (s10, no model
  spend) and runs an agentic adversarial panel (s11) to fill each DTO's
  `validation` block. It uses the bundled Claude Agent SDK (Python ≥3.10) and an
  Anthropic model (`models.validate` must
  be `via: cli` or `via: sdk`; a `via: openai` validate model is refused before
  any model spend and the standalone `validate` command exits non-zero). The panel
  runs in the Claude Agent SDK's permission sandbox: it reads the repo and writes
  only its own validation artifacts — there is no Docker, and nothing is applied
  to the scanned repo. Re-runs are idempotent (already-`validated` DTOs are skipped;
  `validation_failed` / `needs_review` stay re-validatable).

## Do / Don't (quick reference)
| ✅ Do | ❌ Don't |
|---|---|
| `vvaharness setup` / `doctor` on any error | edit files under `vvaharness/` |
| pick a shipped `--config` profile | hand-write a config-*.yaml |
| set env vars / `.env` for creds & gateway | paste keys into config or source |
| report bugs with `VVAHARNESS_DEBUG=1` | "fix" the tool to force a run |
| invoke from outside the target with explicit `--config` | `cd` into the scanned repo then run |
| use `via: sdk` or `via: openai` for untrusted targets | use `via: cli` against repos you didn't author |
| re-run a failed scan clean | pass `--resume` against an untrusted repo |
