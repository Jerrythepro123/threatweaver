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
report + SARIF 2.1.0. See `docs/SKILLS.md` for the analysis capabilities.

## First run — always start here
```bash
pipx install .            # or: pip install .   (one command on PATH: vvaharness)
vvaharness setup         # checks Python, agents, keys, gateway, config
```
`setup` tells you exactly what (if anything) is missing and how to fix it. Do
what it says, then re-run `setup` until it prints **Ready ✓**.

## Choosing a profile (don't guess — `setup` recommends one)
| You have… | Use | How |
|---|---|---|
| Claude Code auth (`claude login` / gateway token) | `default` | default — no flag |
| `ANTHROPIC_SDK_API_KEY` (sk-ant-…) and/or `OPENAI_API_KEY` | `full` | `--config vvaharness/config/profiles/full.yaml` |
| Claude Code auth, want Bash listed in `allowed_tools` | `cli` | `--config vvaharness/config/profiles/cli.yaml` |

### Internal gateway note (common cause of 401)
If `ANTHROPIC_API_KEY` is a JWT (`eyJ…`) you are using a gateway/Claude-Code
token. It will **401 against the public API** unless you set the gateway:
```bash
export ANTHROPIC_BASE_URL=https://<your-gateway>/
export NODE_EXTRA_CA_CERTS=$HOME/cacerts.pem   # if it needs a private CA
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 # if the gateway returns "400 invalid beta flag"
```
`vvaharness setup` auto-detects this and prints the exact lines. Set them in
your shell or `.env` — **do not** edit the package to work around it.

## Running a scan
```bash
vvaharness estimate --repo /path/to/target          # scope/cost preview, no spend
vvaharness scan --repo /path/to/target --application-id <id> [--config <profile>]
```
- Progress prints per stage (`▶ … / ✓ … (Ns)`).
- Output: `<target>/security-scan/*_report.md`, `*.sarif`, `*_errors.jsonl`.
- A `run_manifest.json` records models/config/timing for the run.
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
