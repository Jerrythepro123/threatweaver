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

# Visa Vulnerability Agentic Harness — Agentic SAST Pipeline

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-%E2%89%A5%203.10-blue.svg)
![Version](https://img.shields.io/badge/version-1.0.0-informational.svg)
![Output](https://img.shields.io/badge/output-Markdown%20%2B%20SARIF%202.1.0-green.svg)

VVAH is Visa's open-source harness for autonomous vulnerability discovery and
validation, using frontier AI models. Threat modeling before analysis improves
finding quality,
multi-agent deterministic voting reduces noise, and the bottleneck is triage
speed — not discovery. VVAH compresses that lifecycle from AI-discovered weakness to
validated, actionable finding, measured as Mean Time to Adapt (MTTA).

Multi-model by design, VVAH works with Anthropic Claude, OpenAI, or any
combination. No single provider is a dependency.

For setup, see [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md). This repo is not
accepting external contributions; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

> **Authorized use only.** Run scans only against code you own or have explicit
> permission to test. Findings are LLM-generated triage candidates that require
> human review — see [Limitations](#limitations-read-before-you-trust-output).

```
s1 preprocess → s2 threatmodel → s3 decompose → s4 deepdive
              → s5 prefilter   → s6 verify     → s7 dedup → s8 chain → SARIF
```

**Docs:** [SETUP_GUIDE.md](SETUP_GUIDE.md) — install & configuration · [USER_GUIDE.md](USER_GUIDE.md) — commands & options.

## Requirements

- **Python ≥ 3.10**
- An LLM credential — a Claude Code login (`claude login`) for the default
  profile, **or** an Anthropic API key (`ANTHROPIC_SDK_API_KEY`) / `OPENAI_API_KEY`
  if you switch roles to `via: sdk` / `via: openai`; see [Configure](#configure).
- The `claude` CLI — required for the default (`cli`) profile; optional otherwise.

## Install

Recommended — install into a virtual environment (keeps the install isolated).

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
```

Or install it as an isolated global command (no venv needed) on any OS:

```bash
pipx install .
```

Either way this installs one command: `vvaharness`. All three backends (Anthropic
SDK, Claude CLI, OpenAI-compatible) are available out of the box.

## Configure

**macOS / Linux:**

```bash
cp .env.example .env          # then edit .env to add your credential (see below)
```

**Windows (PowerShell):**

```powershell
Copy-Item .env.example .env   # then edit .env
```

`vvaharness` loads a `.env` automatically — it is searched for starting in the
working directory and walking up the parent directories — so no manual `source`
step is needed. (Variables you export yourself still take precedence.)

Which credential you need depends on the backend each role uses:

- **`via: cli`** (the default profile) — use a Claude Code session instead of an
  API key: run `claude` then `/login`, or set `CLAUDE_CODE_OAUTH_TOKEN` (from
  `claude setup-token`).
- **`via: sdk`** — set `ANTHROPIC_SDK_API_KEY`. Behind a private gateway, also set
  `ANTHROPIC_SDK_BASE_URL` (plus `ANTHROPIC_SDK_CA_CERT` /
  `ANTHROPIC_SDK_CLIENT_CERT` for mTLS).
- **`via: openai`** — set `OPENAI_API_KEY` (and `OPENAI_BASE_URL` for an
  OpenAI-compatible endpoint).

The default profile (`vvaharness/config/profiles/default.yaml`) runs every stage
through the `claude` CLI on `claude-sonnet-4-6` — your Claude Code login is
enough, no SDK key required. (`cli.yaml` is the same layout with `Bash` added to
the agentic stages.) To use the multi-backend layout (Claude CLI + Anthropic SDK
+ OpenAI roles), copy `vvaharness/config/profiles/full.yaml` to `./config.yaml`
and edit it.

For a step-by-step walkthrough — picking a profile, config resolution order,
secrets in `.env`, and copy-then-edit customisation — see
**[docs/configuration.md → Setting up your config](docs/configuration.md#setting-up-your-config)**.

### Which setup applies to you?

| You are… | What you need | Profile |
|---|---|---|
| **Public / subscription user** (most people) | Claude Code (`claude login`) for the default; **or** an Anthropic API key `ANTHROPIC_SDK_API_KEY=sk-ant-…` if you prefer `via: sdk` roles | `default` / `cli` (login) or `full` (key) — nothing else: no gateway, no CA cert, no extra flags |
| **Enterprise behind a private AI gateway** | also set `ANTHROPIC_BASE_URL`, plus `NODE_EXTRA_CA_CERTS` (private CA) and `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if the gateway needs them | `default` / `cli` or `full` — see [SETUP_GUIDE.md](SETUP_GUIDE.md) |

Run **`vvaharness setup`** either way — it tells you exactly what (if anything)
is missing for *your* situation. A gateway token is only flagged when you
actually have one.

See **[USER_GUIDE.md](USER_GUIDE.md)** for all commands and options and
**[SETUP_GUIDE.md](SETUP_GUIDE.md)** for detailed install/configuration.

## Run

```bash
vvaharness doctor                                   # check credentials/backends
vvaharness estimate --repo /path/to/target          # rough scope/cost, no spend
vvaharness scan --repo /path/to/target --application-id 12345
```

Batch (clone + scan, one report per AppId):

```bash
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

A `scan` run writes `run_manifest.json` (tool version, model roles, config hash,
target git SHA, timing) into the working directory. (`doctor` and `estimate`
do no scan and write no manifest.)

## Use with an AI agent (Claude / Copilot / Gemini)

So an AI agent *runs* the tool (instead of editing its source to make it work):

```bash
vvaharness setup --install-agents
```
This detects your installed agent(s) and drops the operating instructions where
each one reads them — `AGENTS.md` (cross-tool), `.github/copilot-instructions.md`
(Copilot), `CLAUDE.md` + a Claude skill in `~/.claude/skills/` (Claude Code),
`GEMINI.md` (Gemini CLI). Existing files are left untouched. See
[AGENTS.md](AGENTS.md) for the operating rules and [docs/SKILLS.md](docs/SKILLS.md)
for the analysis capabilities.

## Output

Per target, under `<target>/security-scan/`:
- `<module>_<ts>_report.md` — findings + dropped-findings appendix
- `<module>_<ts>_report.sarif` — SARIF 2.1.0
- `<module>_<ts>_errors.jsonl` — non-fatal errors

## Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings are triage candidates, not
  confirmed vulnerabilities — human review is required. Two runs may differ.
  Majority-vote FP filtering runs on the `sdk` and `openai` backends; the `cli`
  backend (no temperature control) always runs single-pass, as do SDK/OpenAI
  models that reject `temperature` (e.g. Opus 4.7+).
- **Token-hungry.** Caps are per-stage / per-finding, not global. Use
  `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **No published accuracy numbers yet.** Precision/recall figures are not yet published.
- **Elevated Privilege** This tool runs with elevated privilege and must only be used against trusted repositories by authorized operators; running it against untrusted input without the recommended hardening controls may expose host credentials, API keys, and sensitive files to exfiltration or pipeline bypass.

See `docs/` for configuration, models, pipeline, and output details.

## Security

Report vulnerabilities responsibly — see [SECURITY.md](SECURITY.md). Please do not
open security issues in a public tracker.

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2026 Visa, Inc.

Third-party dependencies are installed from PyPI at install time (not bundled
in this repository); their licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
