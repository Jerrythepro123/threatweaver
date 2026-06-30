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
![Version](https://img.shields.io/badge/version-1.1.0-informational.svg)
![Output](https://img.shields.io/badge/output-Markdown%20%2B%20SARIF%202.1.0-green.svg)

VVAH is Visa's open-source harness for autonomous vulnerability discovery
using frontier AI models, built on learnings from
[Project Glasswing](https://www.anthropic.com/glasswing) (Anthropic's
initiative for AI-assisted vulnerability research).

VVAH runs in two phases. **Phase 1 — Detection** (`scan`, stages S1–S9) finds and
reports issues. **Phase 2 — Remediation & Validation** (S10–S11, on by default)
then **proposes a fix** per finding (`remediate`) and **validates** those fixes with
an adversarial panel (`validate`).

Three design choices drive finding quality: threat modeling before analysis
focuses the attack surface; multi-agent deterministic voting reduces false
positives; and structured triage artifacts compress the lifecycle from
AI-discovered weakness to actionable finding. The bottleneck in AI-assisted
vulnerability management is triage speed, not discovery — VVAH is designed
around that constraint. The primary effectiveness metric is **Mean Time to
Adapt (MTTA)**: time from AI-discovered weakness to a validated fix in
production.

Multi-model by design, VVAH works with Anthropic Claude, OpenAI, or any
combination. No single provider is a dependency.

For setup, see [`docs/SETUP_GUIDE.md`](docs/SETUP_GUIDE.md). This repo is not
accepting external contributions; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

> **Authorized use only.** Run scans only against code you own or have explicit
> permission to test. Findings are LLM-generated triage candidates that require
> human review — see [Limitations](#limitations-read-before-you-trust-output).

**Docs:** [SETUP_GUIDE.md](docs/SETUP_GUIDE.md) — install & configuration · [USER_GUIDE.md](docs/USER_GUIDE.md) — commands & options.

---

## Quick start

```bash
pip install .                                          # venv / pipx options under Install
vvaharness doctor                                      # check credentials & backends
vvaharness estimate --repo /path/to/target             # rough scope/cost — spends nothing
vvaharness scan --repo /path/to/target --stop-after s9 # detection only — no code changes
```

> ⚠️ **A plain `scan` edits your code.** The shipped default profile continues past detection into
> remediation _fix mode_, which **edits source files in the target repo**. Add `--stop-after s9` for
> detection only (no code changes).

New here? Follow [Install](#install) → [Configure](#configure) → [Run](#run).

---

## Pipeline

**Phase 1 — Detection (`scan`, S1–S9).** Nine stages combine deterministic
controls with frontier-model reasoning to produce structured, exploit-validated
findings:

| Stage group | Stages | Purpose |
|---|---|---|
| Discovery & Modeling | S1–S3 | Attack surface mapping, threat modeling, hunting plan |
| Deep Dive & Verification | S4–S6 | Multi-lens research, policy gates, adversarial verification |
| Synthesis, Chaining & Reporting | S7–S9 | Deduplication, chain construction, SARIF emission |

**Phase 2 — Remediation & Validation (S10–S11, on by default).** After detection,
the shipped `default.yaml` runs two more steps. The three core commands map cleanly
to the workflow:

- **`scan`** — finds issues (the detection pipeline above).
- **`remediate`** (S10) — proposes, and in fix mode applies, a minimal fix per finding.
- **`validate`** (S11) — checks those fixes with an agentic adversarial panel.

(The CLI also ships `setup`, `doctor`, `estimate`, and `gc` — run `vvaharness --help`.)

> ⚠️ Because Phase 2 is on by default, a plain `vvaharness scan` runs all 11 steps and
> **edits source files in the target repo** (S10 fix mode). For detection only, pass
> `--stop-after s9` — see [Quick start](#quick-start).

Standardized inputs (batch repositories, GitHub Enterprise metadata, CMDB records,
CVE and control feeds) flow in; structured reports, SARIF artifacts, and API-ready
findings flow out. See [`docs/architecture.md`](docs/architecture.md) for
stage-by-stage detail.

---

## Skills

Each LLM-driven pipeline stage is implemented as a composable, reusable skill.
Two stages have no skill of their own: **S9** (SARIF emission) is fully
deterministic, and **S5** (pre-filter) runs deterministic gates plus one
*optional* semantic-dedup call that reuses the S7 `dedup` role — fired only when
the survivor count reaches `step7_dedup.pre_verify_threshold` (default 25) and
`step7_dedup.semantic` is on (default true). Skills can be independently tuned,
versioned, and replaced without rewiring the pipeline.

| Stage | Skill |
|---|---|
| S1 — Explore the attack surface | Attack surface mapper (code, CMDB, CVE, controls) |
| S2 — Model threats in business context | AppSec threat modeler (STRIDE, OWASP, trust boundaries) |
| S3 — Strategize and prioritize | Vulnerability research strategist (taint, API boundaries, authorization controls) |
| S4 — Research by specialized lens | Language, Crypto, Logic-bug, Access-control, Batch/ETL, IaC (Deserialization defined but not default-enabled — see docs/SKILLS.md) |
| S6 — Adversarial verification | Adversarial reviewer (exploit chain, trust boundary tracing) |
| S7 — Deduplicate findings | Finding deduplicator (semantic collapse of overlapping findings, atop a deterministic pass) |
| S8 — Chain construction and reporting | Exploit strategist (CWE, attack paths, remediation) |

The standalone `validate` command adds an agentic adversarial panel — two
always-on personas (`security-architect`, `penetration-tester`) plus a
conditional `cross-repo-analyzer`, spawned only when a fix spans 2+
repositories — that scores each remediation DTO against weighted fix-quality
gates.

See [`docs/SKILLS.md`](docs/SKILLS.md) for configuration and extension guidance.

---

## Requirements

- **Python ≥ 3.10**
- An LLM credential — a Claude Code login (run `claude` then `/login`) for the default
  profile, **or** an Anthropic API key (`ANTHROPIC_SDK_API_KEY`) / `OPENAI_API_KEY`
  if you switch roles to `via: sdk` / `via: openai`; see [Configure](#configure).
- The `claude` CLI — required for the default profile (every role `via: cli`); optional otherwise.

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

Either way this installs one command: `vvaharness`. All three backend adapters (Anthropic
SDK, Claude CLI, OpenAI-compatible) ship out of the box. The Anthropic SDK and
OpenAI backends need only an API key, but the **Claude CLI backend used by the
default profile also requires the external `claude` CLI to be installed
separately** (see [Requirements](#requirements)).

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

The default profile (`vvaharness/config/profiles/default.yaml`) runs every
detection stage (S1–S8) through the `claude` CLI, with the remediate (S10) and
validate (S11) roles pinned to a higher-tier model — all `via: cli`, so your
Claude Code login is enough, no SDK key required. (Exact model IDs are set per
role in the profile.) (`sdk.yaml` runs the same roles via the Anthropic
SDK instead — set `ANTHROPIC_SDK_API_KEY` — and turns on s4 majority voting.) To
use the multi-backend layout (Claude CLI + Anthropic SDK + OpenAI roles), copy
`vvaharness/config/profiles/full.yaml` to `./config.yaml` and edit it.

For a step-by-step walkthrough — picking a profile, config resolution order,
secrets in `.env`, and copy-then-edit customisation — see
**[docs/configuration.md → Setting up your config](docs/configuration.md#setting-up-your-config)**.

### Which setup applies to you?

| You are… | What you need | Profile |
|---|---|---|
| **Public / subscription user** (most people) | Claude Code (run `claude` then `/login`) for the default; **or** an Anthropic API key `ANTHROPIC_SDK_API_KEY=sk-ant-…` if you prefer `via: sdk` roles | `default` (login) or `sdk` (key) — nothing else: no gateway, no CA cert, no extra flags |
| **Enterprise behind a private AI gateway** | for `via: cli` roles set `ANTHROPIC_BASE_URL`, plus `NODE_EXTRA_CA_CERTS` (private CA) and `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` if the gateway needs them (for a `full` profile also point `ANTHROPIC_SDK_BASE_URL` / `OPENAI_BASE_URL` at the gateway for its SDK / OpenAI roles) | `default` or `full` — see [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md) |

Run **`vvaharness setup`** either way — it tells you exactly what (if anything)
is missing for *your* situation. A gateway token is only flagged when you
actually have one.

See **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** for all commands and options and
**[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)** for detailed install/configuration.

## Run

```bash
vvaharness scan --repo /path/to/target --application-id 12345   # full 11-step run — ⚠ edits source (S10 fix mode)
vvaharness scan --repo /path/to/target --stop-after s9          # detection only — no code changes
```

Batch (clone + scan, one report per AppId):

```bash
vvaharness scan --repo-file repos.csv --workspace ./scans --group-by-app --keep-clones
```

A `scan` run writes `run_manifest.json` (tool version, model roles, config hash,
target git SHA, timing) into the working directory. (`doctor` and `estimate` do no
scan and write no manifest.) Remember the default profile **edits source in the
target** — see the [Quick start](#quick-start) warning.

## Validation

`vvaharness validate` checks the fixes that `remediate` produced. It discovers the
per-finding reports under `<repo>/security-remediation/<NN_slug>/remediate_report.json`,
then runs an agentic adversarial panel (Claude Agent SDK) that scores each fix and
records a verdict (`validated`, `validation_failed`, or `needs_review`). The panel is
**read-only** — it reads the repo and writes only its own validation artifacts, never
applies a patch, and runs no Docker. Re-runs are idempotent.

```bash
# Claude Agent SDK ships with vvaharness (Python ≥3.10) — no extra install needed
vvaharness validate --repo /path/to/target
```

Validation is **Anthropic-only** (`models.validate` must run `via: cli` or `via: sdk`);
see [Limitations](#limitations-read-before-you-trust-output). For the panel personas,
weighted gates, and verdict thresholds, see [`docs/validation.md`](docs/validation.md)
(and [`docs/remediation.md`](docs/remediation.md) for the `remediate` command).

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

With the default profile, a scan also writes
`<target>/security-remediation/<NN_slug>/remediate_report.json` and **edits source files
in the target repo** (S10 fix mode — see the [Quick start](#quick-start) warning); pass
`--stop-after s9` to skip. `run_manifest.json` is written to the working directory.

Pipeline checkpoints and resume state are kept **outside** the scanned repo, in a
SQLite state DB at `$VVAHARNESS_STATE_DIR/vvaharness.db` (default
`~/.vvaharness/state/`); prune old runs with `vvaharness gc`.

## Limitations (read before you trust output)

- **LLM-generated, non-deterministic.** Findings are triage candidates, not
  confirmed vulnerabilities — human review is required. Two runs may differ.
  Majority-vote FP filtering runs on the `sdk` and `openai` backends; the `cli`
  backend (no temperature control) always runs single-pass, as do SDK/OpenAI
  models that reject `temperature`.
- **Token-hungry.** Caps are per-stage / per-finding, not global. Use
  `vvaharness estimate` and the `step*.max_budget_usd` knobs.
- **No published accuracy numbers yet.** Precision/recall figures are not yet
  published.
- **Elevated privilege.** This tool runs with elevated privilege and must only be
  used against trusted repositories by authorized operators. Running VVAH
  against untrusted and malicious input and repositories may expose host
  credentials, API keys, and sensitive files, or expose you to other security
  issues. If you must scan a less-trusted target, see
  [`docs/security.md` → Hardening for less-trusted or sensitive targets](docs/security.md#hardening-for-less-trusted-or-sensitive-targets)
  for compensating controls.
- **Validation (S11) is Anthropic-only.** The validation panel runs only on
  Anthropic models (`via: cli` or `via: sdk`); a `via: openai` validate role is
  refused (the validate step aborts with exit code 2). Detection (S1–S9) and
  **report-only** remediation can still run on OpenAI-compatible models (but
  remediation _fix mode_ cannot — see the next item).
- **Remediation _fix mode_ is effectively Anthropic-only.** Applying a fix needs
  the agent's file-mutation tools (`Edit`/`Write`), which only the `via: cli` and
  `via: sdk` (Anthropic) backends expose; the OpenAI-compatible backend is
  sandboxed to Read/Glob/Grep and **cannot edit files**. A `via: openai`
  `models.remediate` role therefore can only run `--mode report-only` (it
  proposes fixes, applies none) — there is no hard error, the agent simply has no
  way to write the edits. The shipped default profile uses an Anthropic `via: cli`
  remediate role, so fix mode works out of the box.
- **Review remediation fixes before you rely on them.** The remediation agent
  proposes — and in fix mode applies — code changes, but vvaharness does **not**
  compile, build, or run tests against the patched tree. Always review the
  generated fixes and build/test them yourself before merging.


See `docs/` for configuration, models, pipeline, and output details.

---

## Security

Report vulnerabilities responsibly — see [SECURITY.md](SECURITY.md). Please do
not open security issues in a public tracker.

---

## License

Licensed under the **Apache License, Version 2.0** — see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Copyright 2026 Visa, Inc.

Third-party dependencies are installed from PyPI at install time (not bundled
in this repository); their licenses are inventoried in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).

See [CHANGELOG.md](CHANGELOG.md) for release history.
