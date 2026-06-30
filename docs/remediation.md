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

# Remediation Agent (`remediate` — step 10)

The canonical reference for the Remediation Agent. For where it sits in the
pipeline see [architecture.md](architecture.md); for the model role see
[models.md](models.md); for config knobs see
[configuration.md](configuration.md#step_remediate--remediation-agent-s10).

## What it does

`vvaharness remediate` reads a prior scan's findings from
`<repo>/security-scan/`, walks the verified findings one-by-one on the
`models.remediate` role (LLM skill; ~46-line system prompt in
`vvaharness/remediation_agent/prompts.py`), and proposes a
**minimal fix per finding**. For each finding it writes a per-finding DTO:

```
<repo>/security-remediation/<NN_slug>/
  remediate_report.json     # the canonical DTO (finding + proposed fix + status)
  evidence/                 # triage.json (structured verdict + meta), summary.md (human-readable), diff.patch (unified diff of the change)
```

These DTOs are exactly what [`validate`](validation.md) (step 11) later grades.

> ⚠️ **Default-on and runs in fix mode.** With the shipped `default.yaml`
> (`step_remediate.enabled: true`), a plain `vvaharness scan` runs the
> Remediation Agent as **Step 10** at the end of the scan, and the in-scan path
> forces **fix mode — it edits source files in the target repo.** To scan
> without modifying the target: `--stop-after s9`, or use a profile with
> `step_remediate.enabled: false`. The flag `--remediate` and config
> `step_remediate.enabled` OR together (the flag only turns it on).

## Modes

| Mode | Effect |
|---|---|
| `fix` *(default)* | Applies the minimal diff to the working tree via `Edit`/`Write` (cwd-confined). The in-scan Step-10 path always uses this. |
| `report-only` | Proposes the fix and writes the DTO; the agent is instructed not to edit files. Note: the edit tools are still in `allowed_tools` — the no-edit behavior is prompt-enforced, not withheld at the tool layer. |

> ⚠️ **Fix mode needs an Anthropic backend (`via: cli` or `via: sdk`).** Applying
> a fix requires the file-mutation tools (`Edit`/`Write`), which only the `cli`
> and `sdk` backends provide. The OpenAI-compatible backend is sandboxed to
> `Read`/`Glob`/`Grep` and cannot edit files, so a `via: openai`
> `models.remediate` role can only do useful work in `--mode report-only` — in
> fix mode it has no way to write the diff (no hard error; it simply applies
> nothing). The shipped `default.yaml` uses an Anthropic `via: cli` remediate
> role, so fix mode works out of the box. See [models.md](models.md).

The tool set is `Read / Glob / Grep / Edit / Write` — **Bash is intentionally
omitted** (a prompt-injected agent with a host shell would be RCE on the
scanner). How that exclusion is enforced depends on the route: on `via: sdk`
the Agent SDK permission gate denies Bash even if it is re-added to
`allowed_tools`; on the **default `via: cli` route there is no such gate** —
Bash is contained only by its absence from `allowed_tools`, so re-adding it
*would* grant a host shell. Don't.

## Running it standalone

```bash
# Remediate the findings of a completed scan (fix mode)
vvaharness remediate --repo /path/to/target

# Only the 10 highest-CVSS findings, interactive picker, no edits
vvaharness remediate --repo /path/to/target --top 10 -i --mode report-only
```

| Flag | Effect |
|---|---|
| `--repo <path>` | Target repo whose `security-scan/` findings are remediated. **Required.** |
| `--config <file>` | Config profile path; else `./config.yaml`, else packaged `default.yaml`. |
| `--mode fix\|report-only` | `fix` (default) applies diffs; `report-only` proposes without editing. |
| `--top <N\|all\|*>` | Remediate only the N highest-CVSS findings (overrides `step_remediate.top_n_findings`; `all`/`*` = every finding). |
| `-i`, `--interactive` | Pick which findings to remediate from a menu. (Shows the FULL findings list — the profile's `top_n_findings` cap is ignored in interactive mode unless you pass an explicit `--top N`.) |
| `--resume` | Skip findings already remediated in a prior run. |
| `-v`, `--verbose` | Print the prompt + raw LLM response per finding. |

## Configuration (`step_remediate:`)

| Key | Default | Effect |
|---|---|---|
| `enabled` | `true` | Run the Remediation Agent (also as Step 10 of a scan). `--remediate` forces on. |
| `top_n_findings` | `5` | Cap by CVSS; `--top` overrides; `all`/`*`/`null` = every finding. |
| `max_budget_usd` | `10.0` | Per-repo soft cap (token accounting). |
| `max_turns` | `40` | Tool-loop cap for `via: sdk` / `via: openai`. |
| `allowed_tools` | `[Read, Glob, Grep, Edit, Write]` | Fix-mode tools; Bash denied. |
| `enforce_policy` | `false` | Opt-in deny-list/playbook gate + diff post-gate (reverts forbidden-path edits). |
| `policy_file` / `playbook_file` | shipped `inputs/` | Override paths to `remediation_policy.yaml` / `remediation_playbook.yaml`. |

## Policy gate & kill-switch (`enforce_policy: true`)

When `enforce_policy` is on, every fix decision passes through the policy gate
(`remediation_policy.yaml` + `remediation_playbook.yaml`): deny/allow CWE maps,
forbidden-path globs, and a diff post-gate that reverts edits to forbidden
paths.

An emergency **kill-switch** is checked on *every* gate decision and forces
GUIDANCE_ONLY (no edits):

- environment variable `VVAHARNESS_REMEDIATE_DISABLE` set to `1`/`true`/`yes`/`on` (case-insensitive), or
- a sentinel file `./.vvaharness-remediate-off` in the working directory.

Both are defined in `remediation_policy.yaml`'s `kill_switch` block and are only
enforced when `enforce_policy: true`.

## Output & safety summary

- Writes `<repo>/security-remediation/<NN_slug>/{remediate_report.json, evidence/}`.
- In **fix mode**, also edits source files in the target repo — only run against
  repos you authored/trust (see [security.md](security.md)).
- `--resume` skips findings already remediated in a prior run. (Note: `--force`
  is a *scan* flag that overrides the s10 git-SHA staleness check, not a
  remediate re-run flag.)
- The DTOs feed [`validate`](validation.md) (step 11).
