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

# Operational Security

> What the agent can and cannot do, how cloned repos are isolated, what gets
> redacted, and what you should never scan with this tool.

> **Reporting a vulnerability in the harness itself?** See
> [`SECURITY.md`](../SECURITY.md) at the repo root.

## Execution boundary

vvaharness is a **static** analyzer: it reads source, it does not build, compile,
or run the target's code. The analysis stages reason over file *contents* and a
textual call graph.

The one place shell execution is possible is the **`cli` backend with `Bash`
enabled** (the `cli.yaml` profile, or any `via: cli` role that re-adds `- Bash`
to `allowed_tools`). There the `claude` subprocess can run shell commands inside
the target directory for repo inventory and evidence retrieval. The `sdk` and
`openai` backends have **no Bash** — they use only the sandboxed Read/Glob/Grep
tool loop (below). If you are scanning untrusted code and want to avoid any shell
execution against it, use a profile whose agentic roles are `via: sdk` /
`via: openai`, or keep `Bash` out of `allowed_tools`.

## Repo isolation / sandboxing

For the `sdk` and `openai` backends, the agentic Read/Glob/Grep tools are
implemented in `vvaharness/backends/localtools.py` and **confined to the scanned
repo root**. `_jail()` resolves every requested path against the root and rejects
anything that escapes it — absolute paths, `..` traversal, and symlinks pointing
outside all return an error string instead of file content. This matters because
the s6 verifier reads attacker-influenced finding text; a prompt-injected path
must not be able to exfiltrate files outside the repo. The tools also cap output
(≈200 KB per read, 200 grep matches, 500 glob hits) so a single call can't dump
an unbounded amount of data.

Batch mode clones each repo under the `--workspace` directory and (unless
`--keep-clones`) deletes the clone after scanning, preserving only the folders in
`output.preserve_on_cleanup` (default `[checkpoints, security-scan]`).

## Redaction (`vvaharness/report/redact.py`)

Card data, PII, and credential material are masked at two boundaries:

- **Write boundary** — the Markdown report and the SARIF JSON are passed through
  `redact()` / `redact_tree()` before they land on disk, so every rendered field
  (description, code snippet, exploit scenario, verifier reasoning, …) is covered.
- **Outbound tool content** — `localtools` runs `Read`/`Grep` results through
  `redact_counts()` before handing them back to the model, so quoted source that
  the agent retrieves is scrubbed before it leaves the process.

Detectors are tuned for **high precision** (few false positives):

- **Card / PAN** — 12–19 digit runs gated by both the Luhn checksum *and* an
  IIN/BIN network check (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners,
  Maestro, RuPay), so random Luhn-passing ids aren't masked. Also `CVV`/`CVC` and
  magnetic `TRACK` data.
- **PII** — SSN/ITIN, both separated (`NNN-NN-NNNN`) and keyword-gated bare
  9-digit, validated by area/group/serial rules.
- **Cloud / SaaS keys** — AWS (`AKIA…`), GitHub (`ghp_…`, `github_pat_…`), Slack,
  Stripe, Google API, Azure SAS, Twilio.
- **Tokens & keys** — JWTs, `Bearer`/`Basic` credentials, and PEM private-key
  blocks.
- **Generic secrets** — values assigned after a credential keyword
  (`password`, `api_key`, `access_key`, `client_secret`, `auth_token`, …). Strong
  keywords always mask; values after prose-ambiguous keywords (`secret`, `token`)
  are left alone when they look like ordinary words or code expressions, and
  obvious placeholders (`${VAR}`, `changeme`, `xxxx`, `<redacted>`, …) are never
  masked.

Redaction is a defense-in-depth measure for the written artifacts and outbound
tool reads — it is **not** a guarantee that no sensitive token ever reaches the
model (see below).

## Data sent to the LLM provider

To analyze a repo, the pipeline necessarily sends the **source code under scan**
to whichever provider each role is routed to: the Anthropic API (`via: sdk`),
an OpenAI-compatible endpoint (`via: openai`), or the Anthropic backend the
`claude` CLI is logged into (`via: cli`). Use a backend/endpoint your
organization permits for the code in question — e.g. a private Anthropic gateway
(`ANTHROPIC_SDK_BASE_URL` / `ANTHROPIC_BASE_URL`) rather than the public API.

The tool never prints credential *values* in `setup`/`doctor` output (only
set/unset presence), and the redaction pass scrubs quoted source before it is
written to disk or returned through the sandboxed tools.

## What not to scan

- Code you are **not authorized** to test, or that you may not share with the
  configured LLM provider/endpoint.
- Data you must not egress — secrets, customer data, PII/PHI, financial data, or
  trade secrets. Redaction reduces but does not eliminate exposure, so do not
  point the tool at a repository whose contents may not leave your environment
  under the backend you've configured.

> Findings are LLM-generated **triage candidates, not confirmed vulnerabilities**
> — human review is required.
