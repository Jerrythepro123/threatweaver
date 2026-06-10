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

# Output Formats

## On-disk layout

Per target, under `<target>/security-scan/`:

- `<module>_<ts>_report.md`
- `<module>_<ts>_report.sarif`
- `<module>_<ts>_errors.jsonl`

Checkpoints under `<target>/checkpoints/*.pkl` (delete to force a fresh
run; the auto-derived `step1.yaml` lives here too). Batch mode also
writes `<workspace>/batch_summary.md`.

> **Checkpoint loading is restricted.** On `--resume`, checkpoints are
> deserialized through an allow-list that only reconstructs the tool's own
> data types — a checkpoint referencing anything else (a tampered or
> foreign-version file) is **refused** and the stage simply re-runs, rather
> than being trusted. Only resume from checkpoints you produced yourself; do
> not `--resume` a scan of an untrusted repository.

`output.preserve_on_cleanup` in `config.yaml` controls which folders
survive when cloned source is deleted (default: `[checkpoints, security-scan]`).

## Markdown report — finding block

Each verified finding follows this block order (metadata fields on
consecutive lines — one field per line, no blank lines between, so the
SARIF parser reads each by regex):

```
### N. [SEVERITY] Title
**Class:** <vuln-class>
**File:** `path:start-end`
**CVSS 3.1:** score (rating) — `vector`
**VulContextSeverity:** `env-vector` - score (rating)   (if CMDB enrichment ran)
**OffensivePriority:** Pn - label | reason         (if CMDB enrichment ran)
**Confidence:** 0.NN (V of N runs agreed)

#### Description
#### Impact
#### Exploit scenario
#### Preconditions
``` code snippet ```
#### How to fix
**Exploitability:** notes
#### Adversarial verification
```

## SARIF 2.1.0 mapping

`vvaharness/report/enrich.py: md_to_sarif()` parses the markdown back and
emits SARIF. Per finding:

| Markdown | SARIF |
|---|---|
| `[SEVERITY]` | `level`, `properties.severity` |
| Title + CVSS | `message.text` |
| `**Class:**` | `ruleId`, `properties.category` |
| `**File:**` line | `locations[0].physicalLocation.{artifactLocation.uri, region.startLine}` |
| `**CVSS 3.1:**` | `rank` (CVSS 0–10 scaled to SARIF's 0–100), `properties.{cvssVector,cvssScore,cvssRating,security-severity}` |
| `**VulContextSeverity:**` | `properties.{vulContextSeverityVector,vulContextSeverityScore,vulContextSeverityRating}` |
| `**OffensivePriority:**` | `properties.{offensivePriority,offensivePriorityLabel,offensivePriorityReason}` |
| `**Confidence:**` | `properties.confidence`, `properties.votes` |
| Description → Verification | `properties.description` (markdown body, ≤4000 chars) |

Run-level `properties` always carries `applicationId`; `applicationName` and
`cmdbSource` are added only when a CMDB AppInfo was resolved for that
application (i.e. CMDB enrichment ran). The SARIF `tool.driver.name` is
`"Agentic SAST"`. `tool.driver.rules[]` catalogs every emitted `ruleId`, and
`tool.driver.supportedTaxonomies` references the CWE taxonomy (by a stable guid)
so each result's `taxa[]` resolves. When the scan was degraded (deep-dive chunks
failed, or the exploit-chain pass could not be computed) the run carries an
`invocations[]` entry with `executionSuccessful=false` and per-stage
`toolExecutionNotifications`; a clean run reports `executionSuccessful=true`.

### Scan Health (markdown)

When a run loses coverage — deep-dive chunks that failed or timed out, or a
chain pass that could not be computed — the report adds a `## Scan Health`
section listing chunks attempted/failed, per-stage error counts, and a pointer
to the per-run `*_errors.jsonl`. A clean run omits the section entirely. Note: a
run that simply found no exploit chains is **not** degraded — that is a normal
outcome and is stated as "No exploit chains were identified".

## CMDB enrichment

Set `inject.cmdb_file` in `config.yaml` to a single CMDB export CSV
(default `./inputs/cmdb.csv`) to enable AppProfile lookup and
VulContextSeverity environmental scoring. When unset or missing, base
CVSS and OffensivePriority are still computed; only the
VulContextSeverity adjustment is skipped.
