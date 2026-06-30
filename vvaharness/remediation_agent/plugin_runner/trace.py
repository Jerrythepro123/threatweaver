# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""remediation_agent.plugin_runner.trace — --verbose stderr tracing helpers.

Labelled, redacted stderr dumps for the prompt / raw response (:func:`dump`)
and the per-finding policy decision + resolved playbook strategy
(:func:`dump_policy`). Pure presentation; no model spend, no policy logic."""
from __future__ import annotations

import sys

from vvaharness.report.redact import redact
from vvaharness.remediation_agent.report_parser import Finding


def dump(title: str, body: str) -> None:
    """Print a labelled, redacted block to stderr for --verbose tracing."""
    bar = "─" * 72
    print(f"\n  ┌─ {title} {bar[len(title) + 4:]}", file=sys.stderr)
    for line in redact(body or "").splitlines() or [""]:
        print(f"  │ {line}", file=sys.stderr)
    print(f"  └{bar}", file=sys.stderr)


def dump_policy(finding: Finding, pre) -> None:
    """Echo the per-finding policy decision + resolved playbook strategy to
    stderr for --verbose tracing.

    The strategy block IS injected into the prompt (and thus appears in the
    PROMPT dump), but it's buried in a large block; this surfaces the policy
    gate's decision and the chosen playbook strategy explicitly so it's clear
    WHAT was ingested and WHY for each finding."""
    decision = pre.decision
    print(f"\n  ┌─ POLICY → finding {finding.index} "
          f"{'─' * 56}", file=sys.stderr)
    print(f"  │ CWE: {pre.cwe or '(unknown)'}", file=sys.stderr)
    print(f"  │ decision: {decision.action.value}  "
          f"(may_patch={decision.may_generate_patch})", file=sys.stderr)
    print(f"  │ reason: {redact(decision.reason or '(none)')}", file=sys.stderr)
    matched = getattr(decision, "matched_rule", None)
    if matched:
        print(f"  │ matched rule: {redact(str(matched))}", file=sys.stderr)
    if pre.strategy is not None:
        print(f"  │ playbook strategy: {pre.strategy.name} "
              f"(confidence={pre.strategy.confidence}, "
              f"fix_location={pre.strategy.fix_location})", file=sys.stderr)
    else:
        print("  │ playbook strategy: (none resolved — guidance-only)",
              file=sys.stderr)
    print(f"  └{'─' * 72}", file=sys.stderr)
    # The full injected strategy block, so verbose shows EXACTLY what the agent
    # received.
    if pre.strategy is not None:
        dump(f"PLAYBOOK STRATEGY → finding {finding.index}",
             pre.strategy.as_prompt_block())
