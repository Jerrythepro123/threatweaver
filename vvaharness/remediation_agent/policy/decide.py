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

"""remediation_agent.policy.decide — the pre-gate (before any LLM call).

:func:`pre_decision` decides whether a finding may be patched and resolves its
playbook strategy; a denied CWE/path yields a non-PATCH decision the caller MUST
honour (skip the agent — no tokens spent). :func:`guidance_verdict` builds the
bare DENIED verdict recorded for a policy-denied finding."""
from __future__ import annotations

from dataclasses import dataclass

from vvaharness.remediation_agent.frameworks import language_for
from vvaharness.remediation_agent.models import RemediationVerdict
from vvaharness.remediation_agent.playbook import Strategy
from vvaharness.remediation_agent.policy_gate import Decision
from vvaharness.remediation_agent.policy.context import PolicyContext
from vvaharness.remediation_agent.report_parser import (Finding,
                                                        parse_finding_fields)


@dataclass
class PreResult:
    """Outcome of the pre-gate for one finding."""
    decision: Decision
    cwe: str | None
    strategy: Strategy | None
    # Convenience: the agent may run iff this is True.
    @property
    def allowed(self) -> bool:
        return self.decision.may_generate_patch


def pre_decision(ctx: PolicyContext, finding: Finding) -> PreResult:
    """Decide whether *finding* may be patched and, if so, resolve its strategy.

    Uses the finding's CWE + clean file path (no line suffix). A denied CWE/path
    yields a non-PATCH decision the caller MUST honour (skip the agent)."""
    fields = parse_finding_fields(finding)
    cwe = fields.get("cwe")
    file_path = fields.get("file") or (finding.file or "")
    decision = ctx.gate.decide(cwe, file_path)
    strategy = None
    if decision.may_generate_patch:
        lang = language_for(file_path)
        # The playbook is SUPPLEMENTARY context, not a second gate. When it has
        # an entry we inject the authoritative fix strategy; when it does not
        # (e.g. broad classes like CWE-20 with no single generic transform), we
        # still run the agent on the main remediation prompt rather than
        # downgrading to guidance. The policy gate alone owns allow/deny.
        strategy = ctx.playbook.resolve(cwe, lang, ctx.frameworks)
    return PreResult(decision=decision, cwe=cwe, strategy=strategy)


def guidance_verdict(ctx: PolicyContext, finding: Finding,
                     pre: PreResult) -> RemediationVerdict:
    """Build a plain DENIED verdict for a policy-denied finding (no patch, no
    prose advice).

    The policy gate denied this finding, so we record a bare "denied by policy"
    verdict carrying only the deny reason — no remediation guidance is produced
    and no model is called."""
    reason = pre.decision.reason
    return RemediationVerdict(
        finding_index=finding.index,
        verdict="Denied",
        root_cause="",
        changes=[],
        recommendations=[],
        summary=f"Denied by policy ({reason}). No patch generated.",
    )
