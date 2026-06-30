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

"""remediation_agent.models.verdict — the per-finding ``RemediationVerdict`` contract.

A single Pydantic model defines exactly what the remediation agent must return
per finding. Its JSON schema is embedded in the prompt (see
:mod:`vvaharness.remediation_agent.prompts`) and the runner validates the agent's response
with ``model_validate`` — the same structured-output pattern the scan pipeline
uses for ThreatModel / TaskManifest / Finding.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, Field

from vvaharness.remediation_agent.models.gates import Gates
from vvaharness.remediation_agent.models.change import Change

Verdict = Literal["Fixed", "Partially Fixed", "Not Fixed",
                  "False Positive", "Needs Review", "Denied"]


class RemediationVerdict(BaseModel):
    """Structured result the remediation agent must return for one finding.

    Only ``verdict`` is strictly required; every other field has a safe default
    so a near-complete agent response (e.g. one that omits ``summary``) is
    preserved rather than thrown away. ``verdict`` itself is salvaged in
    :meth:`coerce` when missing/invalid."""

    finding_index: int = 0
    verdict: Verdict = "Needs Review"
    gates: Gates = Field(default_factory=Gates)
    root_cause: str = Field(default="", description="one paragraph, cites file:line")
    changes: list[Change] = Field(
        default_factory=list,
        description="edits applied (fix mode) or proposed (report-only)")
    remaining_risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(
        default_factory=list,
        description="code-level follow-ups only — no operational controls")
    summary: str = Field(default="", description="2-4 sentence human-readable summary")

    @classmethod
    def schema_json_compact(cls) -> str:
        """Compact JSON schema string for embedding in the SYSTEM prompt."""
        return json.dumps(cls.model_json_schema(), separators=(",", ":"))

    @classmethod
    def coerce(cls, data, *, finding_index: int) -> "RemediationVerdict":
        """Build a verdict from a (possibly imperfect) agent payload, preserving
        as much real content as possible.

        Strategy: try strict validation first; on failure, salvage by keeping
        only recognised keys, normalising an unknown/missing ``verdict`` to a
        valid value, and letting field defaults fill the rest. Always returns a
        verdict (never raises) and pins ``finding_index`` to the known value so
        one off-schema field can't discard an otherwise-useful response."""
        if not isinstance(data, dict):
            return cls(finding_index=finding_index, verdict="Needs Review",
                       summary="agent response was not a JSON object")
        try:
            v = cls.model_validate(data)
            v.finding_index = finding_index
            return v
        except Exception:  # noqa: BLE001 — fall through to salvage
            pass

        clean = {k: data[k] for k in cls.model_fields if k in data}
        valid_verdicts = set(Verdict.__args__)  # type: ignore[attr-defined]
        if clean.get("verdict") not in valid_verdicts:
            clean["verdict"] = "Needs Review"
        try:
            v = cls.model_validate(clean)
        except Exception:  # noqa: BLE001 — last resort: construct from defaults
            v = cls(verdict="Needs Review",
                    summary="agent verdict could not be fully validated; "
                            "salvaged available fields")
            for k, val in clean.items():
                try:
                    setattr(v, k, val)
                except Exception:  # noqa: BLE001
                    pass
        v.finding_index = finding_index
        return v
