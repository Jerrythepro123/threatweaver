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

"""Data contracts for durable, cross-scan experience.

These models deliberately avoid importing pipeline models.  The experience
package is dormant until an orchestrator explicitly calls it, and keeping the
contracts independent prevents importing this module from changing scan
startup or model validation behaviour.

Raw source code does not belong in these records.  Callers should persist
stable hashes and bounded, redacted references instead.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return an aware UTC timestamp for default factories."""
    return datetime.now(timezone.utc)


class ExperienceStage(str, Enum):
    S4 = "s4"
    S5 = "s5"
    S6 = "s6"
    ASAN = "asan"
    S8 = "s8"
    S9 = "s9"
    REMEDIATION = "remediation"
    VALIDATION = "validation"
    HUMAN = "human"


class OutcomeSource(str, Enum):
    PREFILTER = "prefilter"
    VERIFIER = "verifier"
    ASAN = "asan"
    REPORT = "report"
    REMEDIATION = "remediation"
    VALIDATION = "validation"
    HUMAN = "human"
    BENCHMARK = "benchmark"


class OutcomeVerdict(str, Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    UNCONFIRMED = "unconfirmed"
    DUPLICATE = "duplicate"
    NEEDS_REVIEW = "needs_review"
    FIXED = "fixed"
    PARTIALLY_FIXED = "partially_fixed"
    REGRESSED = "regressed"
    ACCEPTED_RISK = "accepted_risk"


class ScanExperience(BaseModel):
    """Immutable identifying context for one scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1, max_length=512)
    repository_fingerprint: str = Field(min_length=1, max_length=128)
    commit_sha: str | None = Field(default=None, max_length=128)
    config_sha256: str | None = Field(default=None, max_length=128)
    prompt_version: str = Field(default="", max_length=128)
    model_roles: dict[str, dict[str, str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class CandidateExperience(BaseModel):
    """One candidate as it first appeared, before later-stage decisions."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1, max_length=512)
    finding_fingerprint: str = Field(min_length=1, max_length=128)
    stage: ExperienceStage = ExperienceStage.S4
    language: str = Field(default="unknown", max_length=64)
    vulnerability_class: str = Field(default="other", max_length=128)
    cwe: str | None = Field(default=None, max_length=32)
    file: str = Field(default="", max_length=4096)
    function: str | None = Field(default=None, max_length=512)
    source_ref: str | None = Field(default=None, max_length=4096)
    sink_ref: str | None = Field(default=None, max_length=4096)
    structural_hash: str | None = Field(default=None, max_length=128)
    model_id: str = Field(default="", max_length=256)
    prompt_version: str = Field(default="", max_length=128)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    votes: int = Field(default=1, ge=0)
    evidence_refs: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class OutcomeExperience(BaseModel):
    """A stage, tool, benchmark, or person judging a candidate."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(min_length=1, max_length=512)
    finding_fingerprint: str = Field(min_length=1, max_length=128)
    source: OutcomeSource
    verdict: OutcomeVerdict
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    trust_level: int = Field(default=0, ge=0, le=4)
    reason: str = Field(default="", max_length=8000)
    evidence_refs: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class MemoryExperience(BaseModel):
    """A promoted, retrieval-safe summary derived from trusted outcomes."""

    model_config = ConfigDict(extra="forbid")

    finding_fingerprint: str = Field(min_length=1, max_length=128)
    repository_fingerprint: str | None = Field(default=None, max_length=128)
    language: str = Field(default="unknown", max_length=64)
    vulnerability_class: str = Field(default="other", max_length=128)
    cwe: str | None = Field(default=None, max_length=32)
    verdict: OutcomeVerdict
    trust_level: int = Field(ge=0, le=4)
    summary: str = Field(default="", max_length=8000)
    pattern: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[str] = Field(default_factory=list)
    source_scan_ids: list[str] = Field(default_factory=list)
    updated_at: datetime = Field(default_factory=utc_now)

