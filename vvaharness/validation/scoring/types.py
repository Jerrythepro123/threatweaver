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

"""Shim: re-exports scoring value types from models.scoring for intra-package compat."""

from __future__ import annotations

from vvaharness.validation.enums.gates import GateName, GateStatus
from vvaharness.validation.enums.readiness import MergeReadiness
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.models.scoring import (
    EvidenceAnchor,
    GateResult,
    ScoredGateEntry,
    ValidationScore,
)

__all__ = [
    "EvidenceAnchor",
    "FixVerdict",
    "GateName",
    "GateResult",
    "GateStatus",
    "MergeReadiness",
    "ScoredGateEntry",
    "ValidationScore",
]
