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

"""remediation_agent.artifacts.validation — the empty s11 validation block.

Remediation lays out the validation structure only; a downstream validator
(s11) fills in the scores/verdicts later. Keeping this in its own module makes
the contract obvious and lets the validator import the canonical empty shape."""
from __future__ import annotations


def empty_validation() -> dict:
    """The s11 validation block as written by remediation: structure only, all
    score/verdict fields null and list fields empty. The validator overwrites
    this; remediation must never populate it."""
    return {
        "_source": "s11 validation (empty on input; written by validator)",
        "fix_status": None,
        "raw_score": None,
        "merge_readiness": None,
        "gate_scores": None,
        "justification": None,
        "conditions_for_full_fix": [],
        "recommendations": [],
    }
