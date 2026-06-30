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

"""ScoringConfig instance for the fix-validation path."""

from vvaharness.validation.constants.scoring import (
    CRITERION_NAME_FIELD,
    GATE_WEIGHTS,
    SCORE_FLOOR,
    STATUS_MULTIPLIER,
    THRESHOLD_FIXED,
    THRESHOLD_PARTIAL,
)
from vvaharness.validation.enums.gates import GateName
from vvaharness.validation.enums.verdicts import FixVerdict
from vvaharness.validation.models.scoring import ScoringConfig, VerdictRule

from ._justify import build_fix_justification

FIX_CONFIG = ScoringConfig(
    name="fix",
    criterion_name_field=CRITERION_NAME_FIELD,
    expected_criteria=frozenset(GATE_WEIGHTS.keys()),
    weights=GATE_WEIGHTS,
    status_multiplier=STATUS_MULTIPLIER,
    verdicts=(
        VerdictRule(min_score=THRESHOLD_FIXED, label=FixVerdict.FIXED),
        VerdictRule(min_score=THRESHOLD_PARTIAL, label=FixVerdict.PARTIALLY_FIXED),
        VerdictRule(min_score=SCORE_FLOOR, label=FixVerdict.NOT_FIXED),
    ),
    unverifiable_label=FixVerdict.UNVERIFIABLE,
    justify=build_fix_justification,
    # The security gate is load-bearing: it cannot be skipped/garbled away or out-weighted.
    critical_criteria=frozenset({GateName.NO_NEW_VULNERABILITIES.value}),
)
