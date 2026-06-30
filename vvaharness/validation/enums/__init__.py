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

"""Domain enums for vvaharness.validation.

Convention: value-enums subclass ``StrEnum`` (via ``._compat``) so ``Member == "value"``
holds; reserve a bare ``Enum`` only for a discriminator never compared to a string. All
value-enums here are ``StrEnum``.
"""

from __future__ import annotations

from .effort import EffortLevel
from .gates import GateName, GateStatus
from .paths import ValidationPath
from .readiness import MergeReadiness
from .setting_source import SettingSource
from .verdicts import Answer, FixVerdict

__all__ = [
    "Answer",
    "EffortLevel",
    "FixVerdict",
    "GateName",
    "GateStatus",
    "MergeReadiness",
    "SettingSource",
    "ValidationPath",
]
