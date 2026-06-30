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

"""Execution-plan value objects for the fix-validation path."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from vvaharness.validation.models.manifest import Manifest

__all__ = ["FixValidationPlan"]


@dataclass(frozen=True)
class FixValidationPlan:
    """Everything the pipeline needs to validate one pre-staged finding."""

    jira_key: str
    session_id: str
    manifest: Manifest
    workspace_dir: Path
    output_dir: Path
