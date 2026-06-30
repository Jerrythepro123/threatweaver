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

"""Validation-path registry. Only the fix-validation path is supported."""

from __future__ import annotations

from dataclasses import dataclass

from vvaharness.validation.constants.artifacts import SYSTEM_PROMPT_FILENAME
from vvaharness.validation.enums.paths import ValidationPath

__all__ = ["VALIDATION_PATHS", "PathConfig", "ValidationPath", "resolve_path"]


@dataclass(frozen=True)
class PathConfig:
    """Immutable agent configuration for a single validation path."""

    path: ValidationPath
    agent_names: tuple[str, ...]
    system_prompt_file: str


VALIDATION_PATHS: dict[ValidationPath, PathConfig] = {
    ValidationPath.FIX_VALIDATION: PathConfig(
        path=ValidationPath.FIX_VALIDATION,
        agent_names=("security-architect", "penetration-tester", "cross-repo-analyzer"),
        system_prompt_file=SYSTEM_PROMPT_FILENAME,
    ),
}


def resolve_path(value: str) -> ValidationPath:
    """Coerce a serialized path string to the enum, defaulting to fix validation."""
    try:
        return ValidationPath(value)
    except ValueError:
        return ValidationPath.FIX_VALIDATION
