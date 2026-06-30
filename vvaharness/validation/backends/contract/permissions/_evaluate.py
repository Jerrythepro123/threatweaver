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

"""Permission evaluation predicates used by PermissionsPolicy.

Write is gated to the session's permitted output files directly under the target dir.
Bash is denied outright by PermissionsPolicy (no shell execution in a validation session),
so no command-parsing predicates live here.
"""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ._decision import PermissionDecision


def _resolve_write_path(input_data: Mapping[str, object]) -> Path | None:
    """Extract and resolve file_path from Write input; return None if missing or unresolvable."""
    raw_path = input_data.get("file_path", "")
    if not isinstance(raw_path, str) or not raw_path:
        return None
    try:
        return Path(raw_path).resolve()
    except (ValueError, OSError):
        return None


def evaluate_write(
    input_data: Mapping[str, object],
    resolved_target: Path,
    allowed_output_files: frozenset[str],
) -> PermissionDecision:
    """Allow Write only to a permitted output file directly under the target dir."""
    resolved = _resolve_write_path(input_data)
    if resolved is None:
        return PermissionDecision(False, "Write path missing or unresolvable", True)
    if resolved.parent != resolved_target or resolved.name not in allowed_output_files:
        return PermissionDecision(False, f"Write to disallowed path: {resolved}", True)
    return PermissionDecision(True)
