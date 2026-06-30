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

"""Backend registry and contract types for validation harness providers."""

from vvaharness.validation.backends.base import Harness
from vvaharness.validation.backends.contract import (
    DEFAULT_ALLOWED_OUTPUT_FILES,
    VALIDATION_POLICY,
    HarnessAssistantText,
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessError,
    HarnessJSONDecodeError,
    HarnessMessage,
    HarnessMessageParseError,
    HarnessProcessError,
    HarnessResult,
    HarnessSessionInit,
    HarnessToolResult,
    HarnessToolUse,
    OneShotOptions,
    OneShotResult,
    PermissionDecision,
    PermissionsPolicy,
    StreamingOptions,
    SubagentDefinition,
    ToolPolicy,
)
from vvaharness.validation.backends.registry import get_harness

__all__ = [
    "DEFAULT_ALLOWED_OUTPUT_FILES",
    "VALIDATION_POLICY",
    "Harness",
    "HarnessAssistantText",
    "HarnessCLINotFoundError",
    "HarnessConnectionError",
    "HarnessError",
    "HarnessJSONDecodeError",
    "HarnessMessage",
    "HarnessMessageParseError",
    "HarnessProcessError",
    "HarnessResult",
    "HarnessSessionInit",
    "HarnessToolResult",
    "HarnessToolUse",
    "OneShotOptions",
    "OneShotResult",
    "PermissionDecision",
    "PermissionsPolicy",
    "StreamingOptions",
    "SubagentDefinition",
    "ToolPolicy",
    "get_harness",
]
