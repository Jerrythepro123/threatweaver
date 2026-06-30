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

"""Harness-level options for one-shot and streaming invocations."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .permissions import PermissionsPolicy
from .subagents import SubagentDefinition
from .tool_policy import ToolPolicy


@dataclass
class OneShotOptions:
    """Options for a parser-only single-turn invocation."""

    model: str
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    effort: str | None = None
    max_turns: int = 15
    tool_policy: ToolPolicy | None = None
    system_prompt: str | None = None
    output_schema: Mapping[str, object] | None = None
    cli_path: str | None = None          # absolute path to the claude executable (pin)


@dataclass
class StreamingOptions:
    """Options for a full validation session."""

    model: str
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    effort: str | None = None
    max_turns: int | None = None
    max_budget_usd: float | None = None
    system_prompt: str | None = None
    setting_sources: tuple[str, ...] | None = None
    tool_policy: ToolPolicy | None = None
    permissions: PermissionsPolicy | None = None
    agents: dict[str, SubagentDefinition] = field(default_factory=dict)
    cli_path: str | None = None          # absolute path to the claude executable (pin)
