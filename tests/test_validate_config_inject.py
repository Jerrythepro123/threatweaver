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

"""N38: rules/ is a required config subtree — inject fails closed when its source is absent.

rules/ carries the scoring rubric and anti-manipulation guidance, so injecting a workspace
without it would let the agent run unguarded. skills/ stays genuinely optional.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from vvaharness.validation.constants.artifacts import CLAUDE_DIRNAME
from vvaharness.validation.session import config_inject


def test_inject_raises_when_rules_source_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Point the injector at a config source that has no rules/ subtree → fail closed.
    fake_source = tmp_path / "claude_config"
    fake_source.mkdir()
    monkeypatch.setattr(config_inject, "CLAUDE_CONFIG_SOURCE", fake_source)
    workspace = tmp_path / "ws"
    workspace.mkdir()

    with pytest.raises(FileNotFoundError):
        config_inject.inject_claude_config(workspace)


def test_inject_succeeds_with_rules_present_and_skills_absent(tmp_path: Path) -> None:
    # The packaged config ships rules/ but no skills/; injection succeeds and copies rules/,
    # while the optional skills/ subtree is simply not created.
    workspace = tmp_path / "ws"
    workspace.mkdir()

    config_inject.inject_claude_config(workspace)

    dest_claude = workspace / CLAUDE_DIRNAME
    assert (dest_claude / "rules").is_dir()
    assert not (dest_claude / "skills").exists()
    # scoring is computed host-side; the package is not copied into the workspace.
    assert not (workspace / "scoring").exists()
