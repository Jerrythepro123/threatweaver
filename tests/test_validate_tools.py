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

"""Tests for user-configurable reviewer-persona tools (step_validate.allowed_tools).

Covers the full chain: profile step_validate.allowed_tools -> _export_validate_tools (env) ->
load_config (ClaudeConfig.validate_tools) -> load_agents(tools_override=) ->
SubagentDefinition.tools -> SDK AgentDefinition.tools. The key safety property is that
dropping Bash from the list removes it from every persona.
"""
import os
from types import SimpleNamespace

from vvaharness.validation.backends.claude.options import _to_agent_definition
from vvaharness.validation.cli._model import _export_validate_tools
from vvaharness.validation.config import load_config
from vvaharness.validation.config.settings import _parse_tools
from vvaharness.validation.constants.artifacts import ENV_VALIDATE_TOOLS
from vvaharness.validation.subagents import load_agents

_PERSONAS = ("security-architect", "penetration-tester", "cross-repo-analyzer")


# ── the safety property: dropping Bash removes it from every persona ───────────
def test_override_without_bash_strips_bash_from_all_personas() -> None:
    ag = load_agents(list(_PERSONAS), tools_override=("Read", "Grep", "Glob"))
    for name in _PERSONAS:
        assert "Bash" not in (ag[name].tools or ()), f"{name} still has Bash"
        assert set(ag[name].tools or ()) == {"Read", "Grep", "Glob"}


def test_override_survives_into_sdk_agent_definition() -> None:
    ag = load_agents(["security-architect"], tools_override=("Read", "Grep", "Glob"))
    sdk_tools = _to_agent_definition(ag["security-architect"]).tools or []
    assert "Bash" not in sdk_tools
    assert "Read" in sdk_tools


# ── default (no override): personas keep their .md frontmatter set incl. Bash ──
def test_no_override_keeps_frontmatter_tools() -> None:
    ag = load_agents(list(_PERSONAS))
    for name in _PERSONAS:
        assert "Bash" in (ag[name].tools or ()), f"{name} should keep Bash by default"


# ── env round-trip: profile list -> env -> ClaudeConfig.validate_tools ─────────
def test_export_then_load_config_roundtrip(monkeypatch) -> None:
    monkeypatch.delenv(ENV_VALIDATE_TOOLS, raising=False)
    cfg = SimpleNamespace(step_validate=SimpleNamespace(allowed_tools=["Read", "Grep", "Glob"]))
    _export_validate_tools(cfg)
    assert os.environ[ENV_VALIDATE_TOOLS] == "Read,Grep,Glob"
    assert load_config().claude.validate_tools == ("Read", "Grep", "Glob")


def test_export_absent_list_leaves_env_unset(monkeypatch) -> None:
    monkeypatch.delenv(ENV_VALIDATE_TOOLS, raising=False)
    _export_validate_tools(SimpleNamespace(step_validate=SimpleNamespace(allowed_tools=None)))
    assert ENV_VALIDATE_TOOLS not in os.environ


def test_unset_env_yields_none_so_personas_inherit(monkeypatch) -> None:
    monkeypatch.delenv(ENV_VALIDATE_TOOLS, raising=False)
    assert load_config().claude.validate_tools is None


# ── _parse_tools ───────────────────────────────────────────────────────────────
def test_parse_tools_splits_strips_and_drops_empties() -> None:
    assert _parse_tools(" Read , Grep ,,Glob ") == ("Read", "Grep", "Glob")
    assert _parse_tools("") is None
    assert _parse_tools("   ") is None
