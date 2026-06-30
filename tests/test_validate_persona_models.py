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

"""Tests for per-persona configurable models in the s11 validator.

Covers the full chain: profile models role -> _export_persona_models (env) ->
load_config (ClaudeConfig) -> _persona_overrides -> load_agents override ->
SubagentDefinition.model -> SDK AgentDefinition.model. Unset persona -> inherit.
"""
import os
from types import SimpleNamespace

from vvaharness.validation.backends.claude.options import _to_agent_definition
from vvaharness.validation.backends.contract.subagents import SubagentDefinition
from vvaharness.validation.cli._model import _export_persona_models
from vvaharness.validation.config import load_config
from vvaharness.validation.constants.artifacts import (
    ENV_CROSS_REPO_ANALYZER_MODEL,
    ENV_PENETRATION_TESTER_MODEL,
    ENV_SECURITY_ARCHITECT_MODEL,
)
from vvaharness.validation.session.launcher import _persona_overrides
from vvaharness.validation.subagents import load_agents


# ---------------------------------------------------------------------------
# load_agents override / inherit
# ---------------------------------------------------------------------------


def test_override_sets_model_inherit_leaves_none() -> None:
    ag = load_agents(
        ["security-architect", "penetration-tester"],
        model_overrides={"security-architect": "claude-opus-4-8"},
    )
    assert ag["security-architect"].model == "claude-opus-4-8"   # overridden
    assert ag["penetration-tester"].model is None                # inherit


def test_no_overrides_all_inherit() -> None:
    ag = load_agents(["security-architect", "penetration-tester", "cross-repo-analyzer"])
    assert all(a.model is None for a in ag.values())


# ---------------------------------------------------------------------------
# env-bridge -> ClaudeConfig
# ---------------------------------------------------------------------------


def test_env_bridge_to_claude_config(monkeypatch) -> None:
    monkeypatch.setenv(ENV_SECURITY_ARCHITECT_MODEL, "claude-opus-4-8")
    monkeypatch.delenv(ENV_PENETRATION_TESTER_MODEL, raising=False)
    monkeypatch.setenv(ENV_CROSS_REPO_ANALYZER_MODEL, "claude-sonnet-4-6")
    c = load_config()
    assert c.claude.security_architect_model == "claude-opus-4-8"
    assert c.claude.penetration_tester_model is None              # unset -> inherit
    assert c.claude.cross_repo_analyzer_model == "claude-sonnet-4-6"


# ---------------------------------------------------------------------------
# _persona_overrides (config -> name->model map)
# ---------------------------------------------------------------------------


def test_persona_overrides_omits_unset() -> None:
    cfg = SimpleNamespace(claude=SimpleNamespace(
        security_architect_model="claude-opus-4-8",
        penetration_tester_model=None,
        cross_repo_analyzer_model="claude-sonnet-4-6",
    ))
    assert _persona_overrides(cfg) == {
        "security-architect": "claude-opus-4-8",
        "cross-repo-analyzer": "claude-sonnet-4-6",
    }


# ---------------------------------------------------------------------------
# _export_persona_models (profile role -> env)
# ---------------------------------------------------------------------------


def test_export_present_role_sets_env(monkeypatch) -> None:
    monkeypatch.delenv(ENV_SECURITY_ARCHITECT_MODEL, raising=False)
    cfg = SimpleNamespace(models=SimpleNamespace(validate_security_architect="claude-opus-4-8"))
    _export_persona_models(cfg)
    assert os.environ.get(ENV_SECURITY_ARCHITECT_MODEL) == "claude-opus-4-8"


def test_export_absent_role_leaves_env_unset(monkeypatch) -> None:
    monkeypatch.delenv(ENV_PENETRATION_TESTER_MODEL, raising=False)
    _export_persona_models(SimpleNamespace(models=SimpleNamespace()))
    assert ENV_PENETRATION_TESTER_MODEL not in os.environ


# ---------------------------------------------------------------------------
# model carried through to the SDK shape
# ---------------------------------------------------------------------------


def test_agent_definition_carries_model() -> None:
    sub = SubagentDefinition(name="security-architect", description="d", prompt="p",
                             model="claude-opus-4-8")
    assert _to_agent_definition(sub).model == "claude-opus-4-8"
