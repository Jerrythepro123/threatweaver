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

"""Model-resolution logic for the ``vvaharness validate`` command."""

from __future__ import annotations

import sys
from pathlib import Path

from vvaharness import config as harness_config
from vvaharness.backends import llm
from vvaharness.validation.cli._parser import _tunable_overrides
from vvaharness.validation.config.environment import set_env
from vvaharness.validation.constants.artifacts import (
    BACKEND_OPENAI,
    ENV_MODEL,
    ENV_VALIDATE_TOOLS,
    ENV_VIA,
    PERSONA_MODEL_ENV,
)


def _validate_model_spec(cfg: object) -> object | None:
    """Return ``cfg.models.validate``, or None when undefined."""
    models = getattr(cfg, "models", None)
    if models is None:
        return None
    return getattr(models, "validate", None)


def _load_validated_spec(config_path: str) -> tuple[object, object] | None:
    """Load config and return (cfg, spec), or None on missing path or absent models.validate."""
    if not Path(config_path).exists():
        print(f"validate: config not found: {config_path}", file=sys.stderr)
        return None
    cfg = harness_config.load(config_path)
    spec = _validate_model_spec(cfg)
    if spec is None:
        print("validate: config defines no models.validate role", file=sys.stderr)
        return None
    return cfg, spec


def _persona_spec_resolved(spec: object) -> tuple[str, str] | None:
    """Resolve a persona model spec to ``(model_id, via)``, or None when absent/invalid."""
    if spec is None:
        return None
    try:
        model_id, via, _extras = llm.resolve(spec)
    except (ValueError, AttributeError, KeyError, TypeError):
        return None  # malformed persona spec — fall back to inheriting models.validate
    return (model_id, via or "") if model_id else None


def _export_persona_models(cfg: object) -> int:
    """Export optional per-persona model overrides to env; 0 on success, 2 to abort.

    Absent/unresolvable role → inherit ``models.validate``. A persona pinned to a
    non-Anthropic endpoint (``via: openai``) aborts with a clear message — the s11
    sub-agents run only on the Anthropic SDK/CLI.
    """
    models = getattr(cfg, "models", None)
    if models is None:
        return 0
    for role, env in PERSONA_MODEL_ENV.values():
        resolved = _persona_spec_resolved(getattr(models, role, None))
        if resolved is None:
            continue
        model_id, via = resolved
        if via == BACKEND_OPENAI:
            print(
                f"validate: persona '{role}' model '{model_id}' is not on an "
                f"Anthropic-compatible endpoint (use via: sdk or cli)",
                file=sys.stderr,
            )
            return 2
        set_env(env, model_id)
    return 0


def _export_validate_tools(cfg: object) -> None:
    """Export ``step_validate.allowed_tools`` comma-joined to env; absent/empty → leave unset."""
    block = getattr(cfg, "step_validate", None)
    tools = getattr(block, "allowed_tools", None) if block is not None else None
    if isinstance(tools, list) and tools:
        set_env(ENV_VALIDATE_TOOLS, ",".join(str(t) for t in tools))


def _apply_model_env(config_path: str) -> tuple[int, dict[str, object]]:
    """Resolve models.validate from the profile and export it as VVAHARNESS_MODEL.

    Returns ``(return_code, tunable_overrides)``: on success ``(0, step_validate scalars)``
    to seed straight into ``load_config(overrides=...)`` (no os.environ round-trip); a missing
    profile or a non-Anthropic endpoint returns ``(2, {})`` so the caller aborts.
    """
    loaded = _load_validated_spec(config_path)
    if loaded is None:
        return 2, {}
    cfg, spec = loaded
    model_id, via, _ = llm.resolve(spec)
    if via == BACKEND_OPENAI:
        print(
            f"validate: models.validate model '{model_id}' is not on an "
            f"Anthropic-compatible endpoint (use via: sdk or cli)",
            file=sys.stderr,
        )
        return 2, {}
    set_env(ENV_MODEL, model_id)
    if via:
        set_env(ENV_VIA, via)
    _export_validate_tools(cfg)
    rc = _export_persona_models(cfg)
    return rc, _tunable_overrides(cfg)
