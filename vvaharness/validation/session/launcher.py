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

"""Execute a single fix-validation session via the harness."""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path

from vvaharness.validation.backends import (
    VALIDATION_POLICY,
    Harness,
    HarnessCLINotFoundError,
    HarnessError,
    PermissionsPolicy,
    StreamingOptions,
    get_harness,
)
from vvaharness.validation.config import Config
from vvaharness.validation.constants.artifacts import (
    ANTHROPIC_API_KEY,
    ANTHROPIC_AUTH_TOKEN,
    LOGGING_DIRNAME,
    MANIFEST_FILENAME,
    ORCHESTRATOR_LOG_DIRNAME,
    SESSION_ENV_FLAG,
    SESSION_ENV_GH_ARCHIVED_TOKEN,
    SESSION_ENV_GH_TOKEN,
    SESSION_ENV_JIRA_KEY,
    SESSION_ENV_LOG_DIR,
    SESSION_ENV_MANIFEST,
    SESSION_ENV_OUTPUT_DIR,
    SESSION_ENV_PROJECT_DIR,
    SESSION_ENV_SESSION_ID,
    SESSION_ENV_TARGET_DIR,
)
from vvaharness.validation.constants.paths import (
    VALIDATION_PATHS,
    resolve_path,
)
from vvaharness.validation.io.message_logger import stream_and_log
from vvaharness.validation.models import Manifest
from vvaharness.validation.session.config_inject import inject_claude_config
from vvaharness.validation.session.errors import ValidationSessionError
from vvaharness.validation.session.launch_prompt import build_launch_prompt
from vvaharness.validation.subagents import load_agents

log = logging.getLogger(__name__)


def _build_env(
    config: Config,
    manifest: Manifest,
    workspace: Path,
    output_dir: Path,
) -> dict[str, str]:
    """Build the subprocess environment dict for the validation session."""
    # Propagate the API auth token so auth works inside Claude Code and standalone.
    effective_api_key = (
        os.environ.get(ANTHROPIC_AUTH_TOKEN) or os.environ.get(ANTHROPIC_API_KEY, "")
    )
    env: dict[str, str] = {
        ANTHROPIC_API_KEY: effective_api_key,
        SESSION_ENV_FLAG: "true",
        SESSION_ENV_TARGET_DIR: str(workspace),
        SESSION_ENV_OUTPUT_DIR: str(output_dir),
        SESSION_ENV_MANIFEST: str(workspace / MANIFEST_FILENAME),
        SESSION_ENV_LOG_DIR: str(workspace / LOGGING_DIRNAME),
        SESSION_ENV_JIRA_KEY: manifest.jira_key,
        SESSION_ENV_SESSION_ID: manifest.session_id,
        SESSION_ENV_PROJECT_DIR: str(workspace),
    }
    if config.ghe.token:
        env[SESSION_ENV_GH_TOKEN] = config.ghe.token
    if config.ghe.archived_token:
        env[SESSION_ENV_GH_ARCHIVED_TOKEN] = config.ghe.archived_token
    return env


def _persona_overrides(config: Config) -> dict[str, str]:
    """Map persona name → configured model id (omitting personas left to inherit validate)."""
    return {
        name: model
        for name, model in (
            ("security-architect", config.claude.security_architect_model),
            ("penetration-tester", config.claude.penetration_tester_model),
            ("cross-repo-analyzer", config.claude.cross_repo_analyzer_model),
        )
        if model
    }


def _resolve_binary(binary: str) -> str:
    """Resolve ``config.claude.binary`` (from $VVAHARNESS_CLAUDE_BINARY, default
    ``"claude"``) to an absolute path so the SDK runs a PINNED executable rather
    than resolving a bare name against PATH at launch (CWE-426/427).

    An explicit path that exists is used as-is; a bare name is resolved via PATH
    and pinned. On miss, the input is returned unchanged (the SDK then resolves
    it as before) so this never breaks a working setup."""
    if Path(binary).is_file():
        return str(binary)
    found = shutil.which(binary)
    if found:
        return found
    log.warning("claude binary %r not found on PATH; SDK will resolve it", binary)
    return binary


def build_validation_options(
    config: Config,
    manifest: Manifest,
    workspace: Path,
    output_dir: Path,
    system_prompt: str | None,
) -> StreamingOptions:
    """Compose a StreamingOptions instance for the validation session."""
    try:
        path_cfg = VALIDATION_PATHS[resolve_path(manifest.validation_path)]
    except KeyError:
        log.exception("Unregistered validation_path for %s", manifest.jira_key)
        raise
    return StreamingOptions(
        model=config.claude.model,
        cwd=workspace,
        env=_build_env(config, manifest, workspace, output_dir),
        effort=config.claude.effort,
        max_turns=config.claude.max_turns,
        max_budget_usd=config.claude.max_budget_usd,
        system_prompt=system_prompt,
        setting_sources=("project",),
        cli_path=_resolve_binary(config.claude.binary),
        tool_policy=VALIDATION_POLICY,
        permissions=PermissionsPolicy(target_dir=workspace),
        agents=load_agents(
            path_cfg.agent_names,
            model_overrides=_persona_overrides(config),
            tools_override=config.claude.validate_tools,
        ),
    )


def _load_system_prompt(config: Config, path_cfg: object) -> str | None:
    """Read the system prompt file if present, else return None."""
    prompt_file = getattr(path_cfg, "system_prompt_file", None)
    if not prompt_file:
        return None
    path = config.paths.prompts_dir / prompt_file
    return path.read_text() if path.exists() else None


async def _run_and_check(
    harness: Harness,
    prompt: str,
    options: StreamingOptions,
    session_id: str,
    log_dir: Path,
) -> int:
    """Stream the session, log it, and raise ValidationSessionError on failure."""
    try:
        messages = harness.run_streaming(prompt, options)
        exit_code, observed_sid = await stream_and_log(
            messages,
            log_dir=log_dir / ORCHESTRATOR_LOG_DIRNAME,
            session_id=session_id,
            live=False,
        )
    except HarnessCLINotFoundError:
        raise
    except HarnessError as e:
        raise ValidationSessionError(
            f"Harness error: {type(e).__name__}",
            cause=e,
            exit_code=getattr(e, "exit_code", None),
        ) from e
    if exit_code != 0:
        log.error("Session %s exited with code %d", session_id, exit_code)
        raise ValidationSessionError(
            "validation session returned non-success",
            exit_code=exit_code,
        )
    log.debug("Session %s completed (observed_sid=%s)", session_id, observed_sid)
    return exit_code


async def launch_session(
    config: Config,
    manifest: Manifest,
    workspace_dir: Path,
    output_dir: Path,
    harness: Harness | None = None,
) -> int:
    """Run a fix-validation session and return the exit code (0 on success)."""
    inject_claude_config(workspace_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path_cfg = VALIDATION_PATHS[resolve_path(manifest.validation_path)]
    options = build_validation_options(
        config=config,
        manifest=manifest,
        workspace=workspace_dir,
        output_dir=output_dir,
        system_prompt=_load_system_prompt(config, path_cfg),
    )
    log.info(
        "Launching validation session %s for %s in %s",
        manifest.session_id, manifest.jira_key, workspace_dir,
    )
    return await _run_and_check(
        harness=harness if harness is not None else get_harness(config.claude.via),
        prompt=build_launch_prompt(manifest),
        options=options,
        session_id=manifest.session_id,
        log_dir=workspace_dir / LOGGING_DIRNAME,
    )
