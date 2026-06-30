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

"""remediation_agent.plugin_runner — run the remediation method for one finding.

Thin orchestration layer that wires the single-purpose modules together:

  - :mod:`vvaharness.remediation_agent.prompts`   — the method (SYSTEM + per-finding USER)
  - :mod:`vvaharness.remediation_agent.models`     — the structured-output contract
  - :mod:`vvaharness.remediation_agent.policy`     — the deterministic gate + playbook
  - :mod:`vvaharness.remediation_agent.artifacts`  — render/persist triage.json + summary.md

The model call goes through the harness's own dispatcher
(``backends.llm.agentic``), so remediation runs on whatever model/backend the
active config's ``models.remediate`` role selects (``via: cli | sdk | openai``).

This package keeps the model seam (:func:`agentic`, :func:`_invoke`) and the
verbose-trace + helper functions in THIS namespace so existing tests that
monkeypatch ``plugin_runner.agentic`` / ``plugin_runner._invoke`` keep working
unchanged. Split into focused modules, re-exported here:

  - :mod:`vvaharness.remediation_agent.plugin_runner.trace`   — --verbose stderr dumps
  - :mod:`vvaharness.remediation_agent.plugin_runner.helpers` — tools / prompt / verdict coercion
  - :mod:`vvaharness.remediation_agent.plugin_runner.run`     — the apply_plugin orchestration
"""
from __future__ import annotations

from pathlib import Path

from vvaharness.backends.llm import agentic
from vvaharness.backends.claude_cli import stream_trace
from vvaharness.util.tokens import TOKENS
from vvaharness.remediation_agent.prompts import SYSTEM
from vvaharness.remediation_agent.report_parser import Finding

from vvaharness.remediation_agent.plugin_runner.trace import (  # noqa: F401
    dump as _dump, dump_policy as _dump_policy)
from vvaharness.remediation_agent.plugin_runner.helpers import (  # noqa: F401
    _build_user, _coerce_verdict, _tools)
from vvaharness.remediation_agent.plugin_runner.run import (  # noqa: F401
    apply_plugin)

__all__ = ["apply_plugin"]


def _invoke(finding: Finding, cfg, repo: Path, mode: str,
            verbose: bool = False, *, pre=None, ctx=None) -> str:
    """Single model call through the configured backend. Isolated so tests can
    monkeypatch one seam.

    When *pre* (a policy PreResult) and *ctx* (a PolicyContext) are supplied, the
    resolved playbook strategy + do-not-edit globs are injected into the prompt
    (the ALLOW path).

    When *verbose*, echoes the user prompt up front and streams the LIVE agent
    interaction — each tool call (name + args), intermediate assistant text,
    and tool results — via ``stream_trace`` (CLI backend only; ignored by
    sdk/openai). The final raw response is also dumped for completeness."""
    sr = getattr(cfg, "step_remediate", None)
    user = _build_user(finding, repo, mode, pre=pre, ctx=ctx)
    if verbose:
        _dump(f"PROMPT → finding {finding.index} ({mode})", user)
    with TOKENS.phase("remediation-agent-remediate"):
        raw = agentic(
            user,
            model=cfg.models.remediate,
            system_prompt=SYSTEM,
            allowed_tools=_tools(cfg),
            cwd=str(repo),
            max_budget_usd=getattr(sr, "max_budget_usd", 10.0),
            max_turns=getattr(sr, "max_turns", 40),
            tag=f"Remediation Agent remediate #{finding.index}",
            stream_cb=(stream_trace if verbose else None),
        )
    if verbose:
        _dump(f"FINAL VERDICT ← finding {finding.index}", raw)
    return raw
