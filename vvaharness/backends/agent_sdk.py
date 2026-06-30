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

"""
Claude Agent SDK backend for *mutating* agentic roles (the Remediation Agent's
`fix` mode under ``via: sdk``).

Why a second SDK backend?  ``backends/sdk.py`` talks to the **raw `anthropic`
SDK** and hand-runs a tool loop over the sandboxed Read/Glob/Grep executors in
``backends/localtools.py`` — it has no file-mutation tools by design (a
prompt-injected verifier must never write the repo).  The Remediation Agent's
`fix` mode, however, legitimately needs to apply minimal diffs.  Rather than
re-implement Edit/Write/Bash, this module drives the **official
`claude_agent_sdk`** (``ClaudeSDKClient``) — the same runtime the `vvaharness
validate` agent uses — which provides Read/Glob/Grep/Edit/Write/Bash *natively*
inside the SDK's permission sandbox.

The ``can_use_tool`` permission callback is **deny-by-default**:

  * Read-only tools (Read / Glob / Grep) are always allowed.
  * File-mutation tools (Edit / Write / MultiEdit / NotebookEdit) are allowed
    only when their resolved target stays inside the repo root (``cwd``),
    mirroring the validation harness's ``PermissionsPolicy``.
  * **Every other tool — including Bash — is DENIED.**  A prompt-injected
    remediation agent with a host shell is RCE on the scanning machine, so the
    gate refuses Bash outright rather than letting it fall through; the
    remediation agent applies diffs via Edit/Write, never a shell.

The public surface (``agentic``) matches ``backends/sdk.py:agentic`` so the
dispatcher (``backends/llm.py``) and the Remediation Agent never need to know
which SDK is doing the work.  ``backends/sdk.py`` delegates here automatically
when an agentic role requests a tool its local loop can't execute.

Auth/endpoint are delegated to the Claude CLI the Agent SDK spawns (same as the
validate agent): ``ANTHROPIC_AUTH_TOKEN`` / ``ANTHROPIC_API_KEY`` (gateway JWT or
key) and ``ANTHROPIC_BASE_URL`` are read from the environment.  The dedicated
``ANTHROPIC_SDK_API_KEY`` (used by the raw-SDK backend) is honoured too — if set
and no ``ANTHROPIC_API_KEY`` is present, it is forwarded so a single key works
for both backends.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from vvaharness.report.redact import redact_counts
from vvaharness.util.tokens import TOKENS

# Read-only tools are always safe; only file-mutation tools are gated to cwd.
_WRITE_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
# Read-only inspection tools — always permitted (output is redaction-hooked).
_READ_TOOLS = frozenset({"Read", "Glob", "Grep", "LS", "NotebookRead"})
# Tool result fields whose text is masked by the PostToolUse redaction hook so
# on-disk secrets/PII read by the agent are not egressed to the model gateway
# unredacted (parity with the read-only localtools loop, which redact_counts()
# every Read/Grep result before it re-enters model context).
_REDACT_TOOLS = _READ_TOOLS | frozenset({"Bash"})


def _resolve_within_root(root: Path, raw: object) -> Path | None:
    """Resolve *raw* to a real path confined to *root*, or ``None`` if it
    escapes / is unresolvable / is a symlinked target.

    The gate hands the returned path back to the SDK as the write target (see
    ``_gate``) so the SDK writes the CANONICAL confined path rather than the
    model's mutable raw name, and a symlinked final component is refused so an
    in-repo link cannot redirect the write outside the tree. A link or
    intermediate directory pointing OUTSIDE *root* is already caught by
    ``resolve()`` + ``relative_to``.

    This shrinks but cannot fully close the check-to-use window: the SDK
    performs the open/write itself with no ``O_NOFOLLOW`` / dirfd binding we can
    inject from this permission callback, so a symlink swapped into the path
    AFTER this check and BEFORE the SDK's write is not provably defeated here.
    Fully closing it needs SDK write-hook support or running remediation in an
    isolated filesystem namespace."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        candidate = Path(raw) if os.path.isabs(raw) else (root / raw)
        # Refuse a symlinked final component without following it — a
        # repo-controlled link is the redirection primitive this gate denies.
        if candidate.is_symlink():
            return None
        target = candidate.resolve()
        target.relative_to(root)
    except (OSError, ValueError):
        return None
    return target


def _within_root(root: Path, raw: object) -> bool:
    """Return True iff *raw* resolves to a non-symlinked path inside (or equal
    to) *root*. Thin bool wrapper over :func:`_resolve_within_root` used where
    only an allow/deny decision is needed."""
    return _resolve_within_root(root, raw) is not None


def _sdk_env() -> dict[str, str]:
    """Inherit the ambient environment, forwarding the SDK-specific key as the
    standard ANTHROPIC_API_KEY when only the former is set so a single
    credential authenticates the Agent-SDK-spawned CLI."""
    env = dict(os.environ)
    if not env.get("ANTHROPIC_API_KEY"):
        fallback = (env.get("ANTHROPIC_AUTH_TOKEN")
                    or env.get("ANTHROPIC_SDK_API_KEY"))
        if fallback:
            env["ANTHROPIC_API_KEY"] = fallback
    sdk_base = env.get("ANTHROPIC_SDK_BASE_URL")
    if sdk_base and not env.get("ANTHROPIC_BASE_URL"):
        env["ANTHROPIC_BASE_URL"] = sdk_base
    return env


def _redact_tool_output(payload: object) -> object:
    """Recursively mask secret/PII material in a tool-result *payload*.

    The Agent SDK surfaces tool output as either a bare string or a list of
    content blocks (dicts with a ``text`` field). We redact every string we can
    reach via :func:`redact_counts` so on-disk credentials/PII a Read/Grep/Bash
    tool surfaced are masked before the text re-enters the model turn — parity
    with the read-only ``localtools`` loop. Unrecognised shapes pass through."""
    if isinstance(payload, str):
        masked, _ = redact_counts(payload)
        return masked
    if isinstance(payload, list):
        return [_redact_tool_output(item) for item in payload]
    if isinstance(payload, dict):
        out = dict(payload)
        for key in ("text", "content", "stdout", "stderr", "output"):
            if key in out:
                out[key] = _redact_tool_output(out[key])
        return out
    return payload


def _build_redaction_hooks():
    """Build a PostToolUse hook map that redacts Read/Grep/Bash tool output.

    Returns ``None`` when the installed ``claude_agent_sdk`` does not expose the
    ``HookMatcher`` surface (older SDKs) so the caller silently skips wiring it.
    The hook is best-effort: it never raises into the SDK event loop."""
    try:
        from claude_agent_sdk import HookMatcher  # type: ignore
    except Exception:  # noqa: BLE001 — optional/older SDK without hooks
        return None

    async def _post_tool_use(input_data, tool_use_id, context):  # noqa: ANN001, ARG001
        try:
            tool_name = (input_data or {}).get("tool_name")
            if tool_name not in _REDACT_TOOLS:
                return {}
            response = (input_data or {}).get("tool_response")
            if response is None:
                return {}
            masked = _redact_tool_output(response)
            if masked == response:
                return {}
            # `updatedToolOutput` is the only PostToolUse key the SDK forwards to
            # the CLI as an output replacement (types.py: additionalContext /
            # updatedToolOutput / updatedMCPToolOutput). An unrecognised key
            # (e.g. the former `updatedToolResponse`) is passed through verbatim
            # and dropped by the CLI, so the masked bytes would be computed then
            # discarded and cleartext would reach the gateway. The replacement
            # must match the tool's output schema; `_redact_tool_output`
            # preserves the shape of `tool_response`, satisfying that contract.
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedToolOutput": masked,
                }
            }
        except Exception:  # noqa: BLE001 — a redaction hook must never break a run
            return {}

    try:
        return {"PostToolUse": [HookMatcher(hooks=[_post_tool_use])]}  # type: ignore[list-item]
    except Exception:  # noqa: BLE001 — SDK HookMatcher shape guard
        return None


def _build_options(*, model: str, system_prompt: str | None,
                   allowed_tools: list[str], cwd: str,
                   max_budget_usd: float | None, max_turns: int | None):
    """Compose ClaudeAgentOptions with a cwd-confined write permission gate.

    Imported lazily so importing this module never hard-requires the optional
    `claude_agent_sdk` dependency."""
    from claude_agent_sdk import (
        ClaudeAgentOptions,
        PermissionResultAllow,
        PermissionResultDeny,
    )

    root = Path(cwd).resolve()

    async def _gate(tool_name, input_data, context):  # noqa: ANN001, ARG001
        # File-mutation tools: allow only when the target stays inside the repo.
        if tool_name in _WRITE_TOOLS:
            raw = key_used = None
            for key in ("file_path", "path", "notebook_path"):
                val = input_data.get(key)
                if val:
                    raw, key_used = val, key
                    break
            resolved = _resolve_within_root(root, raw)
            if resolved is None:
                return PermissionResultDeny(
                    message=(f"{tool_name} target {raw!r} is outside the "
                             f"repository root, unresolvable, or a symlink — "
                             f"edits are confined to {root}"),
                    interrupt=False,
                )
            # Hand the SDK the RESOLVED, confined path (not the model's raw
            # name) so the write targets the canonical in-repo file and a raw
            # alias cannot be re-pointed. See _resolve_within_root for the
            # residual TOCTOU caveat (the SDK owns the open/write).
            safe_input = dict(input_data)
            safe_input[key_used] = str(resolved)
            return PermissionResultAllow(updated_input=safe_input)
        # Read-only inspection tools: always allowed.
        if tool_name in _READ_TOOLS:
            return PermissionResultAllow(updated_input=input_data)
        # DENY-BY-DEFAULT for everything else — most importantly Bash. A host
        # shell would let a prompt-injected remediation agent run arbitrary
        # commands on the scanner (RCE) and exfiltrate ambient credentials; the
        # agent applies diffs via Edit/Write, never a shell. Refusing here means
        # re-adding `Bash` to a profile's allowed_tools still cannot execute it.
        return PermissionResultDeny(
            message=(f"{tool_name} is not permitted in remediation fix mode — "
                     f"only Read/Glob/Grep and cwd-confined Edit/Write are "
                     f"allowed (Bash and other tools are denied by default)."),
            interrupt=False,
        )

    redaction_hooks = _build_redaction_hooks()

    opts = ClaudeAgentOptions(
        model=model,
        cwd=str(root),
        env=_sdk_env(),
        # Programmatic gate decides every tool call; no interactive prompts and
        # no project-level settings/hooks are loaded for a remediation run.
        permission_mode="default",
        setting_sources=None,
        can_use_tool=_gate,
        allowed_tools=list(allowed_tools),
    )
    # PostToolUse redaction: mask secrets/PII in tool output before it re-enters
    # the model turn, restoring parity with the redacting read-only localtools
    # loop. Set defensively (older SDKs may not accept `hooks`).
    if redaction_hooks is not None:
        try:
            opts.hooks = redaction_hooks  # type: ignore[assignment]
        except (AttributeError, TypeError):  # pragma: no cover - SDK shape guard
            pass

    if system_prompt is not None:
        opts.system_prompt = system_prompt
    if max_turns is not None:
        opts.max_turns = int(max_turns)
    if max_budget_usd is not None:
        opts.max_budget_usd = float(max_budget_usd)
    return opts


async def _run(*, user_prompt: str, opts) -> str:  # noqa: ANN001
    """Stream one agentic session to completion and return the final text."""
    from claude_agent_sdk import (
        AssistantMessage,
        ClaudeSDKClient,
        ResultMessage,
        TextBlock,
    )

    text_parts: list[str] = []
    result_text: str | None = None
    async with ClaudeSDKClient(options=opts) as client:
        await client.query(user_prompt)
        async for message in client.receive_response():
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        text_parts.append(block.text)
            elif isinstance(message, ResultMessage):
                if message.usage:
                    TOKENS.add(message.usage)
                result_text = message.result
                break
    # ResultMessage.result holds the model's final answer; fall back to the
    # accumulated assistant text blocks if the runtime didn't populate it.
    return (result_text or "".join(text_parts)).strip()


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",   # accepted for parity; gate handles policy
    max_turns: int | None = None,
    tag: str | None = None,
) -> str:
    """Run an agentic loop with native Edit/Write/Bash via the Claude Agent SDK.

    Mirrors ``backends/sdk.py:agentic`` so the dispatcher can call either
    interchangeably. File-mutation tools are confined to *cwd* by a permission
    gate. Read-only tools (Read/Glob/Grep) are always allowed."""
    try:
        import claude_agent_sdk  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "An agentic role is configured `via: sdk` and requests file-editing "
            "tools (Edit/Write/Bash), which require the Claude Agent SDK. "
            "Reinstall vvaharness to pull it in (pip install .), or "
            "set this role to `via: cli`."
        ) from e

    allowed = list(allowed_tools or ["Read", "Glob", "Grep"])
    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [agent-sdk] agentic -> {model}{tag_sfx} (tools={allowed}, "
          f"max_turns={max_turns}, cwd={cwd})", file=sys.stderr)

    opts = _build_options(
        model=model, system_prompt=system_prompt, allowed_tools=allowed,
        cwd=cwd, max_budget_usd=max_budget_usd, max_turns=max_turns,
    )
    return asyncio.run(_run(user_prompt=user_prompt, opts=opts))
