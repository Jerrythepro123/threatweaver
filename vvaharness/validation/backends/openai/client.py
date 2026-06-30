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

"""OpenAI backend placeholder for the validation harness.

Intended implementation: a manual ``chat.completions`` tool-loop that
reuses ``contract.PermissionsPolicy`` / ``ToolPolicy`` for gate decisions and
delegates tool execution to a sandboxed executor equivalent to
``vvaharness/backends/localtools.py``.

See ``vvaharness/backends/oai.py`` for the reference agentic loop pattern.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from vvaharness.validation.backends.base import Harness
from vvaharness.validation.backends.contract.messages import HarnessMessage, OneShotResult
from vvaharness.validation.backends.contract.options import OneShotOptions, StreamingOptions


class OpenAIHarness(Harness):
    """OpenAI chat.completions implementation of the Harness interface.

    Not yet implemented.  The intended design is a synchronous-wrapped async
    tool loop that:

    1. Builds a ``tools=[...]`` list from ``StreamingOptions.tool_policy`` by
       mapping ``ToolPolicy.allowed_tools`` through a local schema registry
       (see ``vvaharness/backends/localtools.py``).
    2. Sends the prompt via ``openai.OpenAI().chat.completions.create`` with
       ``stream=True``.
    3. On each ``tool_calls`` response, dispatches to a sandboxed executor
       jailed to ``options.cwd`` (same contract as ``localtools.execute``),
       gates each call through ``PermissionsPolicy``, and emits the
       corresponding ``HarnessToolUse`` / ``HarnessToolResult`` messages.
    4. On a text-only response, emits ``HarnessAssistantText`` and then
       ``HarnessResult``.
    5. Normalises token usage to the Anthropic field names so
       ``vvaharness.util.tokens.TOKENS`` sees a unified total.

    The ``openai`` package is imported lazily (inside methods) so that
    importing this module never raises ``ImportError`` when the SDK is absent.
    """

    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn invocation via OpenAI chat.completions.

        Not yet implemented.

        Args:
            prompt: The user-facing prompt text.
            options: One-shot invocation options (model, cwd, tool_policy, …).

        Returns:
            OneShotResult with structured output.

        Raises:
            NotImplementedError: Always, until this backend is implemented.
        """
        raise NotImplementedError(
            "OpenAI backend not yet implemented; "
            "see vvaharness/validation/backends/openai/"
        )

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed harness messages via OpenAI.

        Not yet implemented.

        Args:
            prompt: The user-facing prompt text.
            options: Full streaming session options (model, cwd, permissions, …).

        Returns:
            An async iterator of HarnessMessage variants.

        Raises:
            NotImplementedError: Always, until this backend is implemented.
        """
        raise NotImplementedError(
            "OpenAI backend not yet implemented; "
            "see vvaharness/validation/backends/openai/"
        )
