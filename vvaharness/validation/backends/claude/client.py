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

"""ClaudeHarness: Claude Agent SDK concrete implementation of Harness."""

from __future__ import annotations

from collections.abc import AsyncIterator

from claude_agent_sdk import (
    ClaudeSDKClient,
    CLIConnectionError,
    CLIJSONDecodeError,
    CLINotFoundError,
    ProcessError,
    ResultMessage,
)
from claude_agent_sdk._errors import MessageParseError

from vvaharness.util.tokens import TOKENS
from vvaharness.validation.backends.base import Harness
from vvaharness.validation.backends.claude.options import (
    build_oneshot_sdk_options,
    build_streaming_sdk_options,
)
from vvaharness.validation.backends.claude.translate import translate
from vvaharness.validation.backends.contract.errors import (
    HarnessCLINotFoundError,
    HarnessConnectionError,
    HarnessJSONDecodeError,
    HarnessMessageParseError,
    HarnessProcessError,
)
from vvaharness.validation.backends.contract.messages import HarnessMessage, OneShotResult
from vvaharness.validation.backends.contract.options import OneShotOptions, StreamingOptions

_SIMPLE_ERROR_MAP: tuple[tuple[type[Exception], type[Exception]], ...] = (
    (CLINotFoundError, HarnessCLINotFoundError),
    (CLIConnectionError, HarnessConnectionError),
    (CLIJSONDecodeError, HarnessJSONDecodeError),
    (MessageParseError, HarnessMessageParseError),
)


def _wrap_sdk_error(e: Exception) -> Exception:
    """Map an SDK exception to the appropriate HarnessError subclass."""
    if isinstance(e, ProcessError):
        return HarnessProcessError(
            str(e),
            exit_code=getattr(e, "exit_code", None),
            stderr=getattr(e, "stderr", None),
        )
    for sdk_type, harness_type in _SIMPLE_ERROR_MAP:
        if isinstance(e, sdk_type):
            return harness_type(str(e))
    return e


class ClaudeHarness(Harness):
    """Claude Agent SDK implementation of the Harness interface."""

    async def run_oneshot(
        self, prompt: str, options: OneShotOptions
    ) -> OneShotResult:
        """Run a single-turn invocation and return the structured result."""
        sdk_opts = build_oneshot_sdk_options(options)
        result_text: str | None = None
        structured: object = None
        subtype = ""
        is_error = False
        usage: dict[str, object] | None = None
        total_cost_usd: float | None = None
        try:
            async with ClaudeSDKClient(options=sdk_opts) as client:
                await client.query(prompt)
                async for message in client.receive_response():
                    if isinstance(message, ResultMessage):
                        subtype = message.subtype
                        is_error = bool(message.is_error)
                        result_text = message.result
                        structured = message.structured_output
                        usage = message.usage
                        total_cost_usd = message.total_cost_usd
                        # Feed process-wide counter; usage is cumulative per session.
                        TOKENS.add(usage)
                        break
        except CLINotFoundError:
            raise HarnessCLINotFoundError(
                "Claude CLI binary not found"
            ) from None
        except (ProcessError, CLIConnectionError, CLIJSONDecodeError, MessageParseError) as e:
            raise _wrap_sdk_error(e) from e

        return OneShotResult(
            is_error=is_error,
            subtype=subtype,
            result_text=result_text,
            structured=structured,
            usage=usage,
            total_cost_usd=total_cost_usd,
        )

    def run_streaming(
        self, prompt: str, options: StreamingOptions
    ) -> AsyncIterator[HarnessMessage]:
        """Return an async iterator of typed harness messages for a streaming session."""
        sdk_opts = build_streaming_sdk_options(options)

        async def _gen() -> AsyncIterator[HarnessMessage]:
            try:
                async with ClaudeSDKClient(options=sdk_opts) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        for translated in translate(message):
                            yield translated
            except CLINotFoundError:
                raise HarnessCLINotFoundError(
                    "Claude CLI binary not found"
                ) from None
            except (ProcessError, CLIConnectionError, CLIJSONDecodeError, MessageParseError) as e:
                raise _wrap_sdk_error(e) from e

        return _gen()
