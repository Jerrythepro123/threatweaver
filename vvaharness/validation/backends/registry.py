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

"""Backend registry: maps ``via`` strings to lazy Harness factory callables.

Selecting ``cli`` or ``sdk`` never imports the ``openai`` package, and
selecting ``openai`` never imports ``claude_agent_sdk``.
"""

from __future__ import annotations

from collections.abc import Callable

from vvaharness.validation.backends.base import Harness


def _make_claude() -> Harness:
    from vvaharness.validation.backends.claude.client import ClaudeHarness

    return ClaudeHarness()


def _make_openai() -> Harness:
    from vvaharness.validation.backends.openai.client import OpenAIHarness

    return OpenAIHarness()


_BACKENDS: dict[str, Callable[[], Harness]] = {
    "cli": _make_claude,
    "sdk": _make_claude,
    "openai": _make_openai,
}


def get_harness(via: str | None = None) -> Harness:
    """Return a fresh Harness instance for the given *via* selector.

    Args:
        via: Backend selector string — one of ``"cli"``, ``"sdk"``, or
            ``"openai"``.  ``None`` (or any falsy value) defaults to the
            Claude backend (``"sdk"``); ``"cli"`` is an alias for ``"sdk"``
            (both select the Claude backend).

    Returns:
        A concrete ``Harness`` instance for the requested provider.

    Raises:
        ValueError: If *via* is not a registered backend key.
    """
    key = via or "sdk"
    factory = _BACKENDS.get(key)
    if factory is None:
        valid = ", ".join(f'"{k}"' for k in _BACKENDS)
        raise ValueError(f"unknown backend {key!r}; valid values are: {valid}")
    return factory()


__all__ = ["get_harness"]
