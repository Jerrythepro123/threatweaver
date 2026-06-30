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

"""Parse YAML frontmatter from subagent .md authoring files without a pyyaml dependency."""

from __future__ import annotations

import re
from typing import cast

from typing_extensions import TypedDict


class SubagentFrontmatterMeta(TypedDict, total=False):
    """Typed representation of parsed subagent YAML frontmatter."""

    name: str
    model: str
    description: str
    allowedTools: list[str]
    deniedTools: list[str]
    skills: list[str]


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)
_SCALAR_KEYS = frozenset({"name", "model", "description"})
_LIST_KEYS = frozenset({"allowedTools", "deniedTools", "skills"})


def _append_list_item(
    meta: dict[str, object],
    current_list_key: str | None,
    raw: str,
) -> None:
    """Append a YAML block-list item to its parent bucket in meta."""
    if current_list_key is None:
        raise ValueError(f"list item without parent key: {raw!r}")
    value = raw.rstrip().split("- ", 1)[1].strip()
    bucket = meta[current_list_key]
    if not isinstance(bucket, list):
        raise TypeError(f"expected list for key {current_list_key!r}, got {type(bucket)!r}")
    bucket.append(value)


def _apply_key_line(meta: dict[str, object], raw: str) -> str | None:
    """Apply a ``key: value`` line to meta; return the new list-context key or None."""
    key, sep, value = raw.rstrip().partition(":")
    if not sep:
        raise ValueError(f"malformed frontmatter line: {raw!r}")
    key, value = key.strip(), value.strip()
    if key in _SCALAR_KEYS:
        meta[key] = value
        return None
    if key in _LIST_KEYS:
        if value:
            raise ValueError(f"{key} must be a block list, got inline value")
        meta[key] = []
        return key
    raise ValueError(f"unknown frontmatter key: {key}")


def _classify_line(
    meta: dict[str, object], current_list_key: str | None, raw: str,
) -> str | None:
    """Process one frontmatter line; return the updated list-context key."""
    line = raw.rstrip()
    if not line.strip():
        return None
    if line.startswith(("  - ", "\t- ")):
        _append_list_item(meta, current_list_key, raw)
        return current_list_key
    return _apply_key_line(meta, raw)


def parse_frontmatter(text: str) -> tuple[SubagentFrontmatterMeta, str]:
    """Parse YAML frontmatter and return (meta dict, stripped body text)."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("subagent file missing YAML frontmatter")
    head, body = m.group(1), m.group(2)
    meta: dict[str, object] = {}
    current_list_key: str | None = None
    for raw in head.splitlines():
        current_list_key = _classify_line(meta, current_list_key, raw)
    return cast(SubagentFrontmatterMeta, meta), body.strip()
