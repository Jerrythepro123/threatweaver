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

"""Stable, privacy-conscious identities for repositories and findings."""
from __future__ import annotations

import hashlib
import json
import re


_LINE_SUFFIX = re.compile(r":\d+(?:-\d+)?$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"(?m)(?://|#).*$")
_QUOTED = re.compile(r'''(?s)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')''')
_NUMBER = re.compile(r"\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b")
_SPACE = re.compile(r"\s+")


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def normalize_path(value: str | None) -> str:
    """Normalize a repository-relative path without touching the filesystem."""
    text = (value or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    parts = [part for part in text.split("/") if part not in ("", ".")]
    return "/".join(parts).lower()


def normalize_reference(value: str | None) -> str:
    """Remove unstable line numbers while preserving path/symbol identity."""
    text = (value or "").strip().replace("\\", "/")
    return _LINE_SUFFIX.sub("", text).lower()


def normalize_symbol(value: str | None) -> str:
    return _SPACE.sub(" ", (value or "").strip()).lower()


def structural_hash(excerpt: str | None) -> str | None:
    """Hash a coarse code shape rather than persisting raw source.

    Comments, literal contents, numeric values, and whitespace are normalized
    so small edits do not automatically produce a new identity.  This is not a
    parser and should be treated as one fingerprint component, not proof that
    two findings are equivalent.
    """
    if not excerpt:
        return None
    shaped = _BLOCK_COMMENT.sub(" ", excerpt)
    shaped = _LINE_COMMENT.sub(" ", shaped)
    shaped = _QUOTED.sub(" <str> ", shaped)
    shaped = _NUMBER.sub("<num>", shaped)
    shaped = _SPACE.sub(" ", shaped).strip().lower()
    return _sha256(shaped) if shaped else None


def repository_fingerprint(identity: str) -> str:
    """Hash a canonical repository name or remote URL supplied by the caller."""
    canonical = identity.strip().replace("\\", "/").rstrip("/").lower()
    if not canonical:
        raise ValueError("repository identity must not be empty")
    return _sha256(canonical)


def finding_fingerprint(
    *,
    repository: str,
    vulnerability_class: str,
    cwe: str | None = None,
    file: str | None = None,
    function: str | None = None,
    source_ref: str | None = None,
    sink_ref: str | None = None,
    excerpt: str | None = None,
) -> str:
    """Return a stable identity suitable for cross-commit correlation."""
    material = {
        "repository": repository,
        "class": vulnerability_class.strip().lower(),
        "cwe": (cwe or "").strip().upper(),
        "file": normalize_path(file),
        "function": normalize_symbol(function),
        "source": normalize_reference(source_ref),
        "sink": normalize_reference(sink_ref),
        "shape": structural_hash(excerpt) or "",
    }
    return _sha256(json.dumps(material, sort_keys=True, separators=(",", ":")))

