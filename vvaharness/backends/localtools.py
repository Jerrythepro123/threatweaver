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
Local, sandboxed implementations of the Read / Glob / Grep tools so the
non-CLI backends (backends/sdk.py, backends/oai.py) can run an agentic loop
without shelling out to `claude`.

All paths are resolved against — and confined to — a single root
directory (`cwd`). Any attempt to escape (absolute paths, `..`, symlinks
pointing outside) returns an error string instead of file content. This
matters because s6 verifiers read attacker-influenced finding text; a
prompt-injected path must not exfiltrate files outside the scanned repo.

Bash is intentionally NOT provided. s6_verify only requests
Read/Glob/Grep; s1_preprocess (which wants Bash) should stay on via:cli.
"""
from __future__ import annotations
import os
import re
from pathlib import Path

from vvaharness.report.redact import redact_counts

_MAX_BYTES = 200_000
_MAX_MATCHES = 200
_MAX_GLOB = 500
# Per-line ceiling for the Grep regex scan. The pattern is model-supplied, so a
# pathological line (e.g. a multi-KB minified blob) fed to a backtracking regex
# could pin a worker thread. Bounding the bytes the regex sees per line caps
# that work; the cap is high enough that normal source lines are unaffected.
_MAX_GREP_LINE = 50_000


def _jail(root: Path, p: str) -> Path | None:
    try:
        cand = (root / p).resolve() if not os.path.isabs(p) else Path(p).resolve()
    except (OSError, ValueError):
        return None
    try:
        cand.relative_to(root)
    except ValueError:
        return None
    return cand


def _read(root: Path, path: str, offset: int = 0, limit: int = 2000) -> str:
    fp = _jail(root, path)
    if fp is None:
        return f"ERROR: path '{path}' is outside the repository root"
    if not fp.is_file():
        return f"ERROR: file not found: {path}"
    try:
        with open(fp, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read(_MAX_BYTES * 4).splitlines()
    except OSError as e:
        return f"ERROR: cannot read {path}: {e}"
    start = max(0, int(offset))
    end = start + max(1, int(limit))
    out = []
    for i, line in enumerate(lines[start:end], start + 1):
        out.append(f"{i}\t{line}")
    body = "\n".join(out)
    if len(body) > _MAX_BYTES:
        body = body[:_MAX_BYTES] + "\n... [truncated]"
    if not body:
        body = "(file is empty or offset past EOF)"
    return body


def _glob(root: Path, pattern: str) -> str:
    pat = pattern.lstrip("/").lstrip("\\")
    try:
        hits = sorted(
            str(p.relative_to(root)).replace("\\", "/")
            for p in root.glob(pat)
            if p.is_file() and _jail(root, str(p.relative_to(root))) is not None
        )
    except (OSError, ValueError) as e:
        return f"ERROR: invalid glob '{pattern}': {e}"
    if not hits:
        return "No files found"
    if len(hits) > _MAX_GLOB:
        return "\n".join(hits[:_MAX_GLOB]) + f"\n... ({len(hits) - _MAX_GLOB} more)"
    return "\n".join(hits)


def _grep(root: Path, pattern: str, path: str | None = None,
          glob: str | None = None, ignore_case: bool = False,
          context: int = 0) -> str:
    flags = re.IGNORECASE if ignore_case else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        return f"ERROR: invalid regex '{pattern}': {e}"

    if path:
        target = _jail(root, path)
        if target is None:
            return f"ERROR: path '{path}' is outside the repository root"
        files = [target] if target.is_file() else sorted(
            p for p in target.rglob("*")
            if p.is_file() and _jail(root, str(p)) is not None)
    elif glob:
        files = sorted(
            p for p in root.glob(glob.lstrip("/"))
            if p.is_file() and _jail(root, str(p)) is not None)
    else:
        files = sorted(
            p for p in root.rglob("*")
            if p.is_file() and _jail(root, str(p)) is not None)

    out: list[str] = []
    n = 0
    ctx = max(0, min(200, int(context)))
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(text) > _MAX_BYTES * 8:
            text = text[: _MAX_BYTES * 8]
        lines = text.splitlines()
        rel = str(fp.relative_to(root)).replace("\\", "/")

        def _clip(s: str) -> str:
            # Cap the bytes both searched and emitted per line; mark when cut.
            return s if len(s) <= _MAX_GREP_LINE else s[:_MAX_GREP_LINE] + " …[line clipped]"

        for i, line in enumerate(lines):
            # Search only the bounded prefix so a model-supplied backtracking
            # pattern cannot blow up on a pathologically long line.
            if rx.search(line[:_MAX_GREP_LINE]):
                if ctx:
                    lo, hi = max(0, i - ctx), min(len(lines), i + ctx + 1)
                    for j in range(lo, hi):
                        mark = ":" if j == i else "-"
                        out.append(f"{rel}:{j + 1}{mark}{_clip(lines[j])}")
                    out.append("--")
                else:
                    out.append(f"{rel}:{i + 1}:{_clip(line)}")
                n += 1
                if n >= _MAX_MATCHES:
                    out.append(f"... (stopped at {_MAX_MATCHES} matches)")
                    return "\n".join(out)
    return "\n".join(out) if out else "No matches found"


# ─────────────────────────────────────────────────────────────────────────────
# Public surface used by backends/oai.py
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMAS = {
    "Read": {
        "description": "Read a file from the repository. Returns numbered lines.",
        "parameters": {
            "type": "object",
            "properties": {
                "path":   {"type": "string",
                           "description": "Path relative to the repo root"},
                "offset": {"type": "integer",
                           "description": "0-based line to start from (default 0)"},
                "limit":  {"type": "integer",
                           "description": "Max lines to return (default 2000)"},
            },
            "required": ["path"],
        },
    },
    "Glob": {
        "description": "List files in the repository matching a glob pattern "
                       "(e.g. **/*.java).",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
            },
            "required": ["pattern"],
        },
    },
    "Grep": {
        "description": "Search file contents for a regex. Returns "
                       "file:line:text for each match.",
        "parameters": {
            "type": "object",
            "properties": {
                "pattern":     {"type": "string",
                                "description": "Python regex"},
                "path":        {"type": "string",
                                "description": "Restrict to this file or directory"},
                "glob":        {"type": "string",
                                "description": "Restrict to files matching this glob"},
                "ignore_case": {"type": "boolean"},
                "context":     {"type": "integer",
                                "description": "Lines of context around each match"},
            },
            "required": ["pattern"],
        },
    },
}

_EXEC = {
    "Read": lambda root, a: _read(root, a.get("path", ""),
                                  a.get("offset", 0), a.get("limit", 2000)),
    "Glob": lambda root, a: _glob(root, a.get("pattern", "")),
    "Grep": lambda root, a: _grep(root, a.get("pattern", ""),
                                  a.get("path"), a.get("glob"),
                                  bool(a.get("ignore_case", False)),
                                  a.get("context", 0)),
}


def schemas_for(allowed: list[str]) -> list[dict]:
    """Return OpenAI `tools=[...]` entries for the requested tool names.
    Unsupported names (e.g. Bash) are skipped — the caller decides whether
    that's fatal."""
    out = []
    for name in allowed:
        spec = _SCHEMAS.get(name)
        if spec:
            out.append({"type": "function",
                        "function": {"name": name, **spec}})
    return out


def anthropic_schemas_for(allowed: list[str]) -> list[dict]:
    """Return Anthropic Messages-API `tools=[...]` entries for the requested
    tool names. Same source schemas as schemas_for(); only the envelope
    differs (`input_schema` vs OpenAI's nested `function.parameters`)."""
    out = []
    for name in allowed:
        spec = _SCHEMAS.get(name)
        if spec:
            out.append({"name": name,
                        "description": spec["description"],
                        "input_schema": spec["parameters"]})
    return out


def supported(allowed: list[str]) -> tuple[list[str], list[str]]:
    ok = [t for t in allowed if t in _SCHEMAS]
    missing = [t for t in allowed if t not in _SCHEMAS]
    return ok, missing


def execute(name: str, args: dict, *, cwd: str) -> str:
    root = Path(cwd).resolve()
    fn = _EXEC.get(name)
    if fn is None:
        return f"ERROR: tool '{name}' is not available on this backend"
    try:
        result = fn(root, args or {})
    except Exception as e:  # noqa: BLE001 — tool errors are data, not crashes
        return f"ERROR: {type(e).__name__}: {e}"
    # Mask PII / credential material in file CONTENT before it is handed back
    # to the model (Read and Grep return source text; Glob returns only paths).
    # A provider/gateway PII guard would otherwise reject the request, and PII
    # must not be egressed. redact_counts() is thread-safe for the agentic loop.
    if name in ("Read", "Grep") and not result.startswith("ERROR:"):
        result, _ = redact_counts(result)
    return result
