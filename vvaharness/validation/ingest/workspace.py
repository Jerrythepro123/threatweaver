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

"""Stage a pre-patched copy of the target repo and gate on applied remediation."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from vvaharness.validation.constants.artifacts import (
    APP_DIRNAME,
    DIFF_FILENAME,
    REMEDIATION_DIRNAME,
    SCAN_DIRNAME,
)
from vvaharness.validation.ingest.errors import IngestError

_IGNORE = shutil.ignore_patterns(
    ".git",
    "venv",
    ".venv",
    "checkpoints",
    SCAN_DIRNAME,
    REMEDIATION_DIRNAME,
    "__pycache__",
    "*.pyc",
    "node_modules",
)


def stage_workspace(repo: Path, workspace: Path, diff: str) -> None:
    """Copy the repo into the workspace (hardlinking when possible) and drop the diff."""
    if workspace.exists():
        shutil.rmtree(workspace)
    try:
        shutil.copytree(repo, workspace, ignore=_IGNORE, copy_function=os.link)
    except (OSError, NotImplementedError):
        shutil.copytree(repo, workspace, ignore=_IGNORE)
    (workspace / DIFF_FILENAME).write_text(diff, encoding="utf-8")


def _under_repo(repo: Path, candidate: Path) -> Path | None:
    """Return the resolved *candidate* iff it stays within *repo*, else None (fail closed).

    Resolving follows symlinks, so an in-repo symlink that points outside is rejected too.
    """
    try:
        resolved = candidate.resolve()
        resolved.relative_to(repo.resolve())
    except (ValueError, OSError):
        return None
    return resolved


def _resolve_touched(repo: Path, touched: str) -> Path | None:
    """Resolve a touched path under the repo, trying the ``app/`` prefix fallback.

    Absolute paths and any ``..``/symlink escape outside the repo root are rejected (CWE-22):
    such a path must never satisfy the remediation-applied marker by pointing at a host file.
    """
    if Path(touched).is_absolute():
        return None
    for base in (repo / touched, repo / APP_DIRNAME / touched):
        candidate = _under_repo(repo, base)
        if candidate is not None and candidate.exists():
            return candidate
    return None


def _any_touched_exists(repo: Path, files_touched: list[str]) -> bool:
    """Return True if at least one declared touched file resolves on disk under *repo*."""
    return any(_resolve_touched(repo, touched) is not None for touched in files_touched)


def assert_remediation_applied(repo: Path, files_touched: list[str]) -> None:
    """Refuse validation only when the fix didn't land — i.e. no touched file exists.

    The patch's ``files_touched`` must point at real files in the staged repo; an empty
    list or paths that don't resolve mean there is nothing to validate.
    """
    if not _any_touched_exists(repo, files_touched):
        raise IngestError(f"no touched files found under {repo}: {files_touched}")
