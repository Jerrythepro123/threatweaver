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

"""remediation_agent.artifacts.diff.snapshot — pre-edit file snapshots.

The remediation runner captures the current contents of a finding's files
BEFORE the agent edits them, so a unified diff can later be synthesized for a
non-git target (:func:`synth_unified_diff`) and so the policy post-gate can
restore an exact pre-edit baseline."""
from __future__ import annotations

import logging
from pathlib import Path

from vvaharness.remediation_agent.artifacts.diff.paths import _norm_path, _safe_repo_path

log = logging.getLogger(__name__)


def snapshot_files(repo: Path, files: list[str]) -> dict[str, str | None]:
    """Capture the current contents of *files* (repo-relative) under *repo*.

    Returns a mapping of repo-relative path → file contents, or ``None`` for a
    path that does not yet exist (so a later synthesized diff can render it as a
    newly-created file). Best-effort and never raises; unreadable files map to
    ``None``."""
    repo = Path(repo)
    snap: dict[str, str | None] = {}
    for f in files or []:
        rel = _norm_path(f)
        if not rel or rel in snap:
            continue
        # Confine the reference to the repo before reading it: an absolute/`../`/
        # symlink-escape ref must NOT read host or CI-workspace files into the
        # snapshot (and thus the diff artifact). Fail closed by skipping (CWE-22).
        p = _safe_repo_path(repo, f)
        if p is None:
            log.warning("snapshot: refusing out-of-repo file reference %r "
                        "(escapes %s)", f, repo)
            continue
        try:
            snap[rel] = p.read_text(encoding="utf-8") if p.is_file() else None
        except Exception:  # noqa: BLE001 — binary/unreadable → treat as absent
            snap[rel] = None
    return snap
