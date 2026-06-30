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

"""remediation_agent.artifacts.diff — capture a scoped diff of the edited files.

Two strategies, in preference order:

  1. :func:`capture_git_diff` — a real, scoped ``git diff`` when the target is a
     git work tree (the "before" state is ``HEAD``).
  2. :func:`synth_unified_diff` — a synthesized unified diff for **non-git**
     targets, built with stdlib :mod:`difflib` from a pre-edit *snapshot* of the
     files (captured by the remediation runner before the agent edits them).

The runner snapshots files up-front with :func:`snapshot_files` so a patch can
always be produced regardless of whether the target is under version control.

Split into focused modules, re-exported here so callers keep using
``from vvaharness.remediation_agent.artifacts.diff import …`` unchanged:

  - :mod:`vvaharness.remediation_agent.artifacts.diff.paths`      — path normalisation + confinement
  - :mod:`vvaharness.remediation_agent.artifacts.diff.snapshot`   — pre-edit snapshots
  - :mod:`vvaharness.remediation_agent.artifacts.diff.synth`      — synthesized non-git diff
  - :mod:`vvaharness.remediation_agent.artifacts.diff.gitcapture` — real git-diff capture
"""
from __future__ import annotations

from vvaharness.remediation_agent.artifacts.diff.paths import (  # noqa: F401
    _norm_path, _safe_repo_path)
from vvaharness.remediation_agent.artifacts.diff.snapshot import (  # noqa: F401
    snapshot_files)
from vvaharness.remediation_agent.artifacts.diff.synth import (  # noqa: F401
    SYNTH_HEADER, synth_unified_diff)
from vvaharness.remediation_agent.artifacts.diff.gitcapture import (  # noqa: F401
    capture_git_diff, changed_files_whole_tree)

__all__ = [
    "_norm_path", "_safe_repo_path",
    "snapshot_files",
    "SYNTH_HEADER", "synth_unified_diff",
    "capture_git_diff", "changed_files_whole_tree",
]
