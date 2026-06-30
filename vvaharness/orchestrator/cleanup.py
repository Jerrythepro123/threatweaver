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


from __future__ import annotations

"""orchestrator.cleanup — see package docstring."""
import os
import shutil
import stat
import sys
from pathlib import Path





def _rmtree_rw(path: Path) -> None:
    """shutil.rmtree that clears the read-only bit on Windows (.git/objects/*
    are RO and make ignore_errors=True silently leave the tree behind)."""
    def _on_err(func, p, exc_info):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass
    shutil.rmtree(path, onerror=_on_err)


# Checkpoints no longer live under the cloned repo, so only the report output
# dir is preserved on cleanup.
_CLONE_KEEP_DEFAULT = ("security-scan",)


def _preserve_set(cfg) -> set[str]:
    vals = getattr(getattr(cfg, "output", None), "preserve_on_cleanup", None)
    return set(vals) if vals else set(_CLONE_KEEP_DEFAULT)


def _purge_clone(root: Path, keep: set[str]) -> None:
    """Delete the cloned source under `root` but PRESERVE the named artifact
    folders (security-scan/ by default). Replaces a blanket rmtree so the
    scan outputs survive clone cleanup. Checkpoints live in
    $VVAHARNESS_STATE_DIR, not the clone, so they are unaffected.

    Grouped mode: each repo is a subfolder of `root` → repos go, artifacts stay.
    Single mode:  source files sit alongside the artifact folders inside `root`
                  → source goes, `root` remains holding only the kept folders."""
    if not root.exists():
        return
    for child in root.iterdir():
        if child.name in keep:
            continue
        if child.is_dir():
            _rmtree_rw(child)
        else:
            try:
                os.chmod(child, stat.S_IWRITE)
            except OSError:
                pass
            child.unlink(missing_ok=True)

    # A failed delete (locked file, perms) would otherwise leave a secret-bearing
    # clone on disk with no signal. Surface any survivor so the operator knows.
    leftover = [c.name for c in root.iterdir() if c.name not in keep]
    if leftover:
        print(f"  [cleanup] WARN: {len(leftover)} item(s) survived purge under "
              f"{root}: {', '.join(sorted(leftover))}", file=sys.stderr)
