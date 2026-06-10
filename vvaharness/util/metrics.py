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
Build ScanMetrics from pipeline state. Kept out of the orchestrator so the main
flow stays readable.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.models import ContextPackage, TaskManifest, ScanMetrics, ScopeEntry
from vvaharness.lang.hints import EXT_TO_LANG
from vvaharness.util.tokens import TOKENS
from vvaharness.util import errlog


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build(ctx: ContextPackage, manifest: TaskManifest, *,
          repo_name: str, start_ts: str, end_ts: str,
          raw_findings: int, true_pos: int, false_pos: int,
          duplicates: int,
          chunk_outcomes: dict[str, str] | None = None) -> ScanMetrics:
    repo_root = Path(ctx.repo_root)

    # File coverage: every file that appears in at least one chunk.
    analyzed: set[str] = set()
    n_spec = n_catch = 0
    scope: list[ScopeEntry] = []
    for c in manifest.chunks:
        analyzed.update(c.files)
        if c.specialist:
            n_spec += 1
            kind = "specialist"
        elif c.id.startswith("catchall-"):
            n_catch += 1
            kind = "catchall"
        else:
            kind = "risk"
        scope.append(ScopeEntry(name=c.id, kind=kind, files=sorted(c.files)))
    n_risk = len(manifest.chunks) - n_spec - n_catch

    folders = sorted({str(Path(f).parent).replace("\\", "/")
                      for f in analyzed if "/" in f or "\\" in f} | {"."})

    # LOC by language (in-scope vs scanned).
    loc_scope: dict[str, int] = defaultdict(int)
    loc_scan: dict[str, int] = defaultdict(int)
    for f in ctx.all_files:
        lang = EXT_TO_LANG.get(Path(f).suffix.lower(), "other")
        loc = _loc(repo_root / f)
        loc_scope[lang] += loc
        if f in analyzed:
            loc_scan[lang] += loc

    try:
        s = datetime.fromisoformat(start_ts.replace("Z", "+00:00"))
        e = datetime.fromisoformat(end_ts.replace("Z", "+00:00"))
        dur = (e - s).total_seconds()
    except Exception:
        dur = 0.0

    tok = TOKENS.snapshot()
    tok_avail = tok["calls_with_usage"] > 0

    # Deep-dive chunk outcomes (authoritative failure count comes from here, not
    # from the coarse per-stage error log). Absent on a legacy --resume that
    # predates outcome-tracking → treat as clean (0 failed), no false alarm.
    chunks_attempted = len(manifest.chunks)
    chunks_failed = sum(1 for v in (chunk_outcomes or {}).values()
                        if v != "completed")

    return ScanMetrics(
        scan_id=f"{start_ts}__{repo_name}",
        module_name=repo_name,
        start_ts=start_ts,
        end_ts=end_ts,
        duration_sec=dur,
        total_files_in_scope=len(ctx.all_files),
        analyzed_files_unique=len(analyzed & set(ctx.all_files)),
        chunks_total=len(manifest.chunks),
        chunks_risk=n_risk,
        chunks_catchall=n_catch,
        chunks_specialist=n_spec,
        chunks_attempted=chunks_attempted,
        chunks_failed=chunks_failed,
        errors_by_stage=errlog.counts_by_stage(),
        errors_log_path=str(errlog.current_path()),
        loc_in_scope_by_language=dict(loc_scope),
        loc_scanned_by_language=dict(loc_scan),
        raw_findings_count=raw_findings,
        true_positive_count=true_pos,
        false_positive_count=false_pos,
        duplicate_count=duplicates,
        prompt_tokens=tok["prompt"] if tok_avail else None,
        completion_tokens=tok["completion"] if tok_avail else None,
        total_tokens=tok["total"] if tok_avail else None,
        tokens_by_phase=tok.get("by_phase") if tok_avail else None,
        folders_scanned=folders,
        scope=scope,
        excluded=ctx.excluded or {},
    )


def _loc(p: Path) -> int:
    try:
        return sum(1 for ln in p.open("r", encoding="utf-8", errors="replace")
                   if ln.strip())
    except OSError:
        return 0
