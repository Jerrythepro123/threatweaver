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
Structured error log shared across pipeline stages.

Each entry is one JSON line: {ts, stage, unit, error, ...extra}. Steps call
log() from their except-handlers so transient failures (DNS blips, SDK
timeouts, parse errors) are recorded next to the report instead of being
lost in stderr scrollback.

the orchestrator calls configure() once per scan to point the log at
  <repo>/security-scan/<module>_<ts>_errors.jsonl
"""
from __future__ import annotations
import json
import os
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from vvaharness.report.redact import redact

_path: Path = Path("pipeline-errors.jsonl")
_lock = threading.Lock()


def configure(path: str | Path) -> None:
    global _path
    _path = Path(path)
    _path.parent.mkdir(parents=True, exist_ok=True)


def current_path() -> Path:
    """The errors-log path currently configured (for a report-time pointer)."""
    return _path


def counts_by_stage(path: str | Path | None = None) -> dict[str, int]:
    """Re-read the errors JSONL and tally records per `stage`.

    Best-effort and read-only: a missing or partially-garbled file yields an
    empty/partial map rather than raising. Intentionally takes no lock — it is
    called once at report time (single-threaded), so the latent reentrancy a
    lock would add is not worth it. This is a COARSE per-stage error-record
    count (a stage may log several records per failed unit, e.g. one per run
    retry); authoritative chunk-failure counts come from the s4 chunk outcomes,
    not from here.
    """
    p = Path(path) if path is not None else _path
    counts: dict[str, int] = {}
    try:
        with p.open("r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rec = json.loads(ln)
                except (json.JSONDecodeError, ValueError):
                    continue
                stage = rec.get("stage")
                if isinstance(stage, str):
                    counts[stage] = counts.get(stage, 0) + 1
    except OSError:
        return counts
    return counts


def log(stage: str, unit: str, error: BaseException | str, **extra) -> None:
    """Append one JSONL record. Never raises."""
    if isinstance(error, BaseException):
        msg = f"{type(error).__name__}: {error}"
        tb = "".join(traceback.format_exception(type(error), error,
                                                 error.__traceback__))[-4000:]
    else:
        msg, tb = str(error), None

    msg = redact(msg)
    if tb:
        tb = redact(tb)
    safe_extra = {k: (redact(v) if isinstance(v, str) else v)
                  for k, v in extra.items()}
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # `stage` is a fixed pipeline label; `unit` is repo-derived (a file
        # path / chunk id) so it is redacted too — a credential-shaped substring
        # in a path must not bypass the scrub applied to the other fields.
        "stage": stage,
        "unit": redact(unit) if isinstance(unit, str) else unit,
        "error": msg,
        **safe_extra,
    }
    if tb:
        rec["traceback"] = tb
    try:
        with _lock:
            # Tighten perms on first create so an errors log (which carries
            # redacted-but-still-sensitive context) isn't world-readable under
            # the default umask on shared CI hosts. exists() must be inside the
            # lock to avoid a TOCTOU with a concurrent writer.
            newly_created = not _path.exists()
            with _path.open("a", encoding="utf-8") as f:
                if newly_created:
                    try:
                        os.chmod(_path, 0o600)
                    except OSError:
                        pass  # Windows / unsupported FS — best-effort
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:  # noqa: BLE001
        print(f"WARN [_errlog]: failed to write {rec.get('stage')}/{rec.get('unit')}: {e}",
              file=sys.stderr)
