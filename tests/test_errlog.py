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

"""Unit tests for vvaharness.util.errlog (structured JSONL error log)."""
from __future__ import annotations
import json

import pytest

from vvaharness.util import errlog


# A planted secret that the redactor matches via a fixed pattern (no validator):
# a GitHub personal-access token. The literal token bytes must never survive
# into the written log line.
_PLANTED_SECRET = "ghp_" + "A" * 36
_REDACTED_MARK = "[REDACTED-GITHUB-TOKEN]"


@pytest.fixture(autouse=True)
def _isolate_errlog_path(monkeypatch, tmp_path):
    """Reset the module-global _path so test order never matters.

    errlog._path is a process-wide singleton; pin it to a per-test temp file
    and restore the original after each test.
    """
    default = tmp_path / "default-errors.jsonl"
    monkeypatch.setattr(errlog, "_path", default)
    yield


def _read_lines(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln for ln in f.read().splitlines() if ln]


# ─────────────────────────────────────────────────────────────────────────────
# configure()
# ─────────────────────────────────────────────────────────────────────────────

def test_configure_sets_path(tmp_path):
    target = tmp_path / "scan" / "mod_errors.jsonl"
    errlog.configure(target)
    assert errlog._path == target


def test_configure_creates_parent_dir(tmp_path):
    target = tmp_path / "nested" / "deeper" / "errors.jsonl"
    assert not target.parent.exists()
    errlog.configure(target)
    assert target.parent.is_dir()


def test_configure_accepts_str_and_normalizes_to_path(tmp_path):
    target = tmp_path / "as_str.jsonl"
    errlog.configure(str(target))
    from pathlib import Path
    assert isinstance(errlog._path, Path)
    assert errlog._path == target


def test_configure_idempotent_when_parent_exists(tmp_path):
    target = tmp_path / "exists" / "errors.jsonl"
    target.parent.mkdir(parents=True)
    # Must not raise (exist_ok=True).
    errlog.configure(target)
    errlog.configure(target)
    assert target.parent.is_dir()


# ─────────────────────────────────────────────────────────────────────────────
# log() — happy path / JSONL shape
# ─────────────────────────────────────────────────────────────────────────────

def test_log_writes_one_json_line(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("verify", "unit-1", "boom happened")
    lines = _read_lines(target)
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["stage"] == "verify"
    assert rec["unit"] == "unit-1"
    assert rec["error"] == "boom happened"
    assert "ts" in rec and rec["ts"]


def test_log_appends_multiple_lines(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("a", "u1", "first")
    errlog.log("b", "u2", "second")
    lines = _read_lines(target)
    assert len(lines) == 2
    assert json.loads(lines[0])["error"] == "first"
    assert json.loads(lines[1])["error"] == "second"


def test_log_string_error_has_no_traceback_key(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "plain string error")
    rec = json.loads(_read_lines(target)[0])
    assert "traceback" not in rec


def test_log_exception_records_type_message_and_traceback(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise ValueError("something failed")
    except ValueError as e:
        errlog.log("stage", "unit", e)
    rec = json.loads(_read_lines(target)[0])
    assert rec["error"] == "ValueError: something failed"
    assert "traceback" in rec
    assert "ValueError" in rec["traceback"]


def test_log_ts_is_utc_isoformat_seconds(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg")
    rec = json.loads(_read_lines(target)[0])
    # timespec="seconds" → no fractional seconds; UTC → +00:00 offset.
    assert "." not in rec["ts"]
    assert rec["ts"].endswith("+00:00")


# ─────────────────────────────────────────────────────────────────────────────
# log() — extras
# ─────────────────────────────────────────────────────────────────────────────

def test_log_extra_string_is_included(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", file="src/app.py")
    rec = json.loads(_read_lines(target)[0])
    assert rec["file"] == "src/app.py"


def test_log_non_string_extras_stay_typed(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg",
               attempt=3, ratio=0.5, ok=True, items=[1, 2], meta={"k": "v"},
               nothing=None)
    rec = json.loads(_read_lines(target)[0])
    # Non-string extras must not be coerced or run through redact().
    assert rec["attempt"] == 3 and isinstance(rec["attempt"], int)
    assert rec["ratio"] == 0.5 and isinstance(rec["ratio"], float)
    assert rec["ok"] is True
    assert rec["items"] == [1, 2]
    assert rec["meta"] == {"k": "v"}
    assert rec["nothing"] is None


# ─────────────────────────────────────────────────────────────────────────────
# log() — redaction (security-relevant)
# ─────────────────────────────────────────────────────────────────────────────

def test_planted_secret_in_message_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", f"failed with token {_PLANTED_SECRET}")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["error"]


def test_planted_secret_in_traceback_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    try:
        raise RuntimeError(f"leaked {_PLANTED_SECRET}")
    except RuntimeError as e:
        errlog.log("stage", "unit", e)
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    # Secret leaks into both the formatted message and the traceback text.
    assert _REDACTED_MARK in rec["error"]
    assert _REDACTED_MARK in rec["traceback"]


def test_planted_secret_in_string_extra_is_redacted(tmp_path):
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", context=f"env had {_PLANTED_SECRET}")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["context"]


def test_secret_in_non_string_extra_is_not_redacted(tmp_path):
    """Non-string extras are stored as-is; redact() only runs on str extras."""
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("stage", "unit", "msg", payload=[_PLANTED_SECRET])
    rec = json.loads(_read_lines(target)[0])
    # The value lives inside a list (non-string extra) so it is preserved.
    assert rec["payload"] == [_PLANTED_SECRET]


def test_planted_secret_in_unit_is_redacted(tmp_path):
    # `unit` is repo-derived (a file path / chunk id); a credential-shaped
    # substring in it must be scrubbed like the body fields, not written raw.
    target = tmp_path / "errors.jsonl"
    errlog.configure(target)
    errlog.log("inject.cves", f"/repo/{_PLANTED_SECRET}/feed.json", "msg")
    raw = target.read_text(encoding="utf-8")
    assert _PLANTED_SECRET not in raw
    rec = json.loads(raw.splitlines()[0])
    assert _REDACTED_MARK in rec["unit"]
    # The fixed stage label is preserved verbatim.
    assert rec["stage"] == "inject.cves"


# ─────────────────────────────────────────────────────────────────────────────
# log() — never raises
# ─────────────────────────────────────────────────────────────────────────────

def test_log_never_raises_on_bad_path(tmp_path, monkeypatch, capsys):
    # Point the log at a path whose parent is a regular file → open("a") fails.
    blocker = tmp_path / "iamafile"
    blocker.write_text("x", encoding="utf-8")
    bad = blocker / "cannot" / "errors.jsonl"
    monkeypatch.setattr(errlog, "_path", bad)
    # Must swallow the error and not raise.
    errlog.log("stage", "unit", "msg")
    err = capsys.readouterr().err
    assert "WARN [_errlog]" in err
    assert "stage/unit" in err


def test_log_failure_warning_does_not_propagate_exception(tmp_path, monkeypatch):
    # Force the inner write to blow up; log() must still return None cleanly.
    class _Boom:
        def open(self, *a, **k):
            raise OSError("disk on fire")
    monkeypatch.setattr(errlog, "_path", _Boom())
    assert errlog.log("stage", "unit", "msg") is None
