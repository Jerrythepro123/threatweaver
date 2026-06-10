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

"""Unit tests for vvaharness.backends.localtools.

Security focus: the path jail must confine Read/Glob/Grep to a single repo
root so prompt-injected paths cannot exfiltrate sibling files. These tests
build a tmp_path repo with a sibling SECRET file and assert it is never
reachable. Fully offline/deterministic: no network, no LLM, no subprocess.
"""
from pathlib import Path

import pytest

from vvaharness.backends import localtools as lt


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: a repo root with an out-of-root sibling secret.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def repo(tmp_path):
    """Create `<tmp>/repo` with files, plus a SIBLING secret outside it.

    Layout:
        <tmp>/secret.txt              <- MUST never be reachable
        <tmp>/repo/                   <- jail root
        <tmp>/repo/a.txt
        <tmp>/repo/sub/b.java
        <tmp>/repo/sub/c.py
    """
    root = tmp_path / "repo"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha\nneedle here\nbeta\n", encoding="utf-8")
    (root / "sub" / "b.java").write_text(
        "class B {}\nneedle inside java\n", encoding="utf-8")
    (root / "sub" / "c.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text(
        "TOP_SECRET_NEEDLE password=hunter2\n", encoding="utf-8")
    return root


# ─────────────────────────────────────────────────────────────────────────────
# _jail
# ─────────────────────────────────────────────────────────────────────────────

def test_jail_accepts_in_root_relative(repo):
    got = lt._jail(repo, "a.txt")
    assert got == (repo / "a.txt").resolve()


def test_jail_accepts_in_root_subdir(repo):
    got = lt._jail(repo, "sub/b.java")
    assert got == (repo / "sub" / "b.java").resolve()


def test_jail_rejects_dotdot_escape(repo):
    # ../secret.txt resolves to the sibling secret -> must be rejected.
    assert lt._jail(repo, "../secret.txt") is None


def test_jail_rejects_deep_dotdot_escape(repo):
    assert lt._jail(repo, "sub/../../secret.txt") is None


def test_jail_rejects_absolute_path_outside_root(repo):
    outside = repo.parent / "secret.txt"
    assert lt._jail(repo, str(outside)) is None


def test_jail_accepts_absolute_path_inside_root(repo):
    inside = repo / "a.txt"
    got = lt._jail(repo, str(inside))
    assert got == inside.resolve()


# ─────────────────────────────────────────────────────────────────────────────
# _read
# ─────────────────────────────────────────────────────────────────────────────

def test_read_in_root_returns_numbered_lines(repo):
    out = lt._read(repo, "a.txt")
    assert out.splitlines() == ["1\talpha", "2\tneedle here", "3\tbeta"]


def test_read_out_of_root_blocked(repo):
    out = lt._read(repo, "../secret.txt")
    assert out.startswith("ERROR:")
    assert "outside the repository root" in out
    assert "hunter2" not in out  # secret content never leaks


def test_read_absolute_out_of_root_blocked(repo):
    out = lt._read(repo, str(repo.parent / "secret.txt"))
    assert out.startswith("ERROR:")
    assert "hunter2" not in out


def test_read_missing_file_in_root(repo):
    out = lt._read(repo, "nope.txt")
    assert out.startswith("ERROR: file not found")


def test_read_offset_and_limit(repo):
    out = lt._read(repo, "a.txt", offset=1, limit=1)
    assert out == "2\tneedle here"


def test_read_offset_past_eof(repo):
    out = lt._read(repo, "a.txt", offset=100, limit=10)
    assert out == "(file is empty or offset past EOF)"


# ─────────────────────────────────────────────────────────────────────────────
# _glob
# ─────────────────────────────────────────────────────────────────────────────

def test_glob_finds_in_root(repo):
    out = lt._glob(repo, "**/*.java")
    assert out == "sub/b.java"


def test_glob_dotdot_escape_returns_nothing(repo):
    # "../*" must not surface the sibling secret.
    out = lt._glob(repo, "../*")
    assert out == "No files found"
    assert "secret" not in out


def test_glob_no_match(repo):
    assert lt._glob(repo, "**/*.does_not_exist") == "No files found"


def test_glob_strips_leading_slash(repo):
    # Leading slash is stripped, so "/a.txt" still resolves inside root.
    assert lt._glob(repo, "/a.txt") == "a.txt"


# ─────────────────────────────────────────────────────────────────────────────
# _grep
# ─────────────────────────────────────────────────────────────────────────────

def test_grep_scan_root_finds_matches(repo):
    out = lt._grep(repo, "needle")
    lines = out.splitlines()
    # Both in-root files with "needle" appear; secret never does.
    assert "a.txt:2:needle here" in lines
    assert "sub/b.java:2:needle inside java" in lines
    assert all("secret" not in ln.lower() for ln in lines)
    assert "hunter2" not in out


def test_grep_never_reads_out_of_root_via_path(repo):
    out = lt._grep(repo, "NEEDLE", path="../secret.txt")
    assert out.startswith("ERROR:")
    assert "outside the repository root" in out
    assert "hunter2" not in out


def test_grep_glob_escape_finds_nothing(repo):
    out = lt._grep(repo, "NEEDLE", glob="../*")
    assert out == "No matches found"
    assert "hunter2" not in out


def test_grep_ignore_case(repo):
    out = lt._grep(repo, "NEEDLE", ignore_case=True)
    assert "a.txt:2:needle here" in out.splitlines()


def test_grep_case_sensitive_no_match(repo):
    out = lt._grep(repo, "NEEDLE")
    assert out == "No matches found"


def test_grep_invalid_regex(repo):
    out = lt._grep(repo, "(")
    assert out.startswith("ERROR: invalid regex")


def test_grep_restrict_to_single_file(repo):
    out = lt._grep(repo, "needle", path="a.txt")
    lines = out.splitlines()
    assert lines == ["a.txt:2:needle here"]


# ─────────────────────────────────────────────────────────────────────────────
# supported() / schemas
# ─────────────────────────────────────────────────────────────────────────────

def test_supported_bash_is_missing():
    ok, missing = lt.supported(["Read", "Glob", "Grep", "Bash"])
    assert ok == ["Read", "Glob", "Grep"]
    assert missing == ["Bash"]


def test_supported_all_known():
    ok, missing = lt.supported(["Read", "Grep"])
    assert ok == ["Read", "Grep"]
    assert missing == []


def test_anthropic_schemas_for_shape():
    out = lt.anthropic_schemas_for(["Read", "Bash"])
    # Bash is skipped (not in _SCHEMAS).
    assert len(out) == 1
    entry = out[0]
    assert entry["name"] == "Read"
    assert "description" in entry
    assert entry["input_schema"]["type"] == "object"
    assert entry["input_schema"]["required"] == ["path"]
    # Anthropic envelope uses input_schema, never OpenAI's function nesting.
    assert "function" not in entry
    assert "parameters" not in entry


def test_anthropic_schemas_for_all_tools():
    out = lt.anthropic_schemas_for(["Read", "Glob", "Grep"])
    assert [e["name"] for e in out] == ["Read", "Glob", "Grep"]


def test_schemas_for_openai_envelope():
    out = lt.schemas_for(["Glob", "Bash"])
    assert len(out) == 1
    assert out[0]["type"] == "function"
    assert out[0]["function"]["name"] == "Glob"


# ─────────────────────────────────────────────────────────────────────────────
# execute() dispatch
# ─────────────────────────────────────────────────────────────────────────────

def test_execute_read_dispatch(repo):
    out = lt.execute("Read", {"path": "a.txt"}, cwd=str(repo))
    assert out.splitlines()[0] == "1\talpha"


def test_execute_glob_dispatch(repo):
    out = lt.execute("Glob", {"pattern": "**/*.java"}, cwd=str(repo))
    assert out == "sub/b.java"


def test_execute_grep_dispatch(repo):
    out = lt.execute("Grep", {"pattern": "needle"}, cwd=str(repo))
    assert "a.txt:2:needle here" in out.splitlines()


def test_execute_unknown_tool(repo):
    out = lt.execute("Bash", {"command": "ls"}, cwd=str(repo))
    assert out == "ERROR: tool 'Bash' is not available on this backend"


def test_execute_blocks_escape_through_dispatch(repo):
    out = lt.execute("Read", {"path": "../secret.txt"}, cwd=str(repo))
    assert out.startswith("ERROR:")
    assert "hunter2" not in out


def test_execute_handles_none_args(repo):
    # args=None -> falls back to {} -> Read with empty path -> not found.
    out = lt.execute("Read", None, cwd=str(repo))
    assert out.startswith("ERROR:")


# ─────────────────────────────────────────────────────────────────────────────
# Outbound PII scrubbing: file CONTENT returned to the model must be masked so
# a provider/gateway PII guard cannot reject the request (and PII is not
# egressed). Glob returns paths only and is left untouched. Synthetic test SSN.
# ─────────────────────────────────────────────────────────────────────────────

def test_execute_read_masks_pii_content(repo):
    (repo / "data.txt").write_text("account ssn = 078-05-1120\n", encoding="utf-8")
    out = lt.execute("Read", {"path": "data.txt"}, cwd=str(repo))
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out
    # line numbering still present (structure preserved)
    assert out.splitlines()[0].startswith("1\t")


def test_execute_grep_masks_pii_in_match(repo):
    (repo / "data.txt").write_text("ssn: 078-05-1120\n", encoding="utf-8")
    out = lt.execute("Grep", {"pattern": "ssn"}, cwd=str(repo))
    assert "078-05-1120" not in out
    assert "data.txt:" in out  # match location still reported


def test_execute_glob_paths_not_scrubbed(repo):
    out = lt.execute("Glob", {"pattern": "**/*.txt"}, cwd=str(repo))
    assert "a.txt" in out
    assert not out.startswith("ERROR:")


def test_execute_read_clean_file_unchanged(repo):
    out = lt.execute("Read", {"path": "a.txt"}, cwd=str(repo))
    assert out.splitlines() == ["1\talpha", "2\tneedle here", "3\tbeta"]


def test_grep_clips_pathologically_long_line(tmp_path, monkeypatch):
    # The regex must only see a bounded prefix of each line (ReDoS guard), and
    # the emitted match line is clipped with a marker — a multi-KB minified
    # blob can't blow up the scan or flood the output.
    monkeypatch.setattr(lt, "_MAX_GREP_LINE", 100)
    root = tmp_path / "r"
    root.mkdir()
    (root / "big.txt").write_text("needle" + "A" * 5000 + "\n", encoding="utf-8")
    out = lt._grep(root, "needle")
    assert "big.txt:1:" in out          # match still found
    assert "line clipped" in out        # output was clipped
    assert "A" * 200 not in out         # full 5k line not emitted
