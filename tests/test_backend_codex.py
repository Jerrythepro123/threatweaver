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

"""Offline unit tests for vvaharness.backends.codex."""
import subprocess

import pytest

from vvaharness.backends import codex


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(codex, "_cfg", {
        "use_wsl": None,
        "wsl_distro": None,
        "binary": None,
        "sandbox": "workspace-write",
        "approval_policy": "never",
        "full_auto": False,
    })
    monkeypatch.setattr(codex, "_caps_cache", None)
    monkeypatch.delenv("VVAHARNESS_CODEX_BINARY", raising=False)
    monkeypatch.delenv("VVAHARNESS_CODEX_WSL", raising=False)
    monkeypatch.delenv("VVAHARNESS_CODEX_WSL_DISTRO", raising=False)
    yield


def _ok(stdout="answer"):
    return subprocess.CompletedProcess(["codex"], 0, stdout, "")


def test_find_codex_cmd_defaults_to_wsl_on_windows(monkeypatch):
    monkeypatch.setattr(codex.os, "name", "nt")
    monkeypatch.setattr(codex.shutil, "which", lambda name: "C:\\Windows\\System32\\wsl.exe")
    assert codex._find_codex_cmd() == ["C:\\Windows\\System32\\wsl.exe", "--exec", "codex"]


def test_find_codex_cmd_adds_configured_wsl_distro(monkeypatch):
    monkeypatch.setattr(codex.os, "name", "nt")
    monkeypatch.setattr(codex.shutil, "which", lambda name: "wsl.exe")
    codex.configure(wsl_distro="Ubuntu")
    assert codex._find_codex_cmd() == ["wsl.exe", "-d", "Ubuntu", "--exec", "codex"]


def test_find_codex_cmd_honors_binary_override(monkeypatch):
    monkeypatch.setenv("VVAHARNESS_CODEX_BINARY", "/opt/bin/codex")
    assert codex._find_codex_cmd() == ["/opt/bin/codex"]


def test_prompt_builds_codex_exec_command(monkeypatch):
    captured = {}
    monkeypatch.setattr(codex, "_find_codex_cmd", lambda: ["wsl.exe", "--exec", "codex"])
    monkeypatch.setattr(codex, "_codex_capabilities", lambda: {
        "model": True,
        "cwd": True,
        "sandbox": True,
        "approval": True,
        "full_auto": True,
        "skip_git_repo_check": True,
        "output_last_message": False,
    })

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["kw"] = kw
        return _ok(" final text ")

    monkeypatch.setattr(codex, "_run_with_retry", fake_run)
    out = codex.prompt("hello", model="gpt-5.5-codex", cwd="/mnt/c/repo", max_tokens=7)
    assert out == "final text"
    cmd = captured["cmd"]
    assert cmd[:4] == ["wsl.exe", "--exec", "codex", "exec"]
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "gpt-5.5-codex"
    assert "--cd" in cmd
    assert cmd[cmd.index("--cd") + 1] == "/mnt/c/repo"
    assert "--sandbox" in cmd
    assert "--ask-for-approval" in cmd
    assert "--skip-git-repo-check" in cmd
    assert captured["kw"]["input"] is None
    assert cmd[-1] == "hello"
    assert captured["kw"]["env"]["OPENAI_MAX_OUTPUT_TOKENS"] == "7"


def test_prompt_uses_output_last_message_file_when_supported(monkeypatch, tmp_path):
    monkeypatch.setattr(codex, "_find_codex_cmd", lambda: ["codex"])
    monkeypatch.setattr(codex.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(codex, "_codex_capabilities", lambda: {
        "model": False,
        "cwd": False,
        "sandbox": False,
        "approval": False,
        "full_auto": False,
        "skip_git_repo_check": False,
        "output_last_message": True,
    })

    def fake_run(cmd, **kw):
        path = cmd[cmd.index("--output-last-message") + 1]
        assert path.startswith(str(tmp_path))
        with open(path, "w", encoding="utf-8") as f:
            f.write("from file")
        return _ok("noisy transcript")

    monkeypatch.setattr(codex, "_run_with_retry", fake_run)
    assert codex.prompt("hello", model="ignored") == "from file"


def test_prompt_failure_scrubs_secret(monkeypatch):
    monkeypatch.setattr(codex, "_find_codex_cmd", lambda: ["codex"])
    monkeypatch.setattr(codex, "_codex_capabilities", lambda: {})
    monkeypatch.setattr(
        codex,
        "_run_with_retry",
        lambda *a, **k: subprocess.CompletedProcess(
            ["codex"], 1, "", "Authorization: bearer super-secret-token"),
    )
    with pytest.raises(RuntimeError) as ei:
        codex.prompt("hello", model="m")
    assert "super-secret-token" not in str(ei.value)
    assert "Authorization: ***" in str(ei.value)


def test_agentic_rejects_unsupported_tools_before_launch(monkeypatch):
    monkeypatch.setattr(codex, "_find_codex_cmd", lambda: ["codex"])
    with pytest.raises(NotImplementedError, match="Write"):
        codex.agentic("hi", model="m", cwd=".", allowed_tools=["Read", "Write"])


def test_agentic_includes_tool_instruction_and_stream_callback(monkeypatch):
    captured = {}
    seen = []
    monkeypatch.setattr(codex, "_find_codex_cmd", lambda: ["codex"])
    monkeypatch.setattr(codex, "_codex_capabilities", lambda: {})

    def fake_run(cmd, **kw):
        captured["input"] = kw["input"]
        captured["cmd"] = cmd
        kw["stream_cb"]("line")
        return _ok("done")

    monkeypatch.setattr(codex, "_run_with_retry", fake_run)
    out = codex.agentic(
        "inspect",
        model="m",
        cwd=".",
        allowed_tools=["Read", "Glob", "Grep"],
        stream_cb=seen.append,
    )
    assert out == "done"
    assert captured["input"] is None
    assert "Read, Glob, Grep" in captured["cmd"][-1]
    assert seen == ["line"]
