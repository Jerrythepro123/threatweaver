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
Codex CLI backend. Same public surface as backends.claude_cli:

    prompt(...)  -> single-shot, no repo tools requested
    agentic(...) -> Codex runs in the target repo and may inspect files

On Windows this backend is WSL-first because the desktop app's WindowsApps
``codex.exe`` can deny subprocess execution. Operators can pin the Linux distro
with ``VVAHARNESS_CODEX_WSL_DISTRO`` or a config ``codex.wsl_distro`` block.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

from vvaharness.report.redact import redact
from vvaharness.util.tokens import TOKENS


_cfg: dict = {
    "use_wsl": None,
    "wsl_distro": None,
    "binary": None,
    "sandbox": "workspace-write",
    "approval_policy": "never",
    "full_auto": False,
}
_caps_cache: dict | None = None

_ABORT = threading.Event()
_LIVE_LOCK = threading.Lock()
_LIVE: set[subprocess.Popen] = set()

_SECRET_LINE_RX = re.compile(
    r"(?im)^(.*?\b(authorization|api[-_ ]?key|x-api-key|cookie|set-cookie|"
    r"token|secret|bearer)\b\s*[:=]\s*).+$")
_BEARER_RX = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]+")
_OPENAI_KEY_RX = re.compile(r"(sk-[A-Za-z0-9_-]{6})[A-Za-z0-9_-]+")
_RETRYABLE_RX = re.compile(
    r"\b429\b|rate.?limit|too many requests|overloaded|temporarily unavailable"
    r"|connection (?:reset|closed|aborted)|ECONNRESET|EPIPE|broken pipe",
    re.IGNORECASE,
)
_RL_BACKOFF = (30, 60, 120, 240)

_SUPPORTED_TOOLS = {"Read", "Glob", "Grep", "Bash"}


def aborted() -> bool:
    return _ABORT.is_set()


def abort() -> int:
    _ABORT.set()
    with _LIVE_LOCK:
        procs = list(_LIVE)
    for proc in procs:
        _kill_tree(proc)
    return len(procs)


def reset_abort() -> None:
    _ABORT.clear()


def configure(*, use_wsl: bool | str | None = None,
              wsl_distro: str | None = None,
              binary: str | None = None,
              sandbox: str | None = None,
              approval_policy: str | None = None,
              full_auto: bool | None = None,
              no_proxy: str | None = None) -> None:
    """Configure the Codex subprocess.

    Auth is delegated to Codex/OpenAI in the operator's environment. ``no_proxy``
    is passed through as process environment because WSL inherits it.
    """
    global _caps_cache
    if use_wsl is not None:
        _cfg["use_wsl"] = _as_bool(use_wsl)
    if wsl_distro:
        _cfg["wsl_distro"] = wsl_distro
    if binary:
        _cfg["binary"] = binary
    if sandbox:
        _cfg["sandbox"] = sandbox
    if approval_policy:
        _cfg["approval_policy"] = approval_policy
    if full_auto is not None:
        _cfg["full_auto"] = bool(full_auto)
    if no_proxy:
        os.environ["NO_PROXY"] = no_proxy
        os.environ["no_proxy"] = no_proxy
    _caps_cache = None


def _as_bool(v: bool | str) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _scrub(text: str | None) -> str:
    if not text:
        return ""
    text = _OPENAI_KEY_RX.sub(r"\1***", text)
    text = _BEARER_RX.sub(r"\1***", text)
    text = _SECRET_LINE_RX.sub(r"\1***", text)
    return redact(text)


def _find_codex_cmd() -> list[str]:
    override = _cfg["binary"] or os.environ.get("VVAHARNESS_CODEX_BINARY")
    if override:
        return [override]

    use_wsl = _cfg["use_wsl"]
    env_use_wsl = os.environ.get("VVAHARNESS_CODEX_WSL")
    if env_use_wsl is not None:
        use_wsl = _as_bool(env_use_wsl)
    if use_wsl is None:
        use_wsl = os.name == "nt"

    # Only Windows should launch Codex through WSL. When vvaharness itself is
    # already running inside Linux/WSL, a profile-level use_wsl:true would
    # otherwise recursively call wsl.exe and lose the intended environment.
    if use_wsl and os.name == "nt":
        wsl = shutil.which("wsl.exe") or shutil.which("wsl") or "wsl.exe"
        distro = _cfg["wsl_distro"] or os.environ.get("VVAHARNESS_CODEX_WSL_DISTRO")
        cmd = [wsl]
        if distro:
            cmd += ["-d", distro]
        return cmd + ["--exec", "codex"]

    resolved = shutil.which("codex")
    if resolved:
        return [resolved]
    print("  [codex] WARN: 'codex' not found on PATH; using bare name",
          file=sys.stderr)
    return ["codex"]


def _cmd_uses_wsl(cmd: list[str]) -> bool:
    return bool(cmd) and Path(cmd[0]).name.lower() in {"wsl", "wsl.exe"}


def _codex_capabilities() -> dict:
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache
    help_text = ""
    try:
        r = subprocess.run([*_find_codex_cmd(), "exec", "--help"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=20)
        help_text = (r.stdout or "") + (r.stderr or "")
    except Exception:
        help_text = ""
    _caps_cache = {
        "model": "--model" in help_text or " -m" in help_text,
        "cwd": "--cd" in help_text,
        "sandbox": "--sandbox" in help_text,
        "approval": "--ask-for-approval" in help_text
                    or "--approval-policy" in help_text,
        "approval_flag": ("--approval-policy"
                          if "--approval-policy" in help_text
                          else "--ask-for-approval"),
        "full_auto": "--full-auto" in help_text,
        "skip_git_repo_check": "--skip-git-repo-check" in help_text,
        "output_last_message": "--output-last-message" in help_text,
        "probed": bool(help_text),
    }
    return _caps_cache


def _tail(text: str | None, n: int = 1200) -> str:
    text = _scrub(text)
    if len(text) <= n:
        return text.strip()
    return "...\n" + text[-n:].strip()


def _short_cmd(cmd: list[str]) -> str:
    out = []
    for arg in cmd:
        if len(arg) > 80:
            out.append(f"{arg[:60].replace(chr(10), ' ')}...<{len(arg)} chars>")
        else:
            out.append(arg)
    return " ".join(out)


def _format_error(prefix: str, cmd: list[str],
                  result: subprocess.CompletedProcess) -> str:
    parts = [f"{prefix} (rc={result.returncode})", f"cmd: {_short_cmd(cmd)}"]
    err = _tail(result.stderr)
    out = _tail(result.stdout)
    if err:
        parts.append(f"stderr tail:\n{err}")
    if out:
        parts.append(f"stdout tail:\n{out}")
    if not err and not out:
        parts.append("no stdout/stderr captured")
    return "\n".join(parts)


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=10)
        else:
            proc.kill()
    except Exception:
        pass


def _run(cmd: list[str], *, input: str | None = None,
         cwd: str | None = None, timeout: int = 1800,
         env: dict | None = None, stream_cb=None,
         heartbeat_label: str | None = None,
         heartbeat_interval: int = 300) -> subprocess.CompletedProcess:
    proc_env = {**os.environ, **(env or {})}
    if stream_cb is not None:
        return _run_streaming(cmd, input=input, cwd=cwd, timeout=timeout,
                              env=proc_env, stream_cb=stream_cb)
    if not heartbeat_label:
        return subprocess.run(
            cmd, input=input, cwd=cwd, env=proc_env, timeout=timeout,
            capture_output=True, text=True, encoding="utf-8", errors="replace")

    start = time.monotonic()
    deadline = start + timeout
    pending_input = input
    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=proc_env,
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        try:
            while True:
                if _ABORT.is_set():
                    _kill_tree(proc)
                    out, err = proc.communicate()
                    raise RuntimeError("aborted by user (Ctrl-C)")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    out, err = proc.communicate()
                    raise subprocess.TimeoutExpired(cmd, timeout, output=out,
                                                    stderr=err)
                try:
                    out, err = proc.communicate(
                        input=pending_input,
                        timeout=min(float(heartbeat_interval), remaining),
                    )
                    break
                except subprocess.TimeoutExpired:
                    elapsed = int(time.monotonic() - start)
                    print(f"    [codex] {heartbeat_label} still running... "
                          f"{elapsed}s elapsed", file=sys.stderr)
                    pending_input = None
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)
        return subprocess.CompletedProcess(proc.args, proc.returncode, out, err)


def _run_streaming(cmd: list[str], *, input: str | None, cwd: str | None,
                   timeout: int, env: dict, stream_cb) -> subprocess.CompletedProcess:
    chunks: list[str] = []

    def _reader(pipe):
        for line in iter(pipe.readline, ""):
            chunks.append(line)
            try:
                stream_cb(line)
            except Exception:
                pass
        pipe.close()

    with subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
        env=env,
        bufsize=1,
    ) as proc:
        with _LIVE_LOCK:
            _LIVE.add(proc)
        reader = threading.Thread(target=_reader, args=(proc.stdout,), daemon=True)
        reader.start()
        try:
            if input is not None:
                try:
                    proc.stdin.write(input)
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
            proc.wait(timeout=timeout)
        finally:
            with _LIVE_LOCK:
                _LIVE.discard(proc)
        reader.join(timeout=5)
        err = proc.stderr.read() if proc.stderr else ""
    return subprocess.CompletedProcess(cmd, proc.returncode, "".join(chunks), err)


def _is_transient_failure(result: subprocess.CompletedProcess) -> bool:
    return bool(_RETRYABLE_RX.search(f"{result.stdout or ''}\n{result.stderr or ''}"))


def _run_with_retry(cmd: list[str], *, label: str, **kw) -> subprocess.CompletedProcess:
    attempt = 0
    while True:
        result = _run(cmd, **kw)
        if result.returncode == 0:
            return result
        if attempt >= len(_RL_BACKOFF) or not _is_transient_failure(result):
            return result
        wait = _RL_BACKOFF[attempt]
        print(f"    [codex] {label}: transient upstream error (attempt "
              f"{attempt + 1}/{len(_RL_BACKOFF)}); retrying in {wait}s",
              file=sys.stderr)
        slept = 0
        while slept < wait:
            if _ABORT.is_set():
                raise RuntimeError("aborted by user (Ctrl-C)")
            time.sleep(min(5, wait - slept))
            slept += 5
        attempt += 1


def _output_file_path() -> str:
    return str(Path(tempfile.gettempdir()) / f"vvaharness-codex-{uuid.uuid4().hex}.txt")


def _build_exec_cmd(*, model: str, cwd: str | None,
                    output_last_message: str | None,
                    prompt_text: str) -> list[str]:
    caps = _codex_capabilities()
    base = _find_codex_cmd()
    cmd = [*base, "exec"]
    if model and caps.get("model", True):
        cmd += ["--model", model]
    if cwd and caps.get("cwd"):
        cmd += ["--cd", cwd]
    if _cfg.get("full_auto") and caps.get("full_auto"):
        cmd += ["--full-auto"]
    else:
        if _cfg.get("sandbox") and caps.get("sandbox"):
            cmd += ["--sandbox", str(_cfg["sandbox"])]
        if _cfg.get("approval_policy") and caps.get("approval"):
            cmd += [caps.get("approval_flag") or "--ask-for-approval",
                    str(_cfg["approval_policy"])]
    if caps.get("skip_git_repo_check"):
        cmd += ["--skip-git-repo-check"]
    if (output_last_message and caps.get("output_last_message")
            and not _cmd_uses_wsl(base)):
        cmd += ["--output-last-message", output_last_message]
    return cmd + [prompt_text]


def _compose_prompt(user_prompt: str, system_prompt: str | None,
                    tool_note: str | None = None) -> str:
    parts: list[str] = []
    if system_prompt:
        parts.append(f"System instructions:\n{system_prompt.strip()}")
    if tool_note:
        parts.append(tool_note)
    parts.append(user_prompt)
    return "\n\n".join(parts)


def prompt(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    max_tokens: int | None = None,
    timeout: int = 1800,
    tag: str | None = None,
    **_: object,
) -> str:
    if _ABORT.is_set():
        raise RuntimeError("aborted by user (Ctrl-C)")
    out_path = _output_file_path() if _codex_capabilities().get("output_last_message") else None
    tool_note = (
        "Return only a valid JSON object. Do not include Markdown fences or prose."
        if json_schema or output_format == "json" else None
    )
    prompt_text = _compose_prompt(user_prompt, system_prompt, tool_note)
    cmd = _build_exec_cmd(
        model=model,
        cwd=cwd,
        output_last_message=out_path,
        prompt_text=prompt_text,
    )
    env = {"OPENAI_MAX_OUTPUT_TOKENS": str(max_tokens)} if max_tokens else None
    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [codex] prompt mode -> {model}{tag_sfx} "
          f"({len(user_prompt)} chars)", file=sys.stderr)
    result = _run_with_retry(
        cmd,
        label=f"prompt({model}){tag_sfx}",
        input=None,
        cwd=cwd if not _codex_capabilities().get("cwd") else None,
        timeout=timeout,
        env=env,
        heartbeat_label=f"prompt mode ({model}){tag_sfx}",
    )
    if result.returncode != 0:
        raise RuntimeError(_format_error("codex CLI failed", cmd, result))
    text = ""
    if out_path and Path(out_path).is_file():
        try:
            text = Path(out_path).read_text(encoding="utf-8", errors="replace")
            Path(out_path).unlink(missing_ok=True)
        except OSError:
            text = ""
    if not text:
        text = result.stdout
    TOKENS.add(None)
    return text.strip()


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",
    max_turns: int | None = None,
    timeout: int = 3600,
    tag: str | None = None,
    stream_cb=None,
    **_: object,
) -> str:
    allowed = list(allowed_tools or ["Read", "Glob", "Grep"])
    unsupported = [t for t in allowed if t not in _SUPPORTED_TOOLS]
    if unsupported:
        raise NotImplementedError(
            f"via:codex agentic() does not implement tools {unsupported}. "
            "Supported: Read, Glob, Grep, Bash."
        )
    if "Bash" in allowed:
        note = (
            "You are running under vvaharness inside the target repository. "
            f"Use only these tool categories: {', '.join(allowed)}. "
            "Bash is allowed only for bounded local inspection, build, test, and repro commands. "
            "During ASAN build, build/configuration files may be amended only to fix compilation; "
            "source files and application logic must not be changed. Do not install packages, use the network, "
            "use git, sudo, docker/podman, or run destructive commands. Write generated repro artifacts only "
            "under the requested security-scan/asan/bug*/build_attempt*/ or "
            "security-scan/asan/bug*/repro_attempt*/ directory."
        )
    else:
        note = (
            "You are running under vvaharness as a read-only repository inspector. "
            f"Use only these tool categories when inspecting the repo: {', '.join(allowed)}. "
            "Do not modify files."
        )
    prompt_text = _compose_prompt(user_prompt, system_prompt, note)
    out_path = _output_file_path() if _codex_capabilities().get("output_last_message") else None
    cmd = _build_exec_cmd(
        model=model,
        cwd=cwd,
        output_last_message=out_path,
        prompt_text=prompt_text,
    )
    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [codex] agentic mode -> {model}{tag_sfx}, cwd={cwd}",
          file=sys.stderr)
    result = _run_with_retry(
        cmd,
        label=f"agentic({model}){tag_sfx}",
        input=None,
        cwd=cwd if not _codex_capabilities().get("cwd") else None,
        timeout=timeout,
        heartbeat_label=None if stream_cb else f"agentic mode ({model}){tag_sfx}",
        stream_cb=stream_cb,
    )
    if result.returncode != 0:
        raise RuntimeError(_format_error("codex CLI agentic failed", cmd, result))
    text = ""
    if out_path and Path(out_path).is_file():
        try:
            text = Path(out_path).read_text(encoding="utf-8", errors="replace")
            Path(out_path).unlink(missing_ok=True)
        except OSError:
            text = ""
    if not text:
        text = result.stdout
    TOKENS.add(None)
    return text.strip()
