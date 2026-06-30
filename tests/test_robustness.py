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

"""Robustness fixes: config defaults, CLI capability detection, credential
presence-only output, and the bare-command help path. These guard the changes
that stop a partial config or an incompatible Claude CLI from crashing a scan
(and stop a user's agent from "fixing" the source to work around them)."""
from __future__ import annotations

import pytest

from vvaharness import config as config_mod
from vvaharness import cli
from vvaharness.orchestrator import _mask
from vvaharness.backends import claude_cli as cc


# ── Config defaults: a partial config never crashes a stage ──────────────────
def _write(tmp_path, text):
    p = tmp_path / "profile.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_partial_config_fills_step_defaults(tmp_path):
    cfg = config_mod.load(_write(tmp_path, "models:\n  deepdive: {id: x, via: cli}\n"))
    # Keys the deep-dive stage reads directly must resolve, not raise.
    assert cfg.step4.vote_threshold == 1
    assert cfg.step4.line_bucket == 10
    assert cfg.step4.max_findings_per_run == 10
    assert cfg.step6_verify.min_confidence == 7
    assert cfg.step3.taint_max_hops == 10


def test_user_values_win_over_defaults(tmp_path):
    cfg = config_mod.load(_write(tmp_path, "step4:\n  parallel: 9\n  vote_threshold: 2\n"))
    assert cfg.step4.parallel == 9          # explicit user value
    assert cfg.step4.vote_threshold == 2    # explicit user value (differs from default)
    assert cfg.step4.line_bucket == 10      # gap filled from defaults


def test_empty_config_still_has_all_steps(tmp_path):
    cfg = config_mod.load(_write(tmp_path, "# just a comment\n"))
    assert cfg.step4.runs == 1
    assert cfg.step1.max_file_kb == 1024


# ── Credential output: presence only, never any key material ─────────────────
def test_mask_never_emits_key_material():
    secret = "sk-ant-supersecret-0123456789"
    out = _mask(secret)
    assert out == "set ✓"
    # No substring of the secret, no length, no prefix leaks.
    assert "sk-ant" not in out
    assert "0123" not in out
    assert str(len(secret)) not in out


def test_mask_unset():
    assert _mask(None) == "<unset>"
    assert _mask("") == "<unset>"


# ── Claude CLI capability detection ──────────────────────────────────────────
@pytest.fixture
def fake_caps(monkeypatch):
    def _set(effort, modes):
        monkeypatch.setattr(cc, "_caps_cache",
                            {"effort": effort, "permission_modes": set(modes),
                             "probed": True})
    return _set


def test_permission_mode_prefers_acceptedits_over_bypass(fake_caps):
    fake_caps(False, {"acceptEdits", "bypassPermissions", "default", "plan"})
    # 'auto' is gone in CLI 2.0.x → must fall back; acceptEdits is the safe
    # default (Bash NOT auto-approved) and is preferred over bypassPermissions.
    assert cc._safe_permission_mode("auto") == "acceptEdits"


def test_permission_mode_falls_back_when_acceptedits_absent(fake_caps):
    fake_caps(False, {"bypassPermissions", "default", "plan"})
    # acceptEdits not advertised → next preference is `default`.
    assert cc._safe_permission_mode("auto") == "default"


def test_permission_mode_honoured_when_supported(fake_caps):
    fake_caps(True, {"auto", "bypassPermissions", "default"})
    assert cc._safe_permission_mode("auto") == "auto"


def test_permission_mode_unknown_probe_trusts_request(fake_caps):
    fake_caps(False, set())          # help couldn't be parsed
    assert cc._safe_permission_mode("auto") == "auto"


def test_effort_capability_flag(fake_caps):
    fake_caps(False, {"default"})
    assert cc._cli_capabilities()["effort"] is False
    fake_caps(True, {"default"})
    assert cc._cli_capabilities()["effort"] is True


# ── Bare command shows help, writes no manifest ──────────────────────────────
def test_bare_command_prints_help_no_manifest(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main([])
    assert rc == 0
    assert "Usage: vvaharness" in capsys.readouterr().out
    assert not (tmp_path / "run_manifest.json").exists()


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_help_flags_route_to_top_level_help(flag, monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    rc = cli.main([flag])
    assert rc == 0
    assert "Commands:" in capsys.readouterr().out
    assert not (tmp_path / "run_manifest.json").exists()


# ── Per-stage status reporting ───────────────────────────────────────────────
from vvaharness.util.status import stage  # noqa: E402


def test_stage_reports_success(capsys):
    with stage("Step 1 — Pre-process", n=1, total=9):
        pass
    err = capsys.readouterr().err
    assert "▶ [1/9] Step 1 — Pre-process" in err
    assert "✓ [1/9] Step 1 — Pre-process" in err


def test_stage_reports_failure_then_reraises(capsys):
    import pytest as _pytest
    with _pytest.raises(ValueError):
        with stage("Step 3 — Decompose", n=3, total=9):
            raise ValueError("boom")
    err = capsys.readouterr().err
    assert "✗ [3/9] Step 3 — Decompose — failed" in err
    assert "ValueError: boom" in err


def test_stage_without_counter(capsys):
    with stage("doing a thing"):
        pass
    err = capsys.readouterr().err
    assert "▶ doing a thing" in err
    assert "✓ doing a thing" in err


def test_stage_emits_blank_line_between_consecutive_stages(capsys):
    # Each completed stage is followed by a blank line so the [n/total] blocks
    # are visually separated in the log (1/11, blank, 2/11, …).
    with stage("Step 1", n=1, total=2):
        pass
    with stage("Step 2", n=2, total=2):
        pass
    lines = capsys.readouterr().err.split("\n")
    done1 = next(i for i, l in enumerate(lines) if "✓ [1/2] Step 1" in l)
    assert lines[done1 + 1] == ""                      # blank separator after step 1
    # and the next non-blank line is step 2's start, not glued to step 1.
    nxt = next(l for l in lines[done1 + 1:] if l.strip())
    assert "[2/2] Step 2" in nxt


def test_stage_failure_also_emits_blank_separator(capsys):
    import pytest as _pytest
    with _pytest.raises(ValueError):
        with stage("Step 1", n=1, total=2):
            raise ValueError("boom")
    lines = capsys.readouterr().err.split("\n")
    failed = next(i for i, l in enumerate(lines) if "✗ [1/2] Step 1" in l)
    assert lines[failed + 1] == ""


def test_scan_without_repo_propagates_systemexit_no_manifest(monkeypatch, tmp_path):
    """`vvaharness scan` with no --repo must surface argparse's SystemExit(2)
    and write NO manifest. Regression: a `return` inside manifest.capture's
    finally previously swallowed the SystemExit, causing an UnboundLocalError
    and a junk run_manifest.json."""
    import pytest as _pytest
    monkeypatch.chdir(tmp_path)
    with _pytest.raises(SystemExit) as ei:
        cli.main(["scan"])               # missing required --repo/--repo-file
    assert ei.value.code == 2
    assert not (tmp_path / "run_manifest.json").exists()


def test_main_passes_argv_explicitly_without_mutating_sys_argv(monkeypatch,
                                                               tmp_path):
    """The orchestrator receives its argv as a parameter; the global sys.argv
    is never overwritten, so a concurrent in-process main() can't consume
    another invocation's --repo/--config."""
    import sys as _sys
    from vvaharness import orchestrator
    seen = {}

    def fake_main(argv=None):
        seen["argv"] = argv
        return 0

    monkeypatch.setattr(orchestrator, "main", fake_main)
    monkeypatch.chdir(tmp_path)
    before = list(_sys.argv)

    rc = cli.main(["scan", "--repo", "/x"])

    assert rc == 0
    assert seen["argv"] == ["--repo", "/x"]   # scan stripped, passed explicitly
    assert _sys.argv == before                # global argv untouched


# ── structured JSON logging ──────────────────────────────────────────────────
def test_status_json_logs_when_enabled(monkeypatch, capsys):
    import json as _json
    from vvaharness.util import status as st
    monkeypatch.setenv("VVAHARNESS_JSON_LOGS", "1")
    with st.stage("Step 4 — Deep-dive", n=4, total=9):
        pass
    lines = [l for l in capsys.readouterr().err.splitlines() if l.strip()]
    recs = [_json.loads(l) for l in lines]
    assert {r["event"] for r in recs} == {"stage_start", "stage_ok"}
    assert recs[0]["stage"] == "Step 4 — Deep-dive" and recs[0]["n"] == 4


def test_status_pretty_by_default(monkeypatch, capsys):
    from vvaharness.util import status as st
    monkeypatch.delenv("VVAHARNESS_JSON_LOGS", raising=False)
    with st.stage("Step 1", n=1, total=9):
        pass
    err = capsys.readouterr().err
    assert "▶" in err and "✓" in err


# ── preflight: gateway gap fails fast (no 60s probe hang) ────────────────────
def test_check_backends_fastfails_on_gateway_gap(monkeypatch):
    """JWT-shaped ANTHROPIC_API_KEY with no ANTHROPIC_BASE_URL must abort BEFORE
    the live probe (which would otherwise hang to a timeout), with the remedy."""
    from vvaharness.orchestrator import preflight
    monkeypatch.setenv("ANTHROPIC_API_KEY", "eyJfake.jwt.token")
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    monkeypatch.setattr(preflight, "_iter_model_roles",
                        lambda cfg: [("deepdive", "node")])
    monkeypatch.setattr(preflight, "resolve_model", lambda m: ("m", "cli", {}))
    monkeypatch.setattr(preflight.shutil, "which", lambda n: "/usr/bin/claude")
    # probe must NOT be reached
    monkeypatch.setattr(preflight, "probe_backends",
                        lambda cfg: (_ for _ in ()).throw(AssertionError("probe ran")))
    assert preflight.check_backends(cfg=object()) is False


# ── live loader: spinner on a TTY, plain line otherwise ──────────────────────
def test_stage_spinner_on_tty():
    import io, time as _t
    from vvaharness.util import status as st

    class _TTY(io.StringIO):
        def isatty(self):
            return True
    out = _TTY()
    with st.stage("Step 4 — Deep-dive", n=4, total=9, stream=out):
        _t.sleep(0.25)
    cap = out.getvalue()
    assert any(f in cap for f in st._SPIN)   # animated frames appeared
    assert "✓" in cap and "(0." in cap        # final timed line


# ── setup --install-agents drops agent instructions for the installed agent ──
def test_install_agents_writes_per_agent(monkeypatch, tmp_path):
    import shutil, pathlib
    from vvaharness import cli as _cli
    proj, home = tmp_path / "proj", tmp_path / "home"
    proj.mkdir(); home.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(shutil, "which",
                        lambda c: f"/usr/bin/{c}" if c in ("claude", "gemini") else None)
    assert _cli._install_agents() == 0
    assert (proj / "AGENTS.md").exists()
    assert (proj / ".github" / "copilot-instructions.md").exists()
    assert (proj / "CLAUDE.md").exists()                       # claude detected
    assert (proj / "GEMINI.md").exists()                       # gemini detected
    assert (home / ".claude" / "skills" / "vvaharness" / "SKILL.md").exists()
    # idempotent: re-run leaves existing files untouched, no error
    assert _cli._install_agents() == 0


def test_install_agents_skips_codex_only(monkeypatch, tmp_path):
    import shutil, pathlib
    from vvaharness import cli as _cli
    proj, home = tmp_path / "p", tmp_path / "h"; proj.mkdir(); home.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.setattr(pathlib.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(shutil, "which", lambda c: None)       # no agents on PATH
    _cli._install_agents()
    assert (proj / "AGENTS.md").exists()                       # always
    assert not (proj / "CLAUDE.md").exists()                   # claude absent
    assert not (proj / "GEMINI.md").exists()
