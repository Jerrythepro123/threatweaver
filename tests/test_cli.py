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

"""Unit tests for vvaharness.cli helpers: _config_path_from, _check_python,
_load_dotenv. Fully offline/deterministic — importlib.metadata and dotenv are
monkeypatched; no network, no real subprocess, no LLM calls."""
import importlib.metadata as ilm
import sys
import types

import pytest

from vvaharness import cli
from vvaharness.orchestrator import _default_config


# --------------------------------------------------------------------------- #
# _config_path_from
# --------------------------------------------------------------------------- #
def test_config_path_from_default_when_absent():
    # No --config anywhere => packaged/default config path.
    expected = str(_default_config())
    assert cli._config_path_from([]) == expected
    assert cli._config_path_from(["--repo", "/tmp/x", "scan"]) == expected


def test_config_path_from_split_form():
    assert cli._config_path_from(["--config", "/etc/foo.yaml"]) == "/etc/foo.yaml"


def test_config_path_from_joined_form():
    assert cli._config_path_from(["--config=/etc/bar.yaml"]) == "/etc/bar.yaml"


def test_config_path_from_last_wins_split():
    # Repeated flag: last occurrence wins, matching argparse.
    rest = ["--config", "/first.yaml", "--config", "/second.yaml"]
    assert cli._config_path_from(rest) == "/second.yaml"


def test_config_path_from_last_wins_mixed_forms():
    rest = ["--config=/a.yaml", "--repo", "/code", "--config", "/b.yaml"]
    assert cli._config_path_from(rest) == "/b.yaml"


def test_config_path_from_joined_wins_when_last():
    rest = ["--config", "/a.yaml", "--config=/c.yaml"]
    assert cli._config_path_from(rest) == "/c.yaml"


def test_config_path_from_dangling_flag_falls_back():
    # `--config` with no following value (i+1 out of range) is ignored,
    # so the default is returned rather than raising.
    assert cli._config_path_from(["--config"]) == str(_default_config())


def test_config_path_from_empty_string_value_is_honoured():
    # An explicit empty value is `not None`, so it is returned verbatim
    # (the function distinguishes "absent" from "empty").
    assert cli._config_path_from(["--config", ""]) == ""


# ─────────────────────────────────────────────────────────────────────────────
# _doctor — config existence guard
# ─────────────────────────────────────────────────────────────────────────────

def test_doctor_missing_config_returns_nonzero_without_raising(capsys):
    rc = cli._doctor(["--config", "/no/such/config-does-not-exist.yaml"])
    assert rc != 0
    assert "config not found" in capsys.readouterr().err


@pytest.mark.parametrize(("argv", "target"), [
    (["setup"], "_setup"),
    (["doctor"], "_doctor"),
    (["estimate"], "_estimate"),
])
def test_main_handles_keyboard_interrupt_for_commands(monkeypatch, capsys, argv, target):
    monkeypatch.setattr(cli, target, lambda rest: (_ for _ in ()).throw(KeyboardInterrupt()))
    rc = cli.main(argv)
    assert rc == 130
    err = capsys.readouterr().err
    assert "command aborted by user" in err
    assert "Traceback" not in err


# --------------------------------------------------------------------------- #
# _check_python  (metadata-driven floor)
# --------------------------------------------------------------------------- #
def _meta_with_requires(value):
    """Build a fake metadata mapping exposing .get('Requires-Python')."""
    class _Meta:
        def get(self, key, default=None):
            if key == "Requires-Python":
                return value
            return default
    return _Meta()


def test_check_python_returns_none_when_metadata_absent(monkeypatch):
    # importlib.metadata.metadata raising (PackageNotFound-style) => skip.
    def _raise(_name):
        raise ilm.PackageNotFoundError("vvaharness")
    monkeypatch.setattr(ilm, "metadata", _raise)
    assert cli._check_python() is None


def test_check_python_returns_none_when_no_requires_constraint(monkeypatch):
    # Metadata present but no `>=X.Y` token => no floor to enforce.
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(""))
    assert cli._check_python() is None
    monkeypatch.setattr(
        ilm, "metadata", lambda _n: _meta_with_requires("<4.0"))
    assert cli._check_python() is None


def test_check_python_passes_when_interpreter_meets_floor(monkeypatch):
    # Floor below the running interpreter => no error.
    low = f">={sys.version_info[0]}.{max(sys.version_info[1] - 1, 0)}"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(low))
    assert cli._check_python() is None


def test_check_python_fails_when_interpreter_below_floor(monkeypatch):
    # Floor above the running interpreter => error string mentioning the floor.
    high = f">={sys.version_info[0]}.{sys.version_info[1] + 1}"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(high))
    err = cli._check_python()
    assert err is not None
    assert "requires Python" in err
    assert f">= {sys.version_info[0]}.{sys.version_info[1] + 1}" in err


def test_check_python_parses_floor_with_whitespace(monkeypatch):
    # The regex tolerates whitespace after `>=`.
    high = f">= {sys.version_info[0]}.{sys.version_info[1] + 2}, <99"
    monkeypatch.setattr(ilm, "metadata", lambda _n: _meta_with_requires(high))
    err = cli._check_python()
    assert err is not None
    assert f"{sys.version_info[0]}.{sys.version_info[1] + 2}" in err


# --------------------------------------------------------------------------- #
# _load_dotenv
# --------------------------------------------------------------------------- #
def _install_fake_dotenv(monkeypatch, find_return, calls):
    """Install a fake `dotenv` module so `from dotenv import ...` works."""
    fake = types.ModuleType("dotenv")

    def find_dotenv(*args, **kwargs):
        calls["find"] = (args, kwargs)
        return find_return

    def load_dotenv(*args, **kwargs):
        calls["load"] = (args, kwargs)
        return True

    fake.find_dotenv = find_dotenv
    fake.load_dotenv = load_dotenv
    monkeypatch.setitem(sys.modules, "dotenv", fake)
    return fake


def test_load_dotenv_loads_with_usecwd_and_no_override(monkeypatch):
    calls = {}
    _install_fake_dotenv(monkeypatch, "/proj/.env", calls)
    cli._load_dotenv()
    # find_dotenv called with usecwd=True
    assert calls["find"][1].get("usecwd") is True
    # load_dotenv called with the found path and override=False
    assert calls["load"][0][0] == "/proj/.env"
    assert calls["load"][1].get("override") is False


def test_load_dotenv_noop_when_no_dotenv_found(monkeypatch):
    calls = {}
    # find_dotenv returns empty string (falsy) => load_dotenv never called.
    _install_fake_dotenv(monkeypatch, "", calls)
    cli._load_dotenv()
    assert "find" in calls
    assert "load" not in calls


def test_load_dotenv_noop_when_dotenv_unavailable(monkeypatch):
    # Simulate python-dotenv not installed: importing it raises ImportError.
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "dotenv":
            raise ImportError("No module named 'dotenv'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Must not raise despite missing dependency.
    assert cli._load_dotenv() is None

def test_path_within_detects_in_target(tmp_path):
    from vvaharness.orchestrator.config_paths import _path_within
    repo = tmp_path / "target"
    (repo / "sub").mkdir(parents=True)
    assert _path_within(repo / "config.yaml", repo) is True
    assert _path_within(repo / "sub" / ".env", repo) is True
    assert _path_within(tmp_path / "config.yaml", repo) is False   # sibling
    assert _path_within(tmp_path / "other" / "x", repo) is False


def test_load_dotenv_refuses_env_inside_scan_target(monkeypatch, tmp_path):
    monkeypatch.delenv("VVAHARNESS_ALLOW_CWD_CONFIG", raising=False)
    repo = tmp_path / "target"
    repo.mkdir()
    inside = repo / ".env"
    inside.write_text("ANTHROPIC_BASE_URL=https://attacker.example\n",
                      encoding="utf-8")
    outside = tmp_path / ".env"
    outside.write_text("X=1\n", encoding="utf-8")

    # (a) .env INSIDE the scan target → refused (never loaded)
    calls = {}
    _install_fake_dotenv(monkeypatch, str(inside), calls)
    cli._load_dotenv(str(repo))
    assert "load" not in calls

    # (b) .env OUTSIDE the target → still loaded (no over-refusal)
    calls = {}
    _install_fake_dotenv(monkeypatch, str(outside), calls)
    cli._load_dotenv(str(repo))
    assert calls["load"][0][0] == str(outside)

    # (c) explicit opt-in override loads even an in-target .env
    monkeypatch.setenv("VVAHARNESS_ALLOW_CWD_CONFIG", "1")
    calls = {}
    _install_fake_dotenv(monkeypatch, str(inside), calls)
    cli._load_dotenv(str(repo))
    assert calls["load"][0][0] == str(inside)
