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

"""Unit tests for vvaharness.manifest.

Offline and deterministic: time, version lookup, git subprocess, and config
model loading are all monkeypatched so capture() produces stable output.
"""
import json
import types

import pytest

from vvaharness import manifest


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def frozen_time(monkeypatch):
    """Make time.time() and datetime.now() deterministic inside manifest.

    time.time() advances by exactly 2.5 seconds between the two calls
    capture() makes (start, then end), so duration is predictable.
    """
    times = iter([1000.0, 1002.5])

    def fake_time():
        try:
            return next(times)
        except StopIteration:
            return 1002.5

    monkeypatch.setattr(manifest.time, "time", fake_time)

    class FakeDateTime:
        _vals = iter(["2026-01-01T00:00:00+00:00", "2026-01-01T00:00:02+00:00"])

        @classmethod
        def now(cls, tz=None):
            # Return an object whose isoformat() yields a fixed string.
            try:
                val = next(cls._vals)
            except StopIteration:
                val = "2026-01-01T00:00:02+00:00"
            return types.SimpleNamespace(isoformat=lambda v=val: v)

    monkeypatch.setattr(manifest, "datetime", FakeDateTime)
    return FakeDateTime


@pytest.fixture
def no_git(monkeypatch):
    """Stub out git SHA lookup to None by default (no --repo arg path)."""
    monkeypatch.setattr(manifest, "_git_sha", lambda args: None)


@pytest.fixture
def no_models(monkeypatch):
    """Stub model-role extraction to an empty dict by default."""
    monkeypatch.setattr(manifest, "_models", lambda cfg_path: {})


# ---------------------------------------------------------------------------
# capture() field / write behavior
# ---------------------------------------------------------------------------

def test_capture_yields_expected_fields(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"
    args = ["scan", "--repo", "/x"]

    with manifest.capture(cfg, args, out=out) as m:
        # Inside the block: the seed fields should already be populated.
        assert m["tool"] == "vvaharness"
        # Version is sourced from package metadata (single source of truth), so
        # assert against the live value rather than a literal that can drift.
        from vvaharness import __version__ as _vvah_version
        assert m["version"] == _vvah_version
        assert m["argv"] == args
        assert m["config_profile"] == str(cfg)
        assert m["models"] == {}
        assert m["target_git_sha"] is None
        assert m["per_stage_cost"] is None
        assert m["exit_code"] is None
        assert m["started"] == "2026-01-01T00:00:00+00:00"
        # ended/duration not set until the context exits.
        assert "ended" not in m
        assert "duration_sec" not in m
        # A real scan sets exit_code; that's what authorises the write.
        m["exit_code"] = 0

    # After exit: ended + duration populated, file written.
    assert m["ended"] == "2026-01-01T00:00:02+00:00"
    assert m["duration_sec"] == 2.5
    assert out.exists()


def test_capture_writes_valid_json_matching_dict(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "nested" / "manifest.json"
    out.parent.mkdir()

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written == m
    assert written["tool"] == "vvaharness"
    assert written["duration_sec"] == 2.5


def test_capture_skips_write_when_scan_never_started(tmp_path, frozen_time,
                                                     no_git, no_models):
    """No manifest for a help screen / argparse error: if the body never set
    exit_code (the scan didn't start), capture() must not write a junk file."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("k: v\n", encoding="utf-8")
    out = tmp_path / "manifest.json"

    with manifest.capture(cfg, ["--help"], out=out) as m:
        pass  # exit_code stays None — simulates argparse SystemExit / help

    assert not out.exists()


def test_capture_records_exit_code_set_by_caller(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["exit_code"] == 0


def test_capture_writes_even_when_body_raises(tmp_path, frozen_time, no_git, no_models):
    """The finally block must persist the manifest even on exception."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with pytest.raises(ValueError):
        with manifest.capture(cfg, ["scan"], out=out) as m:
            m["exit_code"] = 2
            raise ValueError("boom")

    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["exit_code"] == 2
    assert written["ended"] == "2026-01-01T00:00:02+00:00"


def test_capture_defaults_dest_to_cwd(tmp_path, monkeypatch, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    with manifest.capture(cfg, ["scan"]) as m:  # no out= -> cwd/run_manifest.json
        m["exit_code"] = 0

    dest = tmp_path / "run_manifest.json"
    assert dest.exists()
    assert json.loads(dest.read_text(encoding="utf-8")) == m


def test_capture_write_failure_is_swallowed(tmp_path, monkeypatch, frozen_time,
                                             no_git, no_models, capsys):
    """An OSError writing the manifest must not propagate."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    def boom(self, *a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(manifest.Path, "write_text", boom)

    # Should not raise despite the write failing.
    with manifest.capture(cfg, ["scan"], out=out) as m:
        m["exit_code"] = 0

    assert not out.exists()
    err = capsys.readouterr().err
    assert "failed to write run manifest" in err


def test_capture_accepts_str_cfg_path(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"

    with manifest.capture(str(cfg), ["scan"], out=out) as m:
        assert m["config_profile"] == str(cfg)


# ---------------------------------------------------------------------------
# _config_sha256
# ---------------------------------------------------------------------------

def test_config_sha256_missing_returns_none(tmp_path):
    assert manifest._config_sha256(tmp_path / "nope.yaml") is None


def test_config_sha256_matches_hashlib(tmp_path):
    import hashlib
    cfg = tmp_path / "profile.yaml"
    data = b"some config bytes\n"
    cfg.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert manifest._config_sha256(cfg) == expected


# ---------------------------------------------------------------------------
# _scrub_argv  (secret redaction before argv lands in run_manifest.json)
# ---------------------------------------------------------------------------

def test_scrub_argv_redacts_flag_value_space_form():
    """`--git-token VALUE` (value in the next token) must be masked to ***."""
    out = manifest._scrub_argv(["scan", "--git-token", "ghp_" + "B" * 36])
    assert out == ["scan", "--git-token", "***"]


def test_scrub_argv_redacts_inline_equals_form():
    """`--anthropic-api-key=VALUE` (inline =VALUE) must be masked to flag=***."""
    out = manifest._scrub_argv(["scan", "--anthropic-api-key=sk-secret123456"])
    assert out == ["scan", "--anthropic-api-key=***"]


def test_scrub_argv_preserves_non_secret_keep_clones_decoy():
    """`key` alone must NOT trigger redaction — `--keep-clones` is preserved
    (guards the _SECRET_FLAG_RX bare-`key` exclusion against regression)."""
    out = manifest._scrub_argv(["scan", "--keep-clones", "--repo", "/x"])
    assert out == ["scan", "--keep-clones", "--repo", "/x"]


def test_scrub_argv_masks_secret_shaped_value_regardless_of_flag():
    """Second (shape) pass: an inline-credential URL passed as any argument is
    scrubbed even though `--repo` is not a secret-named flag."""
    url = "https://user:hunter2pw@host/r"
    out = manifest._scrub_argv(["scan", "--repo", url])
    assert "hunter2pw" not in " ".join(out)
    # Scheme + username preserved; only the password component is masked.
    assert out[2].startswith("https://user:") and out[2].endswith("@host/r")


def test_scrub_argv_leaves_ordinary_args_unchanged():
    """No secrets present -> argv passes through verbatim (no false positives)."""
    args = ["scan", "--repo", "/path/to/repo", "--config", "profile.yaml"]
    assert manifest._scrub_argv(args) == args


def test_capture_persisted_argv_contains_no_secrets(tmp_path, frozen_time,
                                                    no_git, no_models):
    """End-to-end regression guard for the run_manifest secret-persistence
    finding: secrets in argv must not survive into the on-disk manifest."""
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"
    secret_flag = "ghp_" + "C" * 36
    args = ["scan", "--repo", "https://u:topsecretpw@h/r",
            "--git-token", secret_flag, "--anthropic-api-key=sk-live-987654321"]

    with manifest.capture(cfg, args, out=out) as m:
        m["exit_code"] = 0

    raw = out.read_text(encoding="utf-8")
    assert secret_flag not in raw
    assert "topsecretpw" not in raw
    assert "sk-live-987654321" not in raw
    # Structure is otherwise intact.
    assert m["argv"][0] == "scan" and "--repo" in m["argv"]


def test_capture_includes_real_config_sha(tmp_path, frozen_time, no_git, no_models):
    import hashlib
    cfg = tmp_path / "profile.yaml"
    data = b"k: v\n"
    cfg.write_bytes(data)
    out = tmp_path / "m.json"

    with manifest.capture(cfg, ["scan"], out=out) as m:
        assert m["config_sha256"] == hashlib.sha256(data).hexdigest()


def test_capture_config_sha_none_when_missing(tmp_path, frozen_time, no_git, no_models):
    cfg = tmp_path / "absent.yaml"  # never created
    out = tmp_path / "m.json"
    with manifest.capture(cfg, ["scan"], out=out) as m:
        assert m["config_sha256"] is None


# ---------------------------------------------------------------------------
# _git_sha (subprocess mocked)
# ---------------------------------------------------------------------------

def test_git_sha_none_without_repo_arg():
    assert manifest._git_sha(["scan", "--verbose"]) is None


def test_git_sha_space_separated_repo(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["cwd"] = kw.get("cwd")
        return types.SimpleNamespace(stdout="deadbeef\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    sha = manifest._git_sha(["scan", "--repo", str(tmp_path)])
    assert sha == "deadbeef"
    # Hardened form: no `-C`; the repo is passed as cwd (resolved), so the value
    # is never in git's option position.
    assert captured["cmd"] == ["git", "rev-parse", "HEAD"]
    assert captured["cwd"] == str(tmp_path.resolve())


def test_git_sha_equals_form_repo(tmp_path, monkeypatch):
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["cwd"] = kw.get("cwd")
        return types.SimpleNamespace(stdout="abc123\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    sha = manifest._git_sha([f"--repo={tmp_path}"])
    assert sha == "abc123"
    assert captured["cmd"] == ["git", "rev-parse", "HEAD"]
    assert captured["cwd"] == str(tmp_path.resolve())


def test_git_sha_empty_output_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(
        manifest.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="   \n", returncode=0),
    )
    assert manifest._git_sha(["--repo", str(tmp_path)]) is None


def test_git_sha_subprocess_exception_returns_none(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise OSError("git not found")

    monkeypatch.setattr(manifest.subprocess, "run", boom)
    assert manifest._git_sha(["--repo", str(tmp_path)]) is None


# ── hardening: --repo is validated as a real directory BEFORE git is spawned ────
def test_git_sha_nonexistent_repo_returns_none_without_spawning(tmp_path, monkeypatch):
    spawned = {"called": False}

    def fake_run(*a, **k):
        spawned["called"] = True
        return types.SimpleNamespace(stdout="x\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    missing = tmp_path / "does-not-exist"
    assert manifest._git_sha(["--repo", str(missing)]) is None
    assert spawned["called"] is False        # rejected before any git spawn


def test_git_sha_leading_dash_repo_returns_none_without_spawning(monkeypatch):
    # The reported option-injection payload: a leading-dash --repo value. It is
    # not a real directory, so it is rejected before git is ever invoked (and it
    # would be passed via cwd, never as a git option, even if it existed).
    spawned = {"called": False}

    def fake_run(*a, **k):
        spawned["called"] = True
        return types.SimpleNamespace(stdout="x\n", returncode=0)

    monkeypatch.setattr(manifest.subprocess, "run", fake_run)
    assert manifest._git_sha(["--repo", "--git-dir=/tmp/evil/.git"]) is None
    assert spawned["called"] is False


def test_capture_uses_git_sha(tmp_path, frozen_time, no_models, monkeypatch):
    cfg = tmp_path / "profile.yaml"
    cfg.write_text("x", encoding="utf-8")
    out = tmp_path / "m.json"
    monkeypatch.setattr(
        manifest.subprocess, "run",
        lambda *a, **k: types.SimpleNamespace(stdout="feedface\n", returncode=0),
    )
    with manifest.capture(cfg, ["scan", "--repo", str(tmp_path)], out=out) as m:
        assert m["target_git_sha"] == "feedface"


# ---------------------------------------------------------------------------
# _models (config loader mocked)
# ---------------------------------------------------------------------------

def test_models_extracts_roles(monkeypatch, tmp_path):
    role = types.SimpleNamespace(id="model-x", via="sdk")
    models_obj = types.SimpleNamespace(
        autoexclude=role,
        preprocess=None,
        threatmodel=types.SimpleNamespace(id="model-y", via="cli"),
    )
    fake_cfg = types.SimpleNamespace(models=models_obj)

    fake_config_mod = types.SimpleNamespace(load=lambda p: fake_cfg)
    # `manifest._models` does `from vvaharness import config`, which resolves
    # to the `config` attribute already bound on the package object once any
    # prior test has imported the real module. Patching only sys.modules is
    # therefore insufficient when the suite runs together; patch the package
    # attribute (auto-reverted by monkeypatch) so the import sees the fake.
    monkeypatch.setattr(__import__("vvaharness"), "config", fake_config_mod,
                        raising=False)
    monkeypatch.setitem(__import__("sys").modules, "vvaharness.config",
                        fake_config_mod)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["autoexclude"] == {"id": "model-x", "via": "sdk"}
    assert roles["threatmodel"] == {"id": "model-y", "via": "cli"}
    # None roles are skipped entirely.
    assert "preprocess" not in roles


def test_models_via_defaults_to_cli(monkeypatch, tmp_path):
    # A role object lacking a `via` attribute should default to "cli".
    class RoleNoVia:
        id = "only-id"

    models_obj = types.SimpleNamespace(deepdive=RoleNoVia())
    # Ensure other role names are absent -> getattr returns None.
    fake_cfg = types.SimpleNamespace(models=models_obj)
    fake_config_mod = types.SimpleNamespace(load=lambda p: fake_cfg)
    monkeypatch.setattr(__import__("vvaharness"), "config", fake_config_mod,
                        raising=False)
    monkeypatch.setitem(__import__("sys").modules, "vvaharness.config",
                        fake_config_mod)

    roles = manifest._models(tmp_path / "cfg.yaml")
    assert roles["deepdive"] == {"id": "only-id", "via": "cli"}


def test_models_load_failure_returns_empty(monkeypatch, tmp_path, capsys):
    def boom(p):
        raise RuntimeError("bad config")

    fake_config_mod = types.SimpleNamespace(load=boom)
    monkeypatch.setattr(__import__("vvaharness"), "config", fake_config_mod,
                        raising=False)
    monkeypatch.setitem(__import__("sys").modules, "vvaharness.config",
                        fake_config_mod)

    assert manifest._models(tmp_path / "cfg.yaml") == {}
    assert "could not load model roles" in capsys.readouterr().err
