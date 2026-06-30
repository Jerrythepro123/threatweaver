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

"""Offline unit tests for vvaharness.backends.sdk.

No real network / no real anthropic client: messages.stream is mocked, the
`anthropic` module reference inside sdk is monkeypatched to a fake namespace.
All module-level singletons (sdk._client, sdk._cfg, the _NO_* sets) and the
shared TOKENS counter are reset by an autouse fixture so test order never
matters when the whole suite runs together.
"""
from __future__ import annotations

import types

import pytest

from vvaharness.backends import sdk
from vvaharness.util.tokens import TOKENS


# ─────────────────────────────────────────────────────────────────────────────
# Fakes
# ─────────────────────────────────────────────────────────────────────────────

class _FakeBlock:
    def __init__(self, type, text=None):
        self.type = type
        if text is not None:
            self.text = text


class _FakeUsage:
    def __init__(self, data):
        self._data = data

    def model_dump(self):
        return dict(self._data)


class _FakeMessage:
    def __init__(self, content, usage=None, stop_reason="end_turn"):
        self.content = content
        self.usage = usage
        self.stop_reason = stop_reason


class _FakeStream:
    """Context-manager mimicking client.messages.stream(...)."""

    def __init__(self, msg):
        self._msg = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return self._msg


class _FakeMessages:
    def __init__(self, recorder, msg):
        self._recorder = recorder
        self._msg = msg

    def stream(self, **kw):
        self._recorder.append(kw)
        return _FakeStream(self._msg)


class _FakeClient:
    def __init__(self, recorder, msg):
        self.messages = _FakeMessages(recorder, msg)

    def with_options(self, **kw):
        return self


def _install_client(monkeypatch, *, content=None, usage=None,
                    stop_reason="end_turn"):
    """Wire sdk._get_client() to return a fake client. Returns the list that
    captures the kwargs passed to messages.stream()."""
    recorder: list = []
    if content is None:
        content = [_FakeBlock("text", "hello world")]
    msg = _FakeMessage(content,
                       usage=_FakeUsage(usage) if usage is not None else None,
                       stop_reason=stop_reason)
    client = _FakeClient(recorder, msg)
    monkeypatch.setattr(sdk, "_get_client", lambda: client)
    return recorder


# ─────────────────────────────────────────────────────────────────────────────
# Global-state isolation (critical: full suite runs all files together)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # Reset module singletons / drift sets so order never matters.
    monkeypatch.setattr(sdk, "_client", None)
    monkeypatch.setattr(sdk, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(sdk, "_NO_THINK_MODELS", set())
    monkeypatch.setattr(sdk, "_cfg", {
        "api_key": None, "base_url": None, "verify_ssl": True,
        "ca_cert": None, "client_cert": None,
    })
    yield


# ─────────────────────────────────────────────────────────────────────────────
# _supports_temperature / _NO_TEMP_RX matrix
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("model", [
    "opus-4-6",
    "claude-opus-4-6",
    "sonnet-4-6",
    "haiku-4-5",
    "claude-sonnet-4-6-20990101",
])
def test_temperature_kept_models(model):
    assert sdk._supports_temperature(model) is True


@pytest.mark.parametrize("model", [
    "opus-4-7",
    "opus-4-8",
    "claude-opus-4-7",
    "claude-opus-4-8",
    "opus-5",
    "sonnet-5",
    "haiku-5",
    "claude-opus-5-0",
    "claude-sonnet-5-1",
])
def test_temperature_dropped_models(model):
    assert sdk._supports_temperature(model) is False


def test_temperature_runtime_blacklist_overrides_regex():
    # A model that the regex would normally allow becomes unsupported once
    # added to the runtime drift set.
    assert sdk._supports_temperature("opus-4-6") is True
    sdk._NO_TEMP_MODELS.add("opus-4-6")
    assert sdk._supports_temperature("opus-4-6") is False


# ─────────────────────────────────────────────────────────────────────────────
# configure()
# ─────────────────────────────────────────────────────────────────────────────

def test_configure_stores_cfg_and_clears_client(monkeypatch):
    monkeypatch.setattr(sdk, "_client", object())  # pretend a client exists
    sdk.configure(api_key="sk-ant-EXAMPLE", base_url="https://api.example.test",
                  verify_ssl=False, ca_cert="/tmp/ca.pem",
                  client_cert="/tmp/client.pem")
    assert sdk._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert sdk._cfg["base_url"] == "https://api.example.test"
    assert sdk._cfg["verify_ssl"] is False
    assert sdk._cfg["ca_cert"] == "/tmp/ca.pem"
    assert sdk._cfg["client_cert"] == "/tmp/client.pem"
    # configure() forces a rebuild on next _get_client().
    assert sdk._client is None


def test_configure_no_proxy_sets_env(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    sdk.configure(no_proxy="example.com,api.example.test")
    import os
    assert os.environ["NO_PROXY"] == "example.com,api.example.test"
    assert os.environ["no_proxy"] == "example.com,api.example.test"


def test_configure_partial_does_not_clobber_existing(monkeypatch):
    sdk._cfg["api_key"] = "sk-ant-EXAMPLE-keep"
    sdk.configure(base_url="https://api.example.test")
    # api_key untouched because None was passed for it.
    assert sdk._cfg["api_key"] == "sk-ant-EXAMPLE-keep"
    assert sdk._cfg["base_url"] == "https://api.example.test"


# ─────────────────────────────────────────────────────────────────────────────
# _get_client — http_client branch logic
# ─────────────────────────────────────────────────────────────────────────────

class _FakeAnthropicModule(types.SimpleNamespace):
    """Minimal stand-in for the `anthropic` module used by _get_client."""


def _make_fake_anthropic():
    captured = {"anthropic_kw": None, "httpx_kw": None}

    class FakeHttpxClient:
        def __init__(self, **kw):
            captured["httpx_kw"] = kw

    class FakeAnthropic:
        def __init__(self, **kw):
            captured["anthropic_kw"] = kw

    mod = _FakeAnthropicModule(
        DefaultHttpxClient=FakeHttpxClient,
        Anthropic=FakeAnthropic,
    )
    return mod, captured


def test_get_client_no_http_client_when_verify_true(monkeypatch):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    sdk._get_client()
    kw = captured["anthropic_kw"]
    assert "http_client" not in kw  # verify is True, no client_cert
    assert kw["api_key"] == "sk-ant-EXAMPLE"
    assert kw["max_retries"] == 4
    assert captured["httpx_kw"] is None


def test_get_client_builds_http_client_when_verify_false(monkeypatch, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    # urllib3 is imported inside the verify-False branch.
    monkeypatch.setitem(__import__("sys").modules, "urllib3",
                        types.SimpleNamespace(
                            exceptions=types.SimpleNamespace(
                                InsecureRequestWarning=Warning)))
    sdk._cfg["verify_ssl"] = False
    sdk._cfg["base_url"] = "https://gateway.internal"
    sdk._get_client()
    assert "http_client" in captured["anthropic_kw"]
    assert captured["httpx_kw"] == {"verify": False, "cert": None}
    # Disabling TLS must NEVER be silent: a loud, endpoint-naming warning fires.
    err = capsys.readouterr().err
    assert "TLS verification DISABLED" in err
    assert "gateway.internal" in err


def test_get_client_builds_http_client_for_client_cert(monkeypatch, tmp_path):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    cert = tmp_path / "client.pem"
    cert.write_text("dummy")
    sdk._cfg["client_cert"] = str(cert)
    sdk._get_client()
    assert "http_client" in captured["anthropic_kw"]
    # verify stays True (default), cert passed through.
    assert captured["httpx_kw"]["verify"] is True
    assert captured["httpx_kw"]["cert"] == str(cert)


def test_get_client_ca_cert_path_used_as_verify(monkeypatch, tmp_path, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    ca = tmp_path / "ca.pem"
    ca.write_text("dummy ca")
    sdk._cfg["ca_cert"] = str(ca)
    sdk._get_client()
    # ca_cert path wins over verify_ssl -> passed as verify=<path>.
    assert captured["httpx_kw"]["verify"] == str(ca)
    # Secure path (a CA bundle) must NOT emit the insecure-TLS warning.
    assert "TLS verification DISABLED" not in capsys.readouterr().err


def test_get_client_missing_ca_cert_falls_back(monkeypatch, capsys):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    sdk._cfg["ca_cert"] = "/nonexistent/ca.pem"
    sdk._get_client()
    # Falls back to verify_ssl=True -> no http_client built.
    assert "http_client" not in captured["anthropic_kw"]
    assert "not found" in capsys.readouterr().err


def test_get_client_raises_when_anthropic_missing(monkeypatch):
    monkeypatch.setattr(sdk, "anthropic", None)
    with pytest.raises(RuntimeError, match="anthropic"):
        sdk._get_client()


def test_get_client_caches_singleton(monkeypatch):
    mod, captured = _make_fake_anthropic()
    monkeypatch.setattr(sdk, "anthropic", mod)
    monkeypatch.setenv("ANTHROPIC_SDK_API_KEY", "sk-ant-EXAMPLE")
    c1 = sdk._get_client()
    c2 = sdk._get_client()
    assert c1 is c2


# ─────────────────────────────────────────────────────────────────────────────
# prompt() — needs anthropic.APIStatusError / APIConnectionError to exist for
# the except clauses to be importable; install a fake anthropic with those.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def _fake_anthropic_exc(monkeypatch):
    class APIStatusError(Exception):
        def __init__(self, message="", status_code=400):
            super().__init__(message)
            self.message = message
            self.status_code = status_code

    class APIConnectionError(Exception):
        pass

    mod = types.SimpleNamespace(
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    )
    monkeypatch.setattr(sdk, "anthropic", mod)
    return mod


def test_prompt_returns_stripped_text(monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch,
                          content=[_FakeBlock("text", "  answer  ")])
    out = sdk.prompt("hi", model="opus-4-6")
    assert out == "answer"
    # default max_tokens applied.
    assert rec[0]["max_tokens"] == 16000
    assert rec[0]["model"] == "opus-4-6"
    assert rec[0]["messages"] == [{"role": "user", "content": "hi"}]


def test_prompt_temperature_kept_for_supporting_model(monkeypatch,
                                                      _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", temperature=0.7)
    assert rec[0]["temperature"] == 0.7


def test_prompt_temperature_dropped_for_nontemp_model(monkeypatch, capsys,
                                                      _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-8", temperature=0.7)
    assert "temperature" not in rec[0]
    # model recorded in drift set so subsequent calls skip silently.
    assert "opus-4-8" in sdk._NO_TEMP_MODELS
    assert "does not accept" in capsys.readouterr().err


def test_prompt_thinking_budget_yields_adaptive_and_drops_temperature(
        monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", temperature=0.5, thinking_budget=10000)
    kw = rec[0]
    assert kw["thinking"] == {"type": "adaptive"}
    # temperature is dropped while thinking is on.
    assert "temperature" not in kw


def test_prompt_thinking_budget_bumps_max_tokens_for_headroom(
        monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    # max_tokens (5000) <= thinking_budget (10000) -> bumped to budget + 8000.
    sdk.prompt("hi", model="opus-4-6", max_tokens=5000, thinking_budget=10000)
    assert rec[0]["max_tokens"] == 18000


def test_prompt_thinking_skipped_for_no_think_model(monkeypatch,
                                                    _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk._NO_THINK_MODELS.add("opus-4-6")
    sdk.prompt("hi", model="opus-4-6", thinking_budget=10000, temperature=0.5)
    assert "thinking" not in rec[0]
    # temperature survives because thinking branch was skipped.
    assert rec[0]["temperature"] == 0.5


def test_prompt_system_prompt_cache_control(monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", system_prompt="you are helpful")
    sys_block = rec[0]["system"]
    assert sys_block == [{
        "type": "text",
        "text": "you are helpful",
        "cache_control": {"type": "ephemeral"},
    }]


def test_prompt_betas_set_header(monkeypatch, _fake_anthropic_exc):
    rec = _install_client(monkeypatch)
    sdk.prompt("hi", model="opus-4-6", betas=["beta-a", "beta-b"])
    assert rec[0]["extra_headers"] == {"anthropic-beta": "beta-a,beta-b"}


def test_prompt_usage_total_is_input_plus_caches(monkeypatch, capsys,
                                                 _fake_anthropic_exc):
    _install_client(monkeypatch, usage={
        "input_tokens": 100,
        "cache_creation_input_tokens": 30,
        "cache_read_input_tokens": 20,
        "output_tokens": 7,
    })
    sdk.prompt("hi", model="opus-4-6")
    # The printed "in=" reflects fresh + cache_create + cache_read = 150.
    assert "in=150" in capsys.readouterr().err
    # TOKENS headline prompt = fresh + cache_write (not cache_read) = 130.
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 130
    assert snap["completion"] == 7


def test_prompt_usage_none_still_counts_call(monkeypatch, _fake_anthropic_exc):
    _install_client(monkeypatch, usage=None)
    sdk.prompt("hi", model="opus-4-6")
    snap = TOKENS.snapshot()
    assert snap["calls"] == 1
    assert snap["calls_with_usage"] == 0


def test_prompt_concatenates_text_blocks_only(monkeypatch, _fake_anthropic_exc):
    _install_client(monkeypatch, content=[
        _FakeBlock("thinking", "internal"),  # has .text but type != text
        _FakeBlock("text", "part1 "),
        _FakeBlock("tool_use"),              # no .text attr; skipped by type
        _FakeBlock("text", "part2"),
    ])
    out = sdk.prompt("hi", model="opus-4-6")
    assert out == "part1 part2"


def test_prompt_recovers_after_temperature_rejection(monkeypatch,
                                                     _fake_anthropic_exc):
    # A 400 naming `temperature` drops the param and re-sends; the live-bound
    # retry loop must iterate to the cleaned send rather than abandoning it.
    exc = _fake_anthropic_exc
    calls = {"n": 0}

    class _Stream:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get_final_message(self):
            return _FakeMessage([_FakeBlock("text", "ok")], usage=None)

    class _Messages:
        def stream(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1 and "temperature" in kw:
                raise exc.APIStatusError("unexpected parameter: temperature",
                                         status_code=400)
            return _Stream()

    class _Client:
        messages = _Messages()

        def with_options(self, **k):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())
    out = sdk.prompt("hi", model="opus-4-6", temperature=0.7)
    assert out == "ok"
    assert calls["n"] == 2  # rejected once on `temperature`, re-sent without it
    assert "opus-4-6" in sdk._NO_TEMP_MODELS


# ─────────────────────────────────────────────────────────────────────────────
# Transient classifier: retry 429/5xx AND the mid-stream server_error that
# arrives as an APIStatusError with a 200 HTTP status (SDK built-in retry misses
# it); terminal 4xx (auth/model/param) are not retried.
# ─────────────────────────────────────────────────────────────────────────────

def test_is_transient_sdk_retries_5xx_and_midstream_server_error():
    NS = types.SimpleNamespace
    assert sdk._is_transient_sdk(NS(status_code=503, message="unavailable")) is True
    assert sdk._is_transient_sdk(NS(status_code=429, message="slow down")) is True
    assert sdk._is_transient_sdk(NS(status_code=529, message="overloaded")) is True
    # mid-stream error: HTTP 200 but an error body of type server_error/overloaded
    assert sdk._is_transient_sdk(
        NS(status_code=200, message="{'type': 'error', 'error': {'type': 'server_error'}}")) is True
    assert sdk._is_transient_sdk(NS(status_code=200, message="Overloaded")) is True


def test_is_transient_sdk_does_not_retry_terminal_4xx():
    NS = types.SimpleNamespace
    assert sdk._is_transient_sdk(NS(status_code=400, message="invalid model")) is False
    assert sdk._is_transient_sdk(NS(status_code=401, message="bad key")) is False
    assert sdk._is_transient_sdk(NS(status_code=404, message="no such model")) is False


def test_sdk_error_body_is_redacted_in_runtimeerror(monkeypatch):
    """A credential reflected in the provider error body must be scrubbed
    before it lands in the raised RuntimeError text."""
    fake_anthropic = types.SimpleNamespace(
        APIStatusError=type("APIStatusError", (Exception,), {}),
        APIConnectionError=type("APIConnectionError", (Exception,), {}),
    )
    monkeypatch.setattr(sdk, "anthropic", fake_anthropic)

    secret = "ghp_" + "a" * 36
    err = fake_anthropic.APIStatusError(f"rejected token={secret}")
    err.message = f"rejected token={secret}"
    err.status_code = 400

    class _Msgs:
        def stream(self, **kw):
            raise err

    class _Client:
        messages = _Msgs()

        def with_options(self, **kw):
            return self

    monkeypatch.setattr(sdk, "_get_client", lambda: _Client())

    with pytest.raises(RuntimeError) as ei:
        sdk.prompt("hi", model="opus-4-6")
    msg = str(ei.value)
    assert secret not in msg
    assert "[REDACTED" in msg
