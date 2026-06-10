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

"""Unit tests for vvaharness.backends.oai.

Offline & deterministic: no real network, no live OpenAI client. A fake
`openai` module is injected via monkeypatch where the client construction
path is exercised. The module singleton `oai._client` is reset by an
autouse fixture so test order never matters.
"""
import pytest

from vvaharness.backends import oai


@pytest.fixture(autouse=True)
def _reset_oai_state(monkeypatch):
    """Isolate the module-level client singleton and cfg between tests."""
    monkeypatch.setattr(oai, "_client", None, raising=False)
    # Restore cfg to its documented defaults so a configure() in one test
    # cannot leak into another.
    monkeypatch.setattr(
        oai,
        "_cfg",
        {"api_key": None, "base_url": None, "verify_ssl": True,
         "ca_cert": None, "organization": None},
        raising=False,
    )
    # Keep the suite from depending on a real key in the environment.
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    yield


# ─────────────────────────────────────────────────────────────────────────────
# _scrub_secrets
# ─────────────────────────────────────────────────────────────────────────────

def test_scrub_secrets_redacts_sk_key():
    out = oai._scrub_secrets("here is sk-ABCDEFghijklmnop1234567890 done")
    # First 6 chars of the suffix are kept (the regex group is sk- + 6 chars).
    assert "sk-ABCDEF***" in out
    assert "ghijklmnop1234567890" not in out


def test_scrub_secrets_redacts_bearer_token():
    out = oai._scrub_secrets("Header X: Bearer abc123.DEF-456_ghi value")
    assert "Bearer ***" in out
    assert "abc123.DEF-456_ghi" not in out


def test_scrub_secrets_redacts_authorization_line():
    out = oai._scrub_secrets("Authorization: sometoplevelsecretvalue")
    assert "Authorization: ***" in out
    assert "sometoplevelsecretvalue" not in out


def test_scrub_secrets_redacts_cookie_and_apikey_lines():
    text = "Set-Cookie: session=deadbeef\napi_key = supersecretkeyvalue"
    out = oai._scrub_secrets(text)
    assert "deadbeef" not in out
    assert "supersecretkeyvalue" not in out
    assert "Set-Cookie: ***" in out
    assert "api_key = ***" in out


def test_scrub_secrets_preserves_non_secret_text():
    text = "Connection failed: please check your network settings."
    assert oai._scrub_secrets(text) == text


def test_scrub_secrets_empty_input_returns_input():
    assert oai._scrub_secrets("") == ""
    assert oai._scrub_secrets(None) is None


# ─────────────────────────────────────────────────────────────────────────────
# _summarise_status_error
# ─────────────────────────────────────────────────────────────────────────────

class _FakeResp:
    def __init__(self, text):
        self.text = text


class _FakeStatusErr(Exception):
    def __init__(self, *, response=None, message=None):
        super().__init__(message or "")
        self.response = response
        self.message = message


def test_summarise_collapses_dlp_html_block():
    body = ('<html><body><div class="eu_co rsn">Not allowed to access this '
            'file type</div></body></html> zscaler proxy')
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "blocked by corporate proxy/DLP" in out
    assert "Not allowed to access this file type" in out
    # The 12 KB of HTML/CSS must be collapsed away.
    assert "<html>" not in out
    assert "<div" not in out


def test_summarise_dlp_with_no_reason_uses_policy_block():
    body = "<html><body>zscaler dlp generic page with no parseable reason</body></html>"
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "blocked by corporate proxy/DLP" in out
    assert "policy block" in out


def test_summarise_dlp_scrubs_secret_in_reason():
    body = ('<html>dlp <div class="eu_co rsn">reflected sk-ABCDEFsecrettail123456'
            '</div></html>')
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "secrettail123456" not in out
    assert "sk-ABCDEF***" in out


def test_summarise_non_html_body_scrubbed_and_length_capped():
    # A long, non-DLP error body: returned scrubbed and capped to 300 chars.
    body = "plain upstream error " * 100  # well over 300 chars
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert len(out) <= 300
    assert out == oai._scrub_secrets(body)[:300]


def test_summarise_falls_back_to_message_when_no_response():
    err = _FakeStatusErr(response=None, message="upstream 503 unavailable")
    out = oai._summarise_status_error(err)
    assert "upstream 503 unavailable" in out


def test_summarise_non_dlp_body_secrets_scrubbed():
    body = "trace dump Authorization: leakedtokenvalue123 end"
    err = _FakeStatusErr(response=_FakeResp(body))
    out = oai._summarise_status_error(err)
    assert "leakedtokenvalue123" not in out


# ─────────────────────────────────────────────────────────────────────────────
# configure()
# ─────────────────────────────────────────────────────────────────────────────

def test_configure_stores_cfg_and_resets_client(monkeypatch):
    # Pretend a client already exists; configure() must clear it.
    monkeypatch.setattr(oai, "_client", object(), raising=False)
    oai.configure(api_key="sk-ant-EXAMPLE", base_url="https://api.example.test/v1",
                  organization="org-example")
    assert oai._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert oai._cfg["base_url"] == "https://api.example.test/v1"
    assert oai._cfg["organization"] == "org-example"
    assert oai._client is None


def test_configure_verify_ssl_false_is_stored(monkeypatch):
    oai.configure(verify_ssl=False)
    assert oai._cfg["verify_ssl"] is False


def test_configure_none_values_do_not_overwrite(monkeypatch):
    oai.configure(api_key="sk-ant-EXAMPLE")
    # A subsequent call with no api_key must not wipe the stored key.
    oai.configure(base_url="https://api.example.test/v1")
    assert oai._cfg["api_key"] == "sk-ant-EXAMPLE"
    assert oai._cfg["base_url"] == "https://api.example.test/v1"


def test_configure_no_proxy_sets_env(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    oai.configure(no_proxy="example.com")
    import os
    assert os.environ["NO_PROXY"] == "example.com"
    assert os.environ["no_proxy"] == "example.com"


# ─────────────────────────────────────────────────────────────────────────────
# _get_client — DefaultHttpxClient only used when verify != True
# ─────────────────────────────────────────────────────────────────────────────

class _FakeOpenAIClient:
    def __init__(self, **kw):
        self.kw = kw


class _FakeHttpxClient:
    def __init__(self, *, verify):
        self.verify = verify


def _install_fake_openai(monkeypatch):
    import types
    fake = types.SimpleNamespace()
    fake.OpenAI = _FakeOpenAIClient
    fake.DefaultHttpxClient = _FakeHttpxClient
    monkeypatch.setattr(oai, "openai", fake, raising=False)
    return fake


def test_get_client_raises_when_openai_missing(monkeypatch):
    monkeypatch.setattr(oai, "openai", None, raising=False)
    with pytest.raises(RuntimeError, match="openai.*not installed|pip install openai"):
        oai._get_client()


def test_get_client_no_http_client_when_verify_true(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    # default _cfg verify_ssl is True
    client = oai._get_client()
    assert isinstance(client, _FakeOpenAIClient)
    # When verify is True the DefaultHttpxClient path must be skipped.
    assert "http_client" not in client.kw
    assert client.kw["api_key"] == "sk-ant-EXAMPLE"


def test_get_client_uses_httpx_client_when_verify_false(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    # Avoid importing real urllib3 warning machinery: patch warnings module use
    # by configuring verify_ssl=False which triggers the urllib3 import branch.
    oai.configure(verify_ssl=False)
    client = oai._get_client()
    assert "http_client" in client.kw
    assert isinstance(client.kw["http_client"], _FakeHttpxClient)
    assert client.kw["http_client"].verify is False


def test_get_client_uses_httpx_client_with_ca_cert(monkeypatch, tmp_path):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    ca = tmp_path / "ca.pem"
    ca.write_text("-----FAKE CERT-----")
    oai.configure(ca_cert=str(ca))
    client = oai._get_client()
    # verify resolves to the ca path (truthy string != True) -> httpx client used.
    assert "http_client" in client.kw
    assert client.kw["http_client"].verify == str(ca)


def test_get_client_missing_ca_cert_falls_back_to_verify_ssl(monkeypatch, capsys):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    oai.configure(ca_cert="/nonexistent/path/ca.pem")  # verify_ssl stays True
    client = oai._get_client()
    err = capsys.readouterr().err
    assert "not found" in err
    # ca dropped, verify_ssl True -> no http_client.
    assert "http_client" not in client.kw


def test_get_client_strips_whitespace_from_key(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE\n")
    client = oai._get_client()
    assert client.kw["api_key"] == "sk-ant-EXAMPLE"


def test_get_client_default_base_url(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.openai.com/v1"


def test_get_client_blank_base_url_env_falls_back_to_default(monkeypatch):
    # A present-but-empty OPENAI_BASE_URL (the blank `OPENAI_BASE_URL=` shipped
    # in .env.example) must fall back to the default endpoint, not be passed
    # through as "" — which the HTTP client rejects as "missing protocol".
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    monkeypatch.setenv("OPENAI_BASE_URL", "")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.openai.com/v1"


def test_get_client_configured_base_url(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    oai.configure(base_url="https://api.example.test/v1")
    client = oai._get_client()
    assert client.kw["base_url"] == "https://api.example.test/v1"


def test_get_client_is_cached_singleton(monkeypatch):
    _install_fake_openai(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-ant-EXAMPLE")
    first = oai._get_client()
    second = oai._get_client()
    assert first is second


# ─────────────────────────────────────────────────────────────────────────────
# prompt() — param-drop retry: a rejection on the LAST attempt still re-sends
# ─────────────────────────────────────────────────────────────────────────────

import types as _types


class _Delta:
    def __init__(self, content):
        self.content = content


class _Choice:
    def __init__(self, content):
        self.delta = _Delta(content)


class _Ev:
    def __init__(self, content=None, usage=None):
        self.choices = [_Choice(content)] if content is not None else []
        self.usage = usage


def test_prompt_param_drop_on_last_attempt_still_resends(monkeypatch):
    # Three distinct rejections across the three base attempts — the third
    # lands on the LAST attempt. With the live-bound retry loop the cleaned
    # request gets one more (capped) send and succeeds; the old fixed-range
    # loop would have hard-failed with "exhausted all retries".
    class BadRequestError(Exception):
        def __init__(self, msg, status_code=400):
            super().__init__(msg)
            self.status_code = status_code

    class APIStatusError(Exception):
        def __init__(self, msg="", status_code=400):
            super().__init__(msg)
            self.status_code = status_code
            self.message = msg

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _types.SimpleNamespace(
        BadRequestError=BadRequestError,
        APIStatusError=APIStatusError,
        APIConnectionError=APIConnectionError,
    ))
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            n = calls["n"]
            if n == 1 and "temperature" in kw:
                raise BadRequestError("unexpected parameter: temperature")
            if n == 2 and "max_completion_tokens" in kw:
                raise BadRequestError("max_completion_tokens is not supported")
            if n == 3 and "max_tokens" in kw:
                raise BadRequestError("this model requires max_completion_tokens")
            return [_Ev("done", usage=None)]

    class _Client:
        chat = _types.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())

    out = oai.prompt("hi", model="gpt-x", temperature=0.5)
    assert out == "done"
    # 3 rejections (incl. the last attempt) + 1 successful re-send.
    assert calls["n"] == 4

def test_cap_tool_result_truncates_oversized():
    out = oai._cap_tool_result("x" * 100000)
    assert len(out) < oai._TOOL_RESULT_CAP + 200
    assert "truncated" in out


def test_cap_tool_result_passthrough_small():
    assert oai._cap_tool_result("hello") == "hello"
    assert oai._cap_tool_result("") == ""


def test_shrink_history_evicts_oldest_large_tool_message():
    msgs = [
        {"role": "system", "content": "s"},
        {"role": "tool", "content": "y" * 5000},
        {"role": "tool", "content": "z" * 5000},
    ]
    assert oai._shrink_history(msgs) is True
    assert len(msgs[1]["content"]) < 2100
    assert len(msgs[2]["content"]) == 5000        # only the oldest is touched
    # Nothing left large enough -> returns False (loop then raises, no hang).
    small = [{"role": "tool", "content": "short"}]
    assert oai._shrink_history(small) is False


def test_shrink_history_advances_across_repeated_calls():
    # Repeated overflows must evict DIFFERENT messages (not re-pick the first),
    # then return False once all oversized tool results are evicted — otherwise
    # multi-large-read overflows never free enough context.
    msgs = [{"role": "tool", "content": "a" * 5000},
            {"role": "tool", "content": "b" * 5000}]
    assert oai._shrink_history(msgs) is True          # evicts #0
    assert oai._shrink_history(msgs) is True          # ADVANCES to #1
    assert msgs[0]["content"].endswith(oai._EVICTED_MARK)
    assert msgs[1]["content"].endswith(oai._EVICTED_MARK)
    assert oai._shrink_history(msgs) is False         # nothing left to evict


# ─────────────────────────────────────────────────────────────────────────────
# Transient-status classifier: retry 429/5xx, never terminal 4xx.
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("sc,expected", [
    (429, True), (500, True), (502, True), (503, True), (504, True), (529, True),
    (400, False), (401, False), (403, False), (404, False), (None, False),
])
def test_is_transient_status(sc, expected):
    import types
    assert oai._is_transient_status(types.SimpleNamespace(status_code=sc)) is expected


def test_prompt_retries_transient_500_then_succeeds(monkeypatch):
    import types as _t

    class APIStatusError(Exception):
        def __init__(self, status_code):
            super().__init__(f"status {status_code}")
            self.status_code = status_code

    class BadRequestError(APIStatusError):
        pass

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _t.SimpleNamespace(
        APIStatusError=APIStatusError, BadRequestError=BadRequestError,
        APIConnectionError=APIConnectionError))
    monkeypatch.setattr(oai, "_summarise_status_error", lambda e: str(e))
    monkeypatch.setattr(oai.time, "sleep", lambda s: None)   # no real backoff
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise APIStatusError(500)        # transient -> should retry
            return [_Ev("done", usage=None)]

    class _Client:
        chat = _t.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    out = oai.prompt("hi", model="gpt-x")
    assert out == "done"
    assert calls["n"] == 2                        # one 500 retry + success


def test_prompt_does_not_retry_terminal_404(monkeypatch):
    import types as _t

    class APIStatusError(Exception):
        def __init__(self, status_code):
            super().__init__(f"status {status_code}")
            self.status_code = status_code

    class BadRequestError(APIStatusError):
        pass

    class APIConnectionError(Exception):
        pass

    monkeypatch.setattr(oai, "openai", _t.SimpleNamespace(
        APIStatusError=APIStatusError, BadRequestError=BadRequestError,
        APIConnectionError=APIConnectionError))
    monkeypatch.setattr(oai, "_summarise_status_error", lambda e: str(e))
    monkeypatch.setattr(oai.time, "sleep", lambda s: None)
    monkeypatch.setattr(oai, "_NO_TEMP_MODELS", set())
    monkeypatch.setattr(oai, "_USE_LEGACY_MAXTOK", set())

    calls = {"n": 0}

    class _Completions:
        def create(self, **kw):
            calls["n"] += 1
            raise APIStatusError(404)            # terminal -> must NOT retry

    class _Client:
        chat = _t.SimpleNamespace(completions=_Completions())

        def with_options(self, **k):
            return self

    monkeypatch.setattr(oai, "_get_client", lambda: _Client())
    with pytest.raises(RuntimeError):
        oai.prompt("hi", model="gpt-x")
    assert calls["n"] == 1


# Provider message shapes (neutral placeholder model/limits) returned when the
# prompt exceeds the model's input window — the regex must match every variant
# so the agentic loop recovers instead of dropping work.
@pytest.mark.parametrize("msg", [
    "Input tokens exceed the configured limit of N tokens. Your messages resulted in M tokens.",
    "The context length of model test-model is N your query has M tokens in the prompts.",
    "Could not process the query for model test-model. Error: ... Input tokens exceed the configured limit of N tokens.",
    "context_length_exceeded",
])
def test_ctx_overflow_regex_matches_all_observed_shapes(msg):
    assert oai._CTX_OVERFLOW_RX.search(msg.lower())
