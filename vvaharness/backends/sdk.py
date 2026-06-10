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
Anthropic SDK backend. Mirrors the public surface of backends/claude_cli.py:

    prompt(user_prompt, *, model, system_prompt=None, max_tokens=None,
           temperature=None, ...) -> str
    agentic(user_prompt, *, model, system_prompt=None, allowed_tools=None,
            cwd, max_turns=None, ...) -> str

The dispatcher (backends/llm.py) decides which backend to call per role.

Auth:  ANTHROPIC_SDK_API_KEY env var, or override via configure(api_key=...,
       base_url=...) called once from the orchestrator at startup. A separate
       env var name is used so the SDK backend can target a different
       gateway/key than the `claude` CLI backend (which reads the standard
       ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN per its native precedence).

Notes:
  - Uses streaming + .get_final_message() so we can request large max_tokens
    (s3/s4/s8 ask for 64k) without hitting the SDK's non-streaming HTTP timeout.
  - Prompt-caches the system prompt block. s4 fires the same system prompt
    N×runs×chunks; cache reads are ~10% of input cost.
  - SDK auto-retries 429/5xx (max_retries=4); we don't need our own loop.
"""
from __future__ import annotations
import os
import re
import sys
import threading
import time

from vvaharness.util.tokens import TOKENS
from vvaharness.backends import localtools as _localtools
from vvaharness.backends._tls import coerce_verify
from vvaharness.report.redact import redact

# Lazy import: the orchestrator and every step pull backends.llm → backends.sdk at
# import time. If `anthropic` isn't installed but no role uses via:sdk,
# the run should still work. Only fail when an SDK call is actually made.
try:
    import anthropic
except ImportError:
    anthropic = None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# Lazy, thread-safe singleton client (s4/s6 run in ThreadPoolExecutor).
# ─────────────────────────────────────────────────────────────────────────────

_client = None
_client_lock = threading.Lock()
_cfg: dict = {"api_key": None, "base_url": None, "verify_ssl": True,
              "ca_cert": None, "client_cert": None,
              # When True, _get_client() may fall back to the shared
              # ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN if no SDK-specific key
              # is set. The orchestrator only enables this when via:sdk is the
              # SOLE backend, so when sdk coexists with via:cli the SDK never
              # silently borrows the CLI's gateway token. Defaults off.
              "allow_api_key_fallback": False}


def configure(*, api_key: str | None = None, base_url: str | None = None,
              verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              client_cert: str | tuple | None = None,
              no_proxy: str | None = None,
              allow_api_key_fallback: bool | None = None) -> None:
    """Called once from the orchestrator before any SDK step runs. Optional —
    falls back to ANTHROPIC_SDK_API_KEY / default endpoint if never called.

    verify_ssl:  True (default) / False to disable TLS verification.
    ca_cert:     path to a CA bundle (PEM) used to verify the gateway's
                 server certificate. Takes precedence over verify_ssl.
    client_cert: path to a client cert for mTLS, or (cert, key) tuple.
    no_proxy:    comma-separated host list to bypass HTTP(S)_PROXY for.
    allow_api_key_fallback: enable the shared ANTHROPIC_API_KEY/AUTH_TOKEN
                 fallback (set by the orchestrator only when sdk is the sole
                 backend)."""
    global _client
    with _client_lock:
        if api_key:
            _cfg["api_key"] = api_key
        if base_url:
            _cfg["base_url"] = base_url
        if allow_api_key_fallback is not None:
            _cfg["allow_api_key_fallback"] = bool(allow_api_key_fallback)
        if verify_ssl is not None:
            _cfg["verify_ssl"] = coerce_verify(verify_ssl)
        if ca_cert:
            _cfg["ca_cert"] = ca_cert
        if client_cert:
            _cfg["client_cert"] = client_cert
        if no_proxy:
            # httpx and requests both honour NO_PROXY via trust_env; export
            # both casings so it sticks regardless of which lib reads it.
            import os
            os.environ["NO_PROXY"] = no_proxy
            os.environ["no_proxy"] = no_proxy
        _client = None  # force rebuild on next call


def _get_client():
    global _client
    if anthropic is None:
        raise RuntimeError(
            "The `anthropic` package is not installed but a model role is "
            "configured with `via: sdk`. Run: pip install anthropic"
        )
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            kw = {"max_retries": 4}
            # Dedicated env var so the SDK backend can use a different
            # gateway/key than the `claude` CLI backend (which reads the
            # standard ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN).
            key = _cfg["api_key"] or os.environ.get("ANTHROPIC_SDK_API_KEY")
            if not key and _cfg.get("allow_api_key_fallback"):
                # Sole-sdk profile: mirror the preflight gate and accept the
                # shared ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN when no
                # SDK-specific key is set. Not enabled when sdk coexists with
                # via:cli, so sdk never silently borrows the CLI's token.
                key = (os.environ.get("ANTHROPIC_API_KEY")
                       or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
                if key:
                    print("    [sdk] no ANTHROPIC_SDK_API_KEY — falling back to "
                          "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN (sdk is the "
                          "only backend)", file=sys.stderr)
            if key:
                kw["api_key"] = key.strip()
            if _cfg["base_url"]:
                kw["base_url"] = _cfg["base_url"]
            # ca_cert (path) wins over verify_ssl (bool). httpx accepts a
            # str path for `verify=` and treats it as the trusted CA bundle.
            ca = _cfg["ca_cert"]
            if ca and not os.path.exists(ca):
                print(f"WARN [sdk]: ca_cert '{ca}' not found — falling back to "
                      f"verify_ssl={_cfg['verify_ssl']!r}", file=sys.stderr)
                ca = None
            verify = ca or _cfg["verify_ssl"]
            client_cert = _cfg["client_cert"]
            if isinstance(client_cert, str) and not os.path.exists(client_cert):
                print(f"WARN [sdk]: client_cert '{client_cert}' not found — "
                      f"disabling mTLS", file=sys.stderr)
                client_cert = None
            if verify is not True or client_cert:
                if verify is False:
                    import warnings
                    import urllib3
                    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                kw["http_client"] = anthropic.DefaultHttpxClient(verify=verify, cert=client_cert)
            _client = anthropic.Anthropic(**kw)
    return _client


# ─────────────────────────────────────────────────────────────────────────────
# prompt() — single-shot, no tools. Same return contract as cli.prompt().
# ─────────────────────────────────────────────────────────────────────────────

_NO_TEMP_MODELS: set[str] = set()
_NO_THINK_MODELS: set[str] = set()
_NO_TEMP_RX = re.compile(
    r"opus-4[-.]?([7-9]|\d{2,})|opus-[5-9]|sonnet-[5-9]|haiku-[5-9]",
    re.IGNORECASE,
)


def _supports_temperature(model: str) -> bool:
    if model in _NO_TEMP_MODELS:
        return False
    return not _NO_TEMP_RX.search(model)

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 529})
_SERVER_ERR_RX = re.compile(r"server_error|overloaded|service unavailable", re.I)


def _is_transient_sdk(e) -> bool:
    if getattr(e, "status_code", None) in _RETRYABLE_STATUS:
        return True
    return bool(_SERVER_ERR_RX.search(str(getattr(e, "message", e))))


def prompt(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    thinking_budget: int | None = None,
    betas: list[str] | None = None,
    # Accepted-but-ignored kwargs so the dispatcher can pass through whatever
    # the step originally sent to cli.prompt() without crashing here.
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    timeout: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    max_tok = max_tokens or 16000

    kw: dict = {
        "model": model,
        "max_tokens": max_tok,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    if betas:
        kw["extra_headers"] = {"anthropic-beta": ",".join(betas)}
    if thinking_budget and model not in _NO_THINK_MODELS:
        # Extended thinking. Current Anthropic models (Opus 4.7/4.8 and the
        # shipped default profile) REMOVED the fixed-budget form — sending
        # `thinking: {type: "enabled", budget_tokens: N}` returns a 400. The
        # supported on-mode is adaptive thinking, where the model decides how
        # much to think; the configured `thinking_budget` is treated as a
        # request to enable thinking (its magnitude no longer maps to a token
        # cap). Leave headroom in max_tokens for the actual response, and omit
        # temperature (rejected while thinking is on).
        if max_tok <= thinking_budget:
            max_tok = thinking_budget + 8000
            kw["max_tokens"] = max_tok
        kw["thinking"] = {"type": "adaptive"}
        temperature = None
    if temperature is not None:
        if _supports_temperature(model):
            kw["temperature"] = temperature
        elif model not in _NO_TEMP_MODELS:
            _NO_TEMP_MODELS.add(model)
            print(f"    [sdk] note: {model} does not accept `temperature`; "
                  f"dropping T={temperature} for this and subsequent calls",
                  file=sys.stderr)
    if system_prompt:
        # cache_control on the system block: s4 sends the same large system
        # prompt across many chunk×run combos → big cache-read savings.
        kw["system"] = [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]

    print(f"    [sdk] prompt -> {model}{f' [{tag}]' if tag else ''} "
          f"({len(user_prompt)} chars, "
          f"max_tokens={max_tok}"
          f"{f', T={temperature}' if 'temperature' in kw else ''}"
          f"{f', thinking={thinking_budget}' if 'thinking' in kw else ''})",
          file=sys.stderr)

    stream_client = client.with_options(timeout=float(timeout)) if timeout else client

    attempts, retry_wait = 3, 60
    msg = None
    # `attempts` is read live each iteration (not a pre-materialized range), so
    # the param-drop branches below can grant the cleaned request one more send
    # when a 400 lands on the final attempt. This is bounded: each param-drop
    # pops its param, so the branch can fire at most once per droppable param.
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            # Stream so large max_tokens (64k) doesn't trip the HTTP timeout;
            # we only need the final assembled message.
            with stream_client.messages.stream(**kw) as stream:
                msg = stream.get_final_message()
            break
        except anthropic.APIStatusError as e:
            body = str(getattr(e, "message", e))
            low = body.lower()
            if ("temperature" in kw and "temperature" in low
                    and e.status_code == 400):
                _NO_TEMP_MODELS.add(model)
                print(f"    [sdk] {model} rejected `temperature` — "
                      f"retrying without it", file=sys.stderr)
                kw.pop("temperature", None)
                if attempt == attempts and attempts < 6:
                    attempts += 1  # grant the cleaned request one more send (capped)
                continue
            if ("thinking" in kw and "thinking" in low
                    and ("not supported" in low or "unexpected" in low
                         or "adaptive" in low or e.status_code == 400)):
                _NO_THINK_MODELS.add(model)
                print(f"    [sdk] {model} rejected extended thinking "
                      f"({kw['thinking']}) — retrying without it",
                      file=sys.stderr)
                kw.pop("thinking", None)
                if attempt == attempts and attempts < 6:
                    attempts += 1  # grant the cleaned request one more send (capped)
                continue
            if _is_transient_sdk(e) and attempt < attempts:
                print(f"    [sdk] transient error (status={e.status_code}, "
                      f"attempt {attempt}/{attempts}, model={model}); retrying "
                      f"in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            # Scrub the provider response body before it lands in the
            # exception text (a gateway/proxy can reflect Authorization
            # headers, keys, or cookies in an error body). redact() is
            # idempotent, so a downstream errlog redact() pass is harmless.
            raise RuntimeError(
                f"Anthropic SDK call failed (status={e.status_code}, model={model}): "
                f"{redact(body)}"
            ) from e
        except anthropic.APIConnectionError as e:
            if attempt < attempts:
                print(f"    [sdk] connection error (attempt {attempt}/{attempts}): "
                      f"{e} — retrying in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            causes, c = [], e.__cause__
            while c is not None:
                causes.append(f"{type(c).__name__}: {c}")
                c = c.__cause__
            detail = " <- ".join(causes) or "no underlying cause reported"
            raise RuntimeError(
                f"Anthropic SDK connection error after {attempts} attempts "
                f"(model={model}): {redact(str(e))}\n"
                f"  cause: {redact(detail)}\n"
                f"  hint: this is a network/TLS/DNS/proxy failure, not an auth/model "
                f"error. On corp networks set SSL_CERT_FILE to your CA bundle, and "
                f"check HTTPS_PROXY / ANTHROPIC_SDK_BASE_URL."
            ) from e

    if msg is None:
        raise RuntimeError(
            f"Anthropic SDK call to {model} exhausted all retries without a "
            f"successful response (every attempt hit a parameter-drop retry). "
            f"Final request kwargs keys: {sorted(kw)}."
        )

    usage = msg.usage.model_dump() if msg.usage else None
    TOKENS.add(usage)
    if usage:
        _in = (usage.get("input_tokens", 0)
               + (usage.get("cache_creation_input_tokens") or 0)
               + (usage.get("cache_read_input_tokens") or 0))
        cr = usage.get("cache_read_input_tokens") or 0
        cw = usage.get("cache_creation_input_tokens") or 0
        out = usage.get("output_tokens", 0)
        cache_info = f" (cache_read={cr}, cache_write={cw})" if (cr or cw) else ""
        print(f"    [sdk] usage: in={_in}{cache_info} out={out}", file=sys.stderr)

    text = "".join(b.text for b in msg.content if b.type == "text")
    return text.strip()


# ─────────────────────────────────────────────────────────────────────────────
# agentic() — Anthropic tool-use loop over the local Read/Glob/Grep executors
# in backends/localtools.py. Mirrors backends/oai.py:agentic() so `via: sdk` is a
# drop-in for `via: cli`/`via: openai` on the preprocess and verify roles.
# Bash is NOT provided (no executor in _localtools); request it and you get a
# NotImplementedError telling you to switch the role to via:cli.
# ─────────────────────────────────────────────────────────────────────────────

_AGENTIC_MAX_TOK = 16000
_AGENTIC_MAX_TURNS = 40


def _assistant_blocks(content) -> list[dict]:
    """Serialize SDK response blocks back into the dict shape the Messages
    API expects on the next turn. Unknown block types are passed through via
    model_dump() so a newer SDK doesn't break the loop."""
    out: list[dict] = []
    for b in content:
        bt = getattr(b, "type", None)
        if bt == "text":
            out.append({"type": "text", "text": b.text})
        elif bt == "tool_use":
            out.append({"type": "tool_use", "id": b.id,
                        "name": b.name, "input": b.input})
        else:
            try:
                d = b.model_dump()
                d.pop("cache_control", None)  # never persist markers in history
                out.append(d)
            except Exception:  # noqa: BLE001
                pass
    return out


def _with_cache_marker(msgs: list[dict]) -> list[dict]:
    """Return a copy of `msgs` with every cache_control stripped and ONE
    ephemeral marker placed on the very last dict content block. The stored
    `messages` history never carries markers, so the request can never exceed
    the API's 4-block cap (system=1 + this=1 = 2) regardless of turn count
    or what model_dump() emitted for unknown block types."""
    out: list[dict] = []
    last_block: dict | None = None
    for m in msgs:
        c = m.get("content")
        if isinstance(c, list):
            cc: list = []
            for b in c:
                if isinstance(b, dict):
                    b = {k: v for k, v in b.items() if k != "cache_control"}
                    last_block = b
                cc.append(b)
            out.append({**m, "content": cc})
        else:
            out.append(m)
    if last_block is not None:
        last_block["cache_control"] = {"type": "ephemeral"}
    return out


def _summ(args: dict) -> str:
    s = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items())
    return s if len(s) <= 120 else s[:117] + "..."


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,   # accepted for parity; unused
    permission_mode: str = "auto",         # accepted for parity; unused
    max_turns: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    turns_cap = int(max_turns) if max_turns else _AGENTIC_MAX_TURNS
    allowed = list(allowed_tools or ["Read", "Glob", "Grep"])
    ok, missing = _localtools.supported(allowed)
    if missing:
        raise NotImplementedError(
            f"via:sdk agentic() has no executor for {missing}. "
            f"Supported: {sorted(ok)}. Drop the unsupported tool from "
            f"allowed_tools, or set this role to `via: cli` (which provides "
            f"Read/Glob/Grep/Bash natively)."
        )
    tools = _localtools.anthropic_schemas_for(ok)

    base_kw: dict = {"model": model, "max_tokens": _AGENTIC_MAX_TOK,
                     "tools": tools}
    if system_prompt:
        base_kw["system"] = [{
            "type": "text",
            "text": system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
    messages: list[dict] = [{"role": "user", "content": user_prompt}]

    tag_sfx = f" [{tag}]" if tag else ""
    print(f"    [sdk] agentic -> {model}{tag_sfx} (tools={ok}, "
          f"max_turns={turns_cap}, cwd={cwd})", file=sys.stderr)

    tool_calls_total = 0
    transients = 0
    for turn in range(1, turns_cap + 1):
        msg = None
        while msg is None:
            try:
                with client.messages.stream(messages=_with_cache_marker(messages),
                                             **base_kw) as stream:
                    msg = stream.get_final_message()
            except anthropic.APIStatusError as e:
                if _is_transient_sdk(e) and transients < 4:
                    transients += 1
                    print(f"    [sdk] agentic transient (status={e.status_code}, "
                          f"turn={turn}, retry {transients}/4); retrying",
                          file=sys.stderr)
                    time.sleep(min(60, 20 * transients))
                    continue
                raise RuntimeError(
                    f"Anthropic SDK agentic call failed (status={e.status_code}, "
                    f"model={model}, turn={turn}): {getattr(e, 'message', e)}"
                ) from e
            except anthropic.APIConnectionError as e:
                if transients < 4:
                    transients += 1
                    print(f"    [sdk] agentic connection error (turn={turn}, "
                          f"retry {transients}/4); retrying", file=sys.stderr)
                    time.sleep(min(60, 20 * transients))
                    continue
                causes, c = [], e.__cause__
                while c is not None:
                    causes.append(f"{type(c).__name__}: {c}")
                    c = c.__cause__
                raise RuntimeError(
                    f"Anthropic SDK agentic connection error (model={model}, "
                    f"turn={turn}): {e}\n  cause: "
                    f"{' <- '.join(causes) or 'no underlying cause reported'}"
                ) from e

        if msg.usage:
            TOKENS.add(msg.usage.model_dump())

        if msg.stop_reason != "tool_use":
            text = "".join(b.text for b in msg.content
                           if getattr(b, "type", None) == "text").strip()
            print(f"    [sdk] agentic done in {turn} turn(s), "
                  f"{tool_calls_total} tool call(s)", file=sys.stderr)
            return text

        messages.append({"role": "assistant",
                         "content": _assistant_blocks(msg.content)})
        results: list[dict] = []
        for b in msg.content:
            if getattr(b, "type", None) != "tool_use":
                continue
            tool_calls_total += 1
            out = _localtools.execute(b.name, dict(b.input or {}), cwd=cwd)
            print(f"      [sdk] tool {b.name}({_summ(b.input)}) -> "
                  f"{len(out)} chars", file=sys.stderr)
            results.append({"type": "tool_result",
                            "tool_use_id": b.id,
                            "content": out})
        # cache_control is applied at request time by _with_cache_marker();
        # the stored history stays marker-free so the 4-block cap can never
        # be exceeded.
        messages.append({"role": "user", "content": results})

    # Budget exhausted — force a final answer with tools disabled, same as
    # oai.agentic() does, so the caller still gets something parseable.
    print(f"    [sdk] WARN: agentic hit max_turns={turns_cap} without a "
          f"final answer (model={model}); forcing one", file=sys.stderr)
    messages.append({
        "role": "user",
        "content": "Tool budget exhausted. Reply now with your final answer "
                   "based on what you have read so far; do not call any tool.",
    })
    final_kw = {k: v for k, v in base_kw.items() if k != "tools"}
    final_kw["tool_choice"] = {"type": "none"}
    final_kw["tools"] = tools  # API requires tools when tool_choice is set
    try:
        with client.messages.stream(messages=_with_cache_marker(messages),
                                     **final_kw) as stream:
            msg = stream.get_final_message()
    except anthropic.APIStatusError as e:
        raise RuntimeError(
            f"Anthropic SDK agentic forced-final failed "
            f"(status={e.status_code}, model={model}): "
            f"{getattr(e, 'message', e)}"
        ) from e
    if msg.usage:
        TOKENS.add(msg.usage.model_dump())
    return "".join(b.text for b in msg.content
                   if getattr(b, "type", None) == "text").strip()
