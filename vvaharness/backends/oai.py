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
OpenAI backend. Third `via:` option alongside cli/sdk — same public surface:

    prompt(user_prompt, *, model, system_prompt=None, max_tokens=None,
           temperature=None, ...) -> str
    agentic(user_prompt, *, model, system_prompt=None, allowed_tools=None,
            cwd, max_turns=None, ...) -> str   # OpenAI function-calling tool
                                               # loop over local Read/Glob/Grep

Routing: set `via: openai` on a model role in config.yaml, e.g.

    deepdive: {id: gpt-4o, via: openai}

Auth:  OPENAI_API_KEY env var, or cfg.openai.api_key → configure().
URL:   defaults to https://api.openai.com/v1; override with cfg.openai.base_url
       to point at an Azure/OpenAI-compatible gateway.

Notes:
  - Uses the Chat Completions endpoint (widest model coverage) Streams so 64k-token responses don't trip HTTP timeouts.
  - Newer reasoning models (o-series, gpt-5+) reject `temperature` and the
    legacy `max_tokens` param. Both are handled by retry-and-drop, same
    pattern as backends/sdk.py.
  - Token accounting is normalised to the Anthropic field names so
    util/tokens.py sees one unified total across all three backends.
"""
from __future__ import annotations
import json
import os
import re
import sys
import threading
import time

from vvaharness.util.tokens import TOKENS
from vvaharness.backends import localtools as _localtools
from vvaharness.backends._tls import coerce_verify
from vvaharness.report.redact import redact

try:
    import openai
except ImportError:
    openai = None  # type: ignore


_REDACT_RX = re.compile(r"(sk-[A-Za-z0-9_-]{6})[A-Za-z0-9_-]+")
# Match a human-readable block reason in a corporate-proxy / DLP intercept
# page (vendor-neutral): a `reason=` query/form param, or text inside a
# <span>/<div> whose class name contains "rsn"/"reason".
_PROXY_REASON_RX = re.compile(
    r'(?:class="[^"]*\brsn\b[^"]*">\s*|class="[^"]*\breason\b[^"]*">\s*|reason=)'
    r'([^<&\n]{1,200})', re.I)


def _summarise_status_error(e) -> str:
    """Collapse a proxy/DLP HTML block page into one actionable line.

    The raw error/proxy body can contain secrets (a reflected Authorization
    header, an upstream `Set-Cookie`, an `sk-` key echoed in a debug trace).
    Scrub `sk-` keys and `Authorization`/cookie/token-ish lines, then cap the
    length before this string is embedded into a RuntimeError that gets
    logged."""
    body = ""
    resp = getattr(e, "response", None)
    if resp is not None:
        try:
            body = resp.text
        except Exception:
            body = ""
    body = body or str(getattr(e, "message", "") or e)
    low = body.lower()
    if "dlp" in low or "<html" in low:
        m = _PROXY_REASON_RX.search(body)
        reason = _scrub_secrets((m.group(1).strip() if m else "policy block"))
        return (f"blocked by corporate proxy/DLP — {reason}. "
                f"Request an exception or point openai.base_url at an "
                f"internal gateway; ")
    return redact(_scrub_secrets(body))[:300]


# Bearer tokens / api keys / cookies that a proxy or upstream may reflect back
# in an error body. Redact before logging.
_SECRET_LINE_RX = re.compile(
    r"(?im)^(.*?\b(authorization|api[-_ ]?key|x-api-key|cookie|set-cookie|"
    r"token|secret|bearer)\b\s*[:=]\s*).+$")
_BEARER_RX = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]+")


def _scrub_secrets(text: str) -> str:
    if not text:
        return text
    text = _REDACT_RX.sub(r"\1***", text)          # sk-XXXXXX… → sk-XXXXXX***
    text = _BEARER_RX.sub(r"\1***", text)          # Bearer <tok> → Bearer ***
    text = _SECRET_LINE_RX.sub(r"\1***", text)     # Header: <val> → Header: ***
    return text


def _cause_chain(e: Exception) -> str:
    parts, c = [], e.__cause__
    while c is not None:
        parts.append(f"{type(c).__name__}: {c}")
        c = c.__cause__
    detail = " <- ".join(parts) or "no underlying cause reported"
    return _REDACT_RX.sub(r"\1***", detail)


# ─────────────────────────────────────────────────────────────────────────────
# Lazy, thread-safe singleton client (s4 runs in a ThreadPoolExecutor).
# ─────────────────────────────────────────────────────────────────────────────

_client = None
_client_lock = threading.Lock()
_cfg: dict = {"api_key": None, "base_url": None, "verify_ssl": True,
              "ca_cert": None, "organization": None}


def configure(*, api_key: str | None = None, base_url: str | None = None,
              verify_ssl: bool | str | None = None,
              ca_cert: str | None = None,
              organization: str | None = None,
              no_proxy: str | None = None) -> None:
    """Called once from the orchestrator before any OpenAI step runs. Optional —
    falls back to OPENAI_API_KEY / https://api.openai.com/v1 if never called."""
    global _client
    with _client_lock:
        if api_key:
            _cfg["api_key"] = api_key
        if base_url:
            _cfg["base_url"] = base_url
        if verify_ssl is not None:
            _cfg["verify_ssl"] = coerce_verify(verify_ssl)
        if ca_cert:
            _cfg["ca_cert"] = ca_cert
        if organization:
            _cfg["organization"] = organization
        if no_proxy:
            os.environ["NO_PROXY"] = no_proxy
            os.environ["no_proxy"] = no_proxy
        _client = None


def _get_client():
    global _client
    if openai is None:
        raise RuntimeError(
            "The `openai` package is not installed but a model role is "
            "configured with `via: openai`. Run: pip install openai"
        )
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            kw: dict = {"max_retries": 4}
            key = _cfg["api_key"] or os.environ.get("OPENAI_API_KEY")
            if key:
                # Env vars sourced from files often carry a trailing
                # newline; httpx then rejects the Authorization header outright
                # and the SDK reports it as a bare "Connection error."
                kw["api_key"] = key.strip()
            # `or`-chain (not os.environ.get(key, default)): a present-but-empty
            # OPENAI_BASE_URL (e.g. the blank `OPENAI_BASE_URL=` shipped in
            # .env.example) is falsy and must fall back to the default endpoint,
            # not be passed through as an empty base_url (which the HTTP client
            # rejects as "missing protocol"). Mirrors how the sdk backend and
            # api_key handling already treat a blank value as "not configured".
            kw["base_url"] = (_cfg["base_url"]
                              or os.environ.get("OPENAI_BASE_URL")
                              or "https://api.openai.com/v1")
            if _cfg["organization"]:
                kw["organization"] = _cfg["organization"]
            ca = _cfg["ca_cert"]
            if ca and not os.path.exists(ca):
                print(f"WARN [openai]: ca_cert '{ca}' not found — falling back "
                      f"to verify_ssl={_cfg['verify_ssl']!r}", file=sys.stderr)
                ca = None
            verify = ca or _cfg["verify_ssl"]
            if verify is not True:
                if verify is False:
                    # TLS verification is OFF. Suppress urllib3's per-request
                    # InsecureRequestWarning spam, but NEVER do so silently:
                    # emit one loud, unmissable warning naming the endpoint so
                    # an operator can't disable cert/hostname checks unknowingly
                    # (mirrors backends/claude_cli.py). ca_cert is the secure
                    # way to trust a private-CA gateway.
                    import warnings, urllib3
                    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                    print(f"WARN [openai]: TLS verification DISABLED (verify_ssl=false) "
                          f"for base_url={kw['base_url']} — prompts, source snippets, "
                          f"outputs and the auth header are interceptable by an active "
                          f"MITM. Set openai.ca_cert to a CA bundle to verify a "
                          f"private-CA gateway instead.", file=sys.stderr)
                kw["http_client"] = openai.DefaultHttpxClient(verify=verify)
            _client = openai.OpenAI(**kw)
    return _client


# ─────────────────────────────────────────────────────────────────────────────
# prompt() — single-shot, no tools. Same return contract as cli/sdk.prompt().
# ─────────────────────────────────────────────────────────────────────────────

_NO_TEMP_MODELS: set[str] = set()
_USE_LEGACY_MAXTOK: set[str] = set()

# Transient HTTP statuses worth retrying with backoff.
_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504, 529})


def _is_transient_status(e) -> bool:
    """True for a retryable OpenAI error — a 429/5xx HTTP status."""
    return getattr(e, "status_code", None) in _RETRYABLE_STATUS


def prompt(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
    thinking_budget: int | None = None,   # ignored — OpenAI has no equivalent knob here
    betas: list[str] | None = None,        # ignored
    json_schema: dict | None = None,
    output_format: str = "text",
    cwd: str | None = None,
    max_budget_usd: float | None = None,
    timeout: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    max_tok = max_tokens or 16000

    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    kw: dict = {
        "model": model,
        "messages": messages,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    # Newer models (gpt-5+, o-series) only accept max_completion_tokens.
    if model in _USE_LEGACY_MAXTOK:
        kw["max_tokens"] = max_tok
    else:
        kw["max_completion_tokens"] = max_tok
    if temperature is not None and model not in _NO_TEMP_MODELS:
        kw["temperature"] = temperature
    if json_schema or output_format == "json":
        # Force JSON-object mode so GPT can't return prose / string arrays.
        # Steps that expect a structured object (s4 deepdive, s3 decompose, …)
        # pass output_format="json" without needing a full json_schema.
        kw["response_format"] = {"type": "json_object"}

    print(f"    [openai] prompt -> {model}{f' [{tag}]' if tag else ''} "
          f"({len(user_prompt)} chars, max_tokens={max_tok}"
          f"{f', T={temperature}' if 'temperature' in kw else ''}"
          f"{', json' if 'response_format' in kw else ''})",
          file=sys.stderr)

    # Honor a per-step wall-clock timeout if the caller supplied one (parity
    # with the CLI/SDK backends, which enforce it). Applied per-request via
    # with_options(); None falls back to the SDK default.
    req_client = client.with_options(timeout=float(timeout)) if timeout else client

    attempts, retry_wait = 3, 60
    text = None # guard against the all-attempts-continue path: if
    usage = None  # every iteration drops a different rejected param via
                  # `continue`, the loop can exit with text/usage never bound.
    # `attempts` is read live each iteration (not a pre-materialized range), so
    # a param-drop on the final attempt can grant the cleaned request one more
    # send. Bounded: each param-drop pops/swaps its param, so a branch fires at
    # most once.
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            stream = req_client.chat.completions.create(**kw)
            parts: list[str] = []
            usage = None
            for ev in stream:
                if ev.choices:
                    delta = ev.choices[0].delta
                    if delta and delta.content:
                        parts.append(delta.content)
                if getattr(ev, "usage", None):
                    usage = ev.usage
            text = "".join(parts)
            break
        except openai.BadRequestError as e:
            body = str(e).lower()
            # Each parameter-drop branch must guarantee a subsequent real send;
            # otherwise three distinct rejections across the three attempts
            # leave the loop with text/usage unbound (was a NameError).
            dropped = False
            if "temperature" in body and "temperature" in kw:
                _NO_TEMP_MODELS.add(model)
                print(f"    [openai] {model} rejected `temperature` — "
                      f"retrying without it", file=sys.stderr)
                kw.pop("temperature", None)
                dropped = True
            elif "max_completion_tokens" in kw and "max_completion_tokens" in body:
                _USE_LEGACY_MAXTOK.add(model)
                kw["max_tokens"] = kw.pop("max_completion_tokens")
                print(f"    [openai] {model} rejected `max_completion_tokens` — "
                      f"retrying with legacy `max_tokens`", file=sys.stderr)
                dropped = True
            elif "max_tokens" in kw and "max_completion_tokens" in body:
                kw["max_completion_tokens"] = kw.pop("max_tokens")
                print(f"    [openai] {model} requires `max_completion_tokens` — "
                      f"retrying", file=sys.stderr)
                dropped = True
            if dropped:
                # Grant the cleaned request one more send, capped so a server
                # that keeps 400-ing (e.g. an unexpected param ping-pong) can't
                # extend the loop without bound.
                if attempt == attempts and attempts < 6:
                    attempts += 1
                continue
            raise RuntimeError(
                f"OpenAI call failed (status={e.status_code}, model={model}): {e}"
            ) from e
        except openai.APIStatusError as e:
            if _is_transient_status(e) and attempt < attempts:
                print(f"    [openai] transient {e.status_code} (attempt "
                      f"{attempt}/{attempts}, model={model}); retrying in "
                      f"{retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"OpenAI call failed (status={e.status_code}, model={model}): "
                f"{_summarise_status_error(e)}"
            ) from e
        except openai.APIConnectionError as e:
            detail = _cause_chain(e)
            if attempt < attempts:
                print(f"    [openai] connection error (attempt {attempt}/{attempts}): "
                      f"{detail} — retrying in {retry_wait}s", file=sys.stderr)
                time.sleep(retry_wait)
                continue
            raise RuntimeError(
                f"OpenAI connection error after {attempts} attempts "
                f"(model={model}): {e}\n"
                f"  cause: {detail}\n"
                f"  hint: CERTIFICATE_VERIFY_FAILED → set openai.ca_cert in "
                f"config.yaml; 'Illegal header value' → OPENAI_API_KEY has "
                f"trailing whitespace; otherwise check HTTPS_PROXY / "
                f"OPENAI_BASE_URL."
            ) from e

    if text is None:
        # All attempts ended in a parameter-drop `continue` without a real
        # send (each iteration stripped a different rejected param). Fail
        # loudly instead of raising an opaque NameError on `text`/`usage`.
        raise RuntimeError(
            f"OpenAI call to {model} exhausted all retries without a "
            f"successful response (every attempt hit a parameter-drop retry). "
            f"Final request kwargs keys: {sorted(kw)}."
        )

    if usage is not None:
        u = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)
        cached = 0
        ptd = u.get("prompt_tokens_details") or {}
        if isinstance(ptd, dict):
            cached = ptd.get("cached_tokens", 0) or 0
        norm = {
            "input_tokens": (u.get("prompt_tokens", 0) or 0) - cached,
            "output_tokens": u.get("completion_tokens", 0) or 0,
            "cache_read_input_tokens": cached,
        }
        TOKENS.add(norm)
        print(f"    [openai] usage: in={u.get('prompt_tokens', 0)} "
              f"(cached={cached}) out={u.get('completion_tokens', 0)}",
              file=sys.stderr)
    else:
        TOKENS.add(None)

    return text.strip()


# ─────────────────────────────────────────────────────────────────────────────
# agentic() — OpenAI function-calling loop with local Read/Glob/Grep.
# ─────────────────────────────────────────────────────────────────────────────
#
# Mirrors cli.agentic()'s signature so backends/llm.py can dispatch verify (s6)
# and preprocess (s1) here when their role is `via: openai`. Tools are
# executed locally by backends/localtools.py and are jailed to `cwd` — the
# model cannot read outside the scanned repo.
#
# Bash is NOT supported. If a role requests it (s1 with default config),
# this raises immediately so the misconfiguration is obvious rather than
# silently degrading.

_MAX_TURNS = 25          # default tool-loop cap; override per-role via the
                         # step's `max_turns` config (e.g. step1.max_turns)
_AGENTIC_MAX_TOK = 16000


def _record_usage(usage) -> None:
    if usage is None:
        TOKENS.add(None)
        return
    u = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)
    cached = 0
    ptd = u.get("prompt_tokens_details") or {}
    if isinstance(ptd, dict):
        cached = ptd.get("cached_tokens", 0) or 0
    TOKENS.add({
        "input_tokens": (u.get("prompt_tokens", 0) or 0) - cached,
        "output_tokens": u.get("completion_tokens", 0) or 0,
        "cache_read_input_tokens": cached,
    })


# Per-tool-result cap kept in the agentic message history (~12K tokens). A
# single Read of a large / minified file would otherwise accumulate across
# turns and blow past the model's input limit, losing the whole verification.
_TOOL_RESULT_CAP = 48000
_CTX_OVERFLOW_RX = re.compile(
    r"context.?length|context length|exceed.*(?:token|limit)|too long", re.I)


def _cap_tool_result(result: str) -> str:
    if not result or len(result) <= _TOOL_RESULT_CAP:
        return result
    extra = len(result) - _TOOL_RESULT_CAP
    return (result[:_TOOL_RESULT_CAP]
            + f"\n\n…[truncated {extra} chars to fit context — re-read a "
              f"specific line range with Read offset/limit if you need more]")


_EVICTED_MARK = "[evicted to fit context]"


def _shrink_history(messages: list[dict]) -> bool:
    """Evict the OLDEST not-yet-evicted oversized tool result (replace with a
    short stub) to claw back context after an overflow. Returns True if it
    shrank something, False once every oversized tool result has been evicted —
    so repeated calls ADVANCE through all large reads instead of re-picking the
    first one, and the caller stops cleanly when there is nothing left to free."""
    for m in messages:
        c = m.get("content")
        if (m.get("role") == "tool" and isinstance(c, str) and len(c) > 1200
                and not c.endswith(_EVICTED_MARK)):
            m["content"] = c[:800] + "\n…" + _EVICTED_MARK
            return True
    return False


def agentic(
    user_prompt: str,
    *,
    model: str,
    system_prompt: str | None = None,
    allowed_tools: list[str] | None = None,
    cwd: str,
    max_budget_usd: float | None = None,
    permission_mode: str = "auto",  # accepted for parity; unused
    max_turns: int | None = None,
    tag: str | None = None,
) -> str:
    client = _get_client()
    turns_cap = int(max_turns) if max_turns else _MAX_TURNS
    allowed = list(allowed_tools or ["Read", "Glob", "Grep"])
    ok_tools, missing = _localtools.supported(allowed)
    if missing:
        raise NotImplementedError(
            f"via:openai agentic() does not implement tools {missing}. "
            f"Supported: {sorted(ok_tools)}. Keep this role on `via: cli` "
            f"or drop the unsupported tool from allowed_tools."
        )
    tools = _localtools.schemas_for(ok_tools)

    messages: list[dict] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})

    print(f"    [openai] agentic -> {model}{f' [{tag}]' if tag else ''} "
          f"(tools={ok_tools}, cwd={cwd})", file=sys.stderr)

    base_kw: dict = {"model": model, "tools": tools}
    if model in _USE_LEGACY_MAXTOK:
        base_kw["max_tokens"] = _AGENTIC_MAX_TOK
    else:
        base_kw["max_completion_tokens"] = _AGENTIC_MAX_TOK

    final_text = ""
    tool_calls_total = 0
    for turn in range(1, turns_cap + 1):
        resp = None
        shrinks = 0
        transients = 0
        while resp is None:
            try:
                resp = client.chat.completions.create(messages=messages, **base_kw)
            except openai.BadRequestError as e:
                low = str(e).lower()
                if "max_completion_tokens" in base_kw and "max_completion_tokens" in low:
                    _USE_LEGACY_MAXTOK.add(model)
                    base_kw["max_tokens"] = base_kw.pop("max_completion_tokens")
                    continue
                # Context-window overflow: accumulated tool outputs no longer
                # fit. Claw back space by evicting the oldest oversized tool
                # result and retry, rather than dropping the whole verification.
                if (_CTX_OVERFLOW_RX.search(low) and shrinks < 16
                        and _shrink_history(messages)):
                    shrinks += 1
                    print(f"      [openai] context overflow (turn {turn}); "
                          f"evicted oldest tool output [{shrinks}], retrying",
                          file=sys.stderr)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic call failed (model={model}, turn={turn}): {e}"
                ) from e
            except openai.APIStatusError as e:
                if _is_transient_status(e) and transients < 4:
                    transients += 1
                    wait = min(60, 10 * transients)
                    print(f"      [openai] transient {e.status_code} (turn "
                          f"{turn}, retry {transients}/4); waiting {wait}s",
                          file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic call failed (status={e.status_code}, "
                    f"model={model}, turn={turn}): {_summarise_status_error(e)}"
                ) from e
            except openai.APIConnectionError as e:
                if transients < 4:
                    transients += 1
                    wait = min(60, 10 * transients)
                    print(f"      [openai] agentic connection error (turn {turn}, "
                          f"retry {transients}/4); waiting {wait}s", file=sys.stderr)
                    time.sleep(wait)
                    continue
                raise RuntimeError(
                    f"OpenAI agentic connection error (model={model}, turn={turn}): "
                    f"{e}\n  cause: {_cause_chain(e)}"
                ) from e

        _record_usage(getattr(resp, "usage", None))
        msg = resp.choices[0].message
        calls = getattr(msg, "tool_calls", None) or []

        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": [tc.model_dump() for tc in calls] if calls else None,
        })

        if not calls:
            final_text = (msg.content or "").strip()
            print(f"    [openai] agentic done in {turn} turn(s), "
                  f"{tool_calls_total} tool call(s)", file=sys.stderr)
            return final_text

        for tc in calls:
            tool_calls_total += 1
            name = tc.function.name
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            result = _localtools.execute(name, args, cwd=cwd)
            print(f"      [openai] tool {name}({_summ(args)}) -> "
                  f"{len(result)} chars", file=sys.stderr)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": _cap_tool_result(result),
            })

    print(f"    [openai] WARN: agentic hit max_turns={turns_cap} without a "
          f"final answer (model={model})", file=sys.stderr)
    messages.append({
        "role": "user",
        "content": "Tool budget exhausted. Reply now with your final answer "
                   "based on what you have read so far; do not call tools.",
    })
    try:
        resp = client.chat.completions.create(
            messages=messages, model=model,
            **{k: v for k, v in base_kw.items()
               if k != "tools" and k != "model"})
    except openai.APIStatusError as e:
        raise RuntimeError(
            f"OpenAI agentic forced-final failed (status={e.status_code}, "
            f"model={model}): {_summarise_status_error(e)}"
        ) from e
    except openai.APIConnectionError as e:
        raise RuntimeError(
            f"OpenAI agentic forced-final connection error (model={model}): "
            f"{e}\n  cause: {_cause_chain(e)}"
        ) from e
    _record_usage(getattr(resp, "usage", None))
    return (resp.choices[0].message.content or "").strip()


def _summ(args: dict) -> str:
    parts = []
    for k in ("path", "pattern", "glob"):
        v = args.get(k)
        if v:
            s = str(v)
            parts.append(f"{k}={s[:60]}{'…' if len(s) > 60 else ''}")
    return ", ".join(parts) or "…"
