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


from __future__ import annotations

"""orchestrator.preflight — see package docstring."""
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from vvaharness.backends import sdk, oai, claude_cli as cli, codex
from vvaharness.backends.llm import resolve as resolve_model
from vvaharness.orchestrator.config_paths import _iter_model_roles, _resolve_against





def _mask(v: str | None) -> str:
    """Credential PRESENCE only — never emit key material, a prefix, or the
    length. Even a masked prefix/length leaks the token type and size into
    terminals, CI logs, and screen-shares; for a security tool we report binary
    presence and nothing more."""
    return "set ✓" if v else "<unset>"


def configure_backends(cfg, cfg_dir: Path) -> None:
    """Apply cfg.sdk / cfg.openai / cfg.cli (api_key, base_url, TLS/proxy) to the
    backend clients. Called by main() before scanning AND by `vvaharness doctor`
    so the live preflight probe in check_backends() hits the same
    gateway/credentials the real scan will use."""
    # Whether via:sdk is the SOLE backend across all roles — gates the SDK's
    # ANTHROPIC_API_KEY/AUTH_TOKEN fallback so it only kicks in when sdk isn't
    # sharing the run with via:cli (which uses those same vars for the `claude`
    # subprocess). Mirrors the same condition in check_backends().
    vias = {resolve_model(m)[1] for _, m in _iter_model_roles(cfg)}
    sdk_sole = vias == {"sdk"}
    sdk_cfg = getattr(cfg, "sdk", None)
    if sdk_cfg is not None:
        ca_cert = getattr(sdk_cfg, "ca_cert", None) or None
        client_cert = getattr(sdk_cfg, "client_cert", None) or None
        sdk.configure(
            api_key=getattr(sdk_cfg, "api_key", None),
            base_url=getattr(sdk_cfg, "base_url", None),
            verify_ssl=getattr(sdk_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_against(cfg_dir, client_cert)
                        if isinstance(client_cert, str) else client_cert,
            no_proxy=getattr(sdk_cfg, "no_proxy", None) or None,
            allow_api_key_fallback=sdk_sole,
        )
    oai_cfg = getattr(cfg, "openai", None)
    if oai_cfg is not None:
        ca_cert = getattr(oai_cfg, "ca_cert", None) or None
        oai.configure(
            api_key=getattr(oai_cfg, "api_key", None),
            base_url=getattr(oai_cfg, "base_url", None),
            verify_ssl=getattr(oai_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            organization=getattr(oai_cfg, "organization", None) or None,
            no_proxy=getattr(oai_cfg, "no_proxy", None) or None,
        )
    # via:cli roles shell out to the `claude` binary; push the same gateway
    # TLS/proxy settings into the subprocess env (auth/endpoint stay delegated
    # to the CLI). No-op when there is no cli: block.
    cli_cfg = getattr(cfg, "cli", None)
    if cli_cfg is not None:
        ca_cert = getattr(cli_cfg, "ca_cert", None) or None
        client_cert = getattr(cli_cfg, "client_cert", None) or None
        cli.configure(
            verify_ssl=getattr(cli_cfg, "verify_ssl", True),
            ca_cert=_resolve_against(cfg_dir, ca_cert) if ca_cert else None,
            client_cert=_resolve_against(cfg_dir, client_cert)
                        if isinstance(client_cert, str) else client_cert,
            no_proxy=getattr(cli_cfg, "no_proxy", None) or None,
            effort=getattr(cli_cfg, "effort", None) or None,
        )


    codex_cfg = getattr(cfg, "codex", None)
    if codex_cfg is not None:
        codex.configure(
            use_wsl=getattr(codex_cfg, "use_wsl", None),
            wsl_distro=getattr(codex_cfg, "wsl_distro", None) or None,
            binary=getattr(codex_cfg, "binary", None) or None,
            sandbox=getattr(codex_cfg, "sandbox", None) or None,
            approval_policy=getattr(codex_cfg, "approval_policy", None) or None,
            full_auto=getattr(codex_cfg, "full_auto", None),
            no_proxy=getattr(codex_cfg, "no_proxy", None) or None,
        )

def _reachable_despite_token_cap(err_msg: str) -> bool:
    """True when a probe error actually proves the model is reachable.

    A via:cli model that responded but whose reply exceeded the tiny preflight
    max_tokens cap surfaces as an error ("...response exceeded the N output
    token maximum..."), yet it demonstrably reached the model — so the probe
    should pass. (The sdk/openai backends truncate silently and never produce
    this; real scans use a large max_tokens and an over-long output there is a
    genuine result worth surfacing, which is why this is scoped to the probe.)"""
    low = (err_msg or "").lower()
    return "exceeded" in low and "output token" in low


def check_backends(cfg) -> bool:
    """
    Verify whichever backend(s) the config actually uses:
      - any role with via:cli  → `claude` must be on PATH
      - any role with via:sdk  → ANTHROPIC_SDK_API_KEY (or cfg.sdk.api_key) must be set
    """
    vias = {resolve_model(m)[1] for _, m in _iter_model_roles(cfg)}

    print(f"  [auth] active backends: {', '.join(sorted(vias)) or '(none)'}",
          file=sys.stderr)

    # CLI auth is validated by the live probe, not env-var presence: Claude Code
    # can authenticate from its normal login/keychain state.
    if "cli" in vias:
        print("  [auth] cli: delegated to configured CLI; live probe verifies login",
              file=sys.stderr)
        if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
            print("    NOTE: ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN is set and is "
                  "passed through to the `claude` CLI — it will use that "
                  "credential per its native precedence (API key → auth token "
                  "→ OAuth on disk).", file=sys.stderr)
        if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
            print("    CLAUDE_CODE_OAUTH_TOKEN present for unattended CLI auth ✓",
                  file=sys.stderr)

    # Presence dump only for credentials required by active API backends.
    # via:sdk uses the Anthropic Python SDK and requires SDK/API credentials.
    if "sdk" in vias:
        sdk_cfg = getattr(cfg, "sdk", None)
        print("  [auth] sdk credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        for label, val in (
            ("env  ANTHROPIC_SDK_API_KEY    ", os.environ.get("ANTHROPIC_SDK_API_KEY")),
            ("cfg  sdk.api_key              ", getattr(sdk_cfg, "api_key", None)),
            ("cfg  sdk.base_url             ", getattr(sdk_cfg, "base_url", None)),
        ):
            shown = (val or "<unset>") if "base_url" in label else _mask(val)
            print(f"    {label}= {shown}", file=sys.stderr)

    if "openai" in vias:
        openai_cfg = getattr(cfg, "openai", None)
        print("  [auth] openai credential sources (presence only — secrets never printed):",
              file=sys.stderr)
        for label, val in (
            ("env  OPENAI_API_KEY           ", os.environ.get("OPENAI_API_KEY")),
            ("cfg  openai.api_key           ", getattr(openai_cfg, "api_key", None)),
            ("cfg  openai.base_url          ", getattr(openai_cfg, "base_url", None)),
        ):
            shown = (val or "<unset>") if "base_url" in label else _mask(val)
            print(f"    {label}= {shown}", file=sys.stderr)

    ok = True
    if "cli" in vias:
        if not (shutil.which("claude") or shutil.which("claude.cmd")):
            print("ERROR: `claude` CLI not found on PATH (required by via:cli roles).",
                  file=sys.stderr)
            print("  Install: https://docs.anthropic.com/en/docs/claude-code",
                  file=sys.stderr)
            ok = False
        else:
            print("  [cli] claude found on PATH ✓", file=sys.stderr)

    if "sdk" in vias:
        key = getattr(getattr(cfg, "sdk", None), "api_key", None) \
              or os.environ.get("ANTHROPIC_SDK_API_KEY")
        # Sole-sdk profile: accept the shared ANTHROPIC_API_KEY/AUTH_TOKEN as a
        # fallback (matches sdk._get_client()). When sdk coexists with via:cli
        # we do NOT fall back, so each backend keeps its own credential and the
        # SDK never borrows the CLI's gateway token.
        sdk_sole = vias == {"sdk"}
        used_fallback = False
        if not key and sdk_sole:
            key = os.environ.get("ANTHROPIC_API_KEY") \
                  or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            used_fallback = bool(key)
        if not key:
            print("ERROR: ANTHROPIC_SDK_API_KEY not set (required by via:sdk roles).",
                  file=sys.stderr)
            print("  export ANTHROPIC_SDK_API_KEY=sk-ant-...", file=sys.stderr)
            if sdk_sole:
                print("  (or set ANTHROPIC_API_KEY — accepted as a fallback "
                      "because sdk is the only backend)", file=sys.stderr)
            ok = False
        elif used_fallback:
            print("  [sdk] ANTHROPIC_SDK_API_KEY unset — using "
                  "ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN fallback "
                  "(sdk is the only backend) ✓", file=sys.stderr)
        else:
            print("  [sdk] ANTHROPIC_SDK_API_KEY present ✓", file=sys.stderr)

    if "openai" in vias:
        key = getattr(getattr(cfg, "openai", None), "api_key", None) \
              or os.environ.get("OPENAI_API_KEY")
        if not key:
            print("ERROR: OPENAI_API_KEY not set (required by via:openai roles).",
                  file=sys.stderr)
            print("  export OPENAI_API_KEY=sk-...", file=sys.stderr)
            ok = False
        else:
            print("  [openai] OPENAI_API_KEY present ✓", file=sys.stderr)

    # ── Live connectivity probe ─────────────────────────────────────────
    # Skipped when credential checks already failed (nothing to probe).
    if not ok:
        print("  [probe] skipped — fix credential errors above first",
              file=sys.stderr)
        return ok
    # Catch the gateway gap (JWT-shaped ANTHROPIC_API_KEY with no
    # ANTHROPIC_BASE_URL) BEFORE the live probe — otherwise the request goes to
    # the public endpoint and (behind a corporate proxy) hangs to a 60s+ timeout
    # instead of giving the actionable fix. Fail fast with the exact remedy.
    from vvaharness.util.environment import _gateway_check, FAIL as _FAIL
    gw = _gateway_check()
    if gw.status == _FAIL:
        print(f"ERROR: {gw.detail}", file=sys.stderr)
        return False
    return probe_backends(cfg)


# The only two roles that drive the agentic() backend path (every other role
# uses prompt()): s1_preprocess.py and s6_verify.py. Kept here so the smoke
# probe exercises exactly the roles a real scan would.
_AGENTIC_ROLES = ("preprocess", "verify")


def _agentic_role_tools(cfg, role: str) -> list[str]:
    """The allowed_tools each agentic role passes to llm.agentic(), mirroring
    s1_preprocess.py and s6_verify.py exactly so the probe sends the same tool
    set the real scan will — the tool set is what makes a via:sdk/openai role
    raise NotImplementedError (those backends reject Bash/custom tools), so it
    is part of the probe's identity."""
    if role == "preprocess":
        at = getattr(getattr(cfg, "step1", None), "allowed_tools", None)
        return list(at) if isinstance(at, list) else ["Read", "Glob", "Grep", "Bash"]
    if role == "verify":
        at = getattr(getattr(cfg, "step6_verify", None), "allowed_tools", None)
        return list(at) if at else ["Read", "Glob", "Grep"]
    return []


def _probe_agentic_roles(cfg) -> bool:
    """Smoke-probe the agentic() backend path for the preprocess + verify roles.

    The prompt-based probe in probe_backends() only exercises prompt(); it
    never touches agentic(). That blind spot let two whole classes of failure
    reach mid-scan silently: (1) a via:cli stream-json argv regression
    (e.g. missing --verbose) that exits rc=1 before any output, and (2) a role
    moved to via:sdk/openai whose allowed_tools contain a tool those backends
    reject (NotImplementedError). A bounded 1-turn agentic call per unique
    (model, via, tool-set) surfaces both here instead.

    Failure is signalled ONLY by a raised exception: a 1-turn agent may
    legitimately end on a tool_use with no final text, so _parse_envelope
    returns "" — an empty reply is NOT a failure. Bounded by max_turns=1 and a
    tiny prompt; note that no wall-clock timeout is plumbed through
    llm.agentic (the cli backend caps itself at its own subprocess timeout)."""
    from vvaharness.backends.llm import agentic as _probe_agentic
    # (model_id, via, frozenset(tools)) -> (model_cfg_node, tools, [roles]).
    targets: dict[tuple, tuple] = {}
    for role, m in _iter_model_roles(cfg):
        if role not in _AGENTIC_ROLES:
            continue
        mid, via, _ = resolve_model(m)
        tools = _agentic_role_tools(cfg, role)
        _node, _t, roles = targets.setdefault(
            (mid, via, frozenset(tools)), (m, tools, []))
        roles.append(role)

    if not targets:
        return True

    print(f"  [probe] agentic backend path ({len(targets)} agentic "
          f"role/backend pair(s)):", file=sys.stderr)
    ok = True
    for (mid, via, _tk), (mcfg, tools, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        workdir = tempfile.mkdtemp(prefix="vva-preflight-")
        try:
            _probe_agentic("reply with the single word ok",
                           model=mcfg, system_prompt=None,
                           allowed_tools=list(tools), cwd=workdir,
                           max_turns=1, tag="preflight-agentic")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"agentic roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"agentic roles: {role_list}  (reachable; reply exceeded "
                      f"preflight token cap)", file=sys.stderr)
                continue
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED (agentic)  "
                  f"roles: {role_list}", file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
    return ok


def probe_backends(cfg) -> bool:
    """Live connectivity probe: one minimal request per unique (model_id, via)
    so bad credentials, an unreachable base_url, TLS/proxy misconfig, or an
    unknown model id fail HERE instead of mid-scan after tokens are spent
    (~4 output tokens each). Shared by check_backends() and `vvaharness doctor`
    so both exercise the same path the real scan will use. The prompt ping is
    followed by a bounded agentic smoke probe for the agentic-only roles."""
    from vvaharness.backends.llm import prompt as _probe
    # (model_id, via) -> (model_cfg_node, [roles]) — keep the original cfg
    # node so llm.resolve() (which reads .id/.via via getattr) works.
    targets: dict[tuple[str, str], tuple[object, list[str]]] = {}
    for role, m in _iter_model_roles(cfg):
        mid, via, _ = resolve_model(m)
        node, roles = targets.setdefault((mid, via), (m, []))
        roles.append(role)

    print(f"  [probe] live model connectivity ({len(targets)} unique "
          f"model/backend pair(s)):", file=sys.stderr)
    ok = True
    for (mid, via), (mcfg, roles) in targets.items():
        role_list = ",".join(roles)
        t0 = time.time()
        try:
            _probe("ping", model=mcfg,
                   max_tokens=4, timeout=120, tag="preflight")
            print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                  f"roles: {role_list}", file=sys.stderr)
        except Exception as e:
            if _reachable_despite_token_cap(str(e)):
                print(f"    ✓ [{via:<6}] {mid:<32} ({time.time()-t0:4.1f}s)  "
                      f"roles: {role_list}  (reachable; reply exceeded preflight "
                      f"token cap)", file=sys.stderr)
                continue
            # str(e) can be empty (some socket/timeout/SDK connection errors
            # carry no message) — splitlines() then yields [], so guard the
            # index to avoid an IndexError masking the real probe failure.
            lines = str(e).splitlines()
            msg = (lines[0][:160] if lines else "") or "(no message)"
            print(f"    ✗ [{via:<6}] {mid:<32} FAILED  roles: {role_list}",
                  file=sys.stderr)
            print(f"      {type(e).__name__}: {msg}", file=sys.stderr)
            ok = False

    # Exercise the agentic() path too (preprocess/verify only). Listed first so
    # it always runs even when a prompt probe already failed — more complete
    # diagnostics in one pass.
    ok = _probe_agentic_roles(cfg) and ok

    if ok:
        print("  [probe] all model backends reachable ✓", file=sys.stderr)
    else:
        print("ERROR: one or more model backends unreachable — fix before "
              "scanning, or pass --skip-preflight to bypass.", file=sys.stderr)
    return ok
