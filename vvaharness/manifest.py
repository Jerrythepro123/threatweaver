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

"""Run-level scan manifest (vvaharness).

Captures tool version, active model roles, config hash, target git SHA, and
timing for each run, written to ./run_manifest.json. Per-stage token/dollar
costs live inside the pipeline (ScanMetrics) and are a follow-up wiring step.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# Flag names whose VALUE is a likely secret — matched case-insensitively as a
# substring of the flag token, so --git-token / --anthropic-api-key /
# --db-password all hit. ("key" alone is intentionally excluded so --keep-clones
# etc. don't false-match.)
_SECRET_FLAG_RX = re.compile(
    r"(?i)(token|password|passwd|pwd|secret|api[_-]?key|access[_-]?key"
    r"|client[_-]?secret|auth|credential|bearer|private[_-]?key)")


def _scrub_argv(argv: list[str]) -> list[str]:
    """Redact secret-bearing values from a captured argv before it persists to
    run_manifest.json (defense-in-depth — no shipped flag takes a secret, but a
    manifest can outlive the process and land in shared logs).

    Two passes:
      1. The value after a secret-like flag — both ``--token VALUE`` (next token)
         and the inline ``--token=VALUE`` form — is replaced with ``***``.
      2. ``redact_tree()`` over the result masks secret-SHAPED tokens (URL
         userinfo, JWTs, AWS/GitHub keys, PANs/SSNs) regardless of flag name, so
         e.g. an inline-credential URL passed as any argument is scrubbed too.
    """
    out: list[str] = []
    i, n = 0, len(argv)
    while i < n:
        tok = argv[i]
        if tok.startswith("-") and "=" in tok:                 # --flag=VALUE
            flag, _eq, val = tok.partition("=")
            if val and _SECRET_FLAG_RX.search(flag):
                out.append(f"{flag}=***")
                i += 1
                continue
        if (tok.startswith("-") and _SECRET_FLAG_RX.search(tok)  # --flag VALUE
                and i + 1 < n and not argv[i + 1].startswith("-")):
            out.append(tok)
            out.append("***")
            i += 2
            continue
        out.append(tok)
        i += 1
    # Shape-based second pass — catches secret-looking values regardless of flag.
    from vvaharness.report.redact import redact_tree
    return redact_tree(out)


def _git_sha(args: list[str]) -> str | None:
    repo = None
    for i, a in enumerate(args):
        if a == "--repo" and i + 1 < len(args):
            repo = args[i + 1]
        elif a.startswith("--repo="):
            repo = a.split("=", 1)[1]
    if not repo:
        return None
    # Treat --repo as data, not git options. This runs in manifest.capture()
    # BEFORE the orchestrator validates args.repo, so normalize+validate the path
    # here and run git with cwd= rather than the -C flag — the value is then
    # never in git's option position. (`git -C <v>` already takes <v> as a
    # literal path, so leading-dash option-injection does not reproduce; this is
    # defensive hardening of an otherwise-unvalidated sink, not a live exploit.)
    try:
        repo_dir = Path(repo).resolve()
    except (OSError, ValueError):
        return None
    if not repo_dir.is_dir():
        return None
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_dir),
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or None
    except Exception:
        return None


def _models(cfg_path: Path) -> dict:
    try:
        from vvaharness import config as config_mod
        cfg = config_mod.load(cfg_path)
        roles = {}
        for name in ("autoexclude", "preprocess", "threatmodel", "decompose",
                     "deepdive", "verify", "dedup", "chain"):
            r = getattr(cfg.models, name, None)
            if r is not None:
                roles[name] = {"id": getattr(r, "id", str(r)),
                               "via": getattr(r, "via", "cli")}
        return roles
    except Exception as e:
        print(f"  [manifest] could not load model roles from {cfg_path}: {e}",
              file=sys.stderr)
        return {}


def _config_sha256(cfg_path: Path) -> str | None:
    if not cfg_path.exists():
        return None
    try:
        return hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    except OSError as e:
        print(f"  [manifest] could not hash config {cfg_path}: {e}",
              file=sys.stderr)
        return None


@contextlib.contextmanager
def capture(cfg_path: Path, args: list[str], out: Path | None = None):
    cfg_path = Path(cfg_path)
    from vvaharness import __version__
    m: dict = {
        "tool": "vvaharness",
        "version": __version__,
        "started": datetime.now(timezone.utc).isoformat(),
        "argv": _scrub_argv(args),
        "config_profile": str(cfg_path),
        "config_sha256": _config_sha256(cfg_path),
        # A config.local.yaml sibling silently overrides the chosen profile;
        # hash it too so the manifest records the *effective* configuration
        # (None when no overlay is present).
        "config_local_sha256": _config_sha256(cfg_path.with_name("config.local.yaml")),
        "models": _models(cfg_path),
        "target_git_sha": _git_sha(args),
        "per_stage_cost": None,
        "exit_code": None,
    }
    t0 = time.time()
    try:
        yield m
    finally:
        # Only persist a manifest when a scan actually ran. The caller sets
        # exit_code after orchestrator.main() returns; if argparse rejected the
        # args, printed --help, or otherwise raised SystemExit before the scan
        # began, exit_code stays None and we write nothing — no junk manifest
        # for a help screen or a usage error.
        #
        # NB: guard with `if`, never `return`, inside this finally — a return
        # here would suppress an in-flight exception (e.g. argparse's
        # SystemExit) propagating through the `with`, which is exactly the case
        # we must let through.
        if m.get("exit_code") is not None:
            m["ended"] = datetime.now(timezone.utc).isoformat()
            m["duration_sec"] = round(time.time() - t0, 1)
            dest = out or (Path.cwd() / "run_manifest.json")
            try:
                dest.write_text(json.dumps(m, indent=2), encoding="utf-8")
                print(f"  [manifest] wrote {dest}", file=sys.stderr)
            except OSError as e:
                print(f"  [manifest] WARNING: failed to write run manifest "
                      f"{dest}: {e}", file=sys.stderr)
