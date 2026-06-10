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
Step 1 — Claude CLI explores the repo agentically and emits a ContextPackage.

The CLI already has Read, Glob, Grep, Bash tools built in — no custom tools
needed. We give it a system prompt, point it at the repo, and ask it to
produce a JSON ContextPackage.
"""
from __future__ import annotations
import configparser
import fnmatch
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

from vvaharness.models import ContextPackage, CVE, Control
from vvaharness.backends.llm import agentic
from vvaharness.util.json_extract import extract_json
from vvaharness.lang.hints import EXT_TO_LANG

# Deterministic repo walk — guarantees s3/s4 see every source file regardless
# of what the agentic exploration chose to look at.
_DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "target", "vendor", ".terraform",
    ".next", ".nuxt", "coverage", ".pytest_cache", ".mypy_cache",
    # test code — not part of the production attack surface
    # ("spec"/"specs" intentionally NOT here — collides with UI component
    #  folders; *.spec.* test FILES are caught by _DEFAULT_EXCLUDE_GLOBS)
    "test", "tests", "__tests__", "__test__", "e2e", "testdata",
    "fixtures", "__fixtures__", "mocks", "__mocks__", "stubs",
    # IaC / CI / container dirs (helm, docker, k8s, kubernetes, deploy,
    # deployment, .github, .gitlab, ci, ansible, terraform) are KEPT in
    # scope — the `iac` specialist in s3_decompose sweeps them for cloud /
    # supply-chain misconfigurations. Only `.terraform/` (provider state,
    # listed above) stays excluded. 
    # pipeline writes these INTO the target repo — never scan our own output
    "checkpoints", "security-scan",
}
_DEFAULT_EXCLUDE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz",
    ".tar", ".7z", ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib",
    ".bin", ".o", ".a", ".obj", ".pyc", ".pyo", ".pkl", ".lock", ".min.js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
}
# Glob patterns matched against the repo-relative posix path. Catches test
# files that live alongside production code and infra files at repo root.
_DEFAULT_EXCLUDE_GLOBS = (
    "**/test_*.py", "**/*_test.py", "**/conftest.py",
    "**/*_test.go", "**/*.test.js", "**/*.test.ts", "**/*.test.jsx", "**/*.test.tsx",
    "**/*.spec.js", "**/*.spec.ts", "**/*.spec.jsx", "**/*.spec.tsx",
    "**/*Test.java", "**/*Tests.java", "**/*IT.java",
    "**/*Test.cs", "**/*Tests.cs", "**/*Test.kt",
    # Dockerfile / Jenkinsfile / Makefile / *.tf / *.tfvars and Helm chart
    # YAML are KEPT in scope — the `iac` specialist hunts them. The repo
    # metadata block below stays excluded.
    # repo / tooling metadata — never attack surface
    "**/.gitignore", "**/.gitattributes", "**/.gitmodules", "**/.gitkeep",
    "**/.editorconfig", "**/.dockerignore", "**/.npmignore", "**/.eslintignore",
    "**/.prettierignore", "**/.mailmap", "**/CODEOWNERS", "**/.DS_Store",
    "**/LICENSE", "**/LICENSE.*", "**/NOTICE",
)


def _exclusion_sets(cfg) -> tuple[set[str], set[str], list[str]]:
    """Resolve (dirs, exts, globs) once — built-in defaults + config.yaml step1.* appends.
    Single source of truth shared by the deterministic walk, the agent prompt
    skip-list, and the post-agent JSON filter."""
    excl_dirs = {d.lower() for d in
                 _DEFAULT_EXCLUDE_DIRS | set(getattr(cfg.step1, "exclude_dirs", None) or [])}
    excl_exts = _DEFAULT_EXCLUDE_EXTS | set(getattr(cfg.step1, "exclude_exts", None) or [])
    excl_globs = list(_DEFAULT_EXCLUDE_GLOBS) + list(
        getattr(cfg.step1, "exclude_globs", None) or [])
    return excl_dirs, excl_exts, excl_globs


def glob_hit(rel: str, globs) -> str | None:
    """Return the first glob that excludes the repo-relative posix path `rel`,
    else None. Unlike a bare ``fnmatch``, a ``**/x`` pattern ALSO matches a
    repo-ROOT ``x``: ``fnmatch``'s ``**`` requires a slash, so root-level files
    (LICENSE, .gitignore, test_*.py) would otherwise escape the exclusion the
    patterns clearly intend. Shared by the deterministic walk and the survey so
    the two never diverge."""
    name = rel.rsplit("/", 1)[-1]
    for g in globs:
        if fnmatch.fnmatchcase(rel, g):
            return g
        if g.startswith("**/") and fnmatch.fnmatchcase(name, g[3:]):
            return g
    return None


def _norm_rel(repo_root: str, p: str) -> str:
    """Normalize an agent-emitted path to the same repo-relative posix form
    that _walk_repo produces, so set-membership checks work.

    Handles: backslashes, leading './', absolute paths (agent often emits the
    resolved cwd), and Windows case-insensitive drive/dir names. repo_root may
    itself be relative (batch mode passes e.g. 'scans-.../17745'), so we try
    both its literal and resolved forms as strip prefixes."""
    if not p:
        return p
    p = p.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    rel_root = str(Path(repo_root)).replace("\\", "/").rstrip("/") + "/"
    abs_root = str(Path(repo_root).resolve()).replace("\\", "/").rstrip("/") + "/"
    pl = p.lower()
    for r in (abs_root, rel_root):
        if pl.startswith(r.lower()):
            return p[len(r):]
    return p


def _walk_repo(repo_root: str, cfg) -> tuple[list[str], dict]:
    root = Path(repo_root)
    root_resolved = root.resolve()
    excl_dirs, excl_exts, excl_globs = _exclusion_sets(cfg)
    max_kb = getattr(cfg.step1, "max_file_kb", 1024)
    # Default-secure, but coverage-preserving: in-tree symlinks (common in
    # monorepos) are still scanned; only links whose target resolves OUTSIDE
    # the repo are dropped. Set step1.follow_symlinks: true to follow off-root
    # links too (not recommended for untrusted targets).
    follow_symlinks = bool(getattr(cfg.step1, "follow_symlinks", False))

    out: list[str] = []
    skipped_dirs: dict[str, int] = {}
    skipped_exts: dict[str, int] = {}
    skipped_globs: dict[str, int] = {}
    skipped_size: list[tuple[str, int]] = []
    skipped_symlinks: dict[str, int] = {}
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(root)).replace("\\", "/")
        # rglob + is_file() follow symbolic links, so a committed symlink whose
        # target resolves outside the repo would otherwise pull arbitrary host
        # file content (e.g. ~/.ssh/id_rsa) into the inventory and LLM prompts.
        # Reject those out-of-root links unless explicitly opted in.
        if not follow_symlinks and p.is_symlink():
            try:
                tgt = p.resolve(strict=False)
                escapes = not tgt.is_relative_to(root_resolved)
            except OSError:
                escapes = True
            if escapes:
                skipped_symlinks[rel] = skipped_symlinks.get(rel, 0) + 1
                continue
        rel_parts = rel.split("/")
        hit_dir = next((part for part in rel_parts[:-1]
                        if part.lower() in excl_dirs), None)
        if hit_dir:
            prefix = "/".join(rel_parts[:rel_parts.index(hit_dir) + 1])
            skipped_dirs[prefix] = skipped_dirs.get(prefix, 0) + 1
            continue
        name = p.name.lower()
        hit_ext = next((e for e in excl_exts
                        if p.suffix.lower() == e or name.endswith(e)), None)
        if hit_ext:
            skipped_exts[hit_ext] = skipped_exts.get(hit_ext, 0) + 1
            continue
        hit_glob = glob_hit(rel, excl_globs)
        if hit_glob:
            skipped_globs[hit_glob] = skipped_globs.get(hit_glob, 0) + 1
            continue
        try:
            sz = p.stat().st_size
            if sz > max_kb * 1024:
                skipped_size.append((rel, sz))
                continue
        except OSError:
            continue
        out.append(rel)

    excluded = {
        "dirs": skipped_dirs,
        "exts": skipped_exts,
        "globs": skipped_globs,
        "oversize": len(skipped_size),
        "oversize_files": sorted(skipped_size, key=lambda kv: -kv[1]),
        "symlinks": skipped_symlinks,
    }
    return sorted(out), excluded


# ─── Config-file structural dedup ────────────────────────────────────────────
# Collapses near-duplicate per-environment config files (e.g. 5,000 copies of
# service/<svc>/<env>/config.yml) to one representative per shape-cluster, so
# downstream steps don't burn tokens on identical-structure variants. A file
# is only ever dropped if (a) ≥ min_cluster_size siblings share its exact key
# structure AND (b) it passes a secret / insecure-value regex safety net.
# Anything unparseable, unique, or suspicious is kept.

_DEDUP_DEFAULTS = {
    "enabled": True,
    "exts": (".yml", ".yaml", ".json", ".toml", ".ini",
             ".properties", ".conf", ".cfg", ".env"),
    "min_cluster_size": 3,
    "keep_per_top_dir": True,
    "promote_on_secret_hit": True,
    "promote_on_insecure_value": True,
    "max_file_kb": 512,
}

# Layer-2 safety net — literal credential material that must never be
# silently dropped. Negative lookahead skips templated / encrypted refs
# ({{var}}, ${VAR}, CRYPT:…, ENC(…), <%= … %>, vault:…) and nested-key
# false positives (`auth-token:\n  timeout:` — value-looks-like-a-key).
_SECRET_RX = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|"
    r"auth[_-]?token|private[_-]?key|client[_-]?secret|credential)s?"
    r"[ \t]*[:=][ \t]*['\"]?"
    r"(?!CRYPT:|ENC\(|\{\{|\$\{|<%=|<%|vault:|secret:|file:|/)"
    r"(?![\w.-]+[ \t]*:)"
    r"[^\s'\",}{]{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bxox[baprs]-[0-9A-Za-z-]{10,}\b"
    r"|\bgh[pousr]_[0-9A-Za-z]{36,}\b"
    r"|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# Insecure *values* (not secrets) whose presence makes a config variant worth
# scanning even if its shape matches a safe sibling.
_INSECURE_RX = re.compile(
    r"(?i)\b(?:verify|verif(?:y|ication)[_-]?ssl|ssl[_-]?verify|"
    r"validate[_-]?cert\w*|tls[_-]?verify|check[_-]?hostname|"
    r"reject[_-]?unauthori[sz]ed)\b\s*[:=]\s*['\"]?(?:false|0|no|none|off)\b"
    r"|\binsecure\w*\s*[:=]\s*['\"]?(?:true|1|yes)\b"
    r"|\bInsecureSkipVerify\s*[:=]\s*true\b"
    r"|\b(?:auth|authentication|authn|security)\s*[:=]\s*['\"]?(?:none|disabled|off|false)\b"
    r"|\bdebug\s*[:=]\s*['\"]?(?:true|1|yes)\b"
    r"|\ballow[_-]?anonymous\s*[:=]\s*['\"]?(?:true|1|yes)\b"
)


def _flatten_keys(obj, prefix: str = "") -> list[str]:
    if isinstance(obj, dict):
        out: list[str] = []
        for k in obj:
            out.extend(_flatten_keys(obj[k], f"{prefix}.{k}" if prefix else str(k)))
        return out or [prefix]
    if isinstance(obj, list):
        out = []
        for it in obj:
            out.extend(_flatten_keys(it, f"{prefix}[]"))
        return out or [prefix]
    return [prefix]


_KV_LINE_RX = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]")
_YAML_KEY_RX = re.compile(r"^( *)(?:- +)?([\w.\-]+)\s*:")


def _shape_hash(text: str, ext: str) -> str | None:
    """Hash of the sorted key-path set (values stripped). None ⇒ keep file.
    YAML uses a fast line-based indent+key scan instead of full safe_load."""
    keys: list[str] = []
    try:
        if ext in (".yml", ".yaml"):
            stack: list[tuple[int, str]] = []
            for ln in text.splitlines():
                if not ln or ln.lstrip().startswith("#"):
                    continue
                m = _YAML_KEY_RX.match(ln)
                if not m:
                    continue
                indent, name = len(m.group(1)), m.group(2)
                while stack and stack[-1][0] >= indent:
                    stack.pop()
                stack.append((indent, name))
                keys.append(".".join(n for _, n in stack))
        elif ext == ".json":
            keys = _flatten_keys(json.loads(text))
        elif ext in (".ini", ".cfg", ".conf"):
            cp = configparser.ConfigParser(strict=False, allow_no_value=True)
            cp.read_string(text)
            for sec in cp.sections():
                for opt in cp.options(sec):
                    keys.append(f"{sec}.{opt}")
        else:
            for ln in text.splitlines():
                m = _KV_LINE_RX.match(ln)
                if m:
                    keys.append(m.group(1))
    except Exception:
        return None
    if not keys:
        return None
    return hashlib.sha1("\n".join(sorted(set(keys))).encode()).hexdigest()


def _suspicious_set(text: str, want_secret: bool, want_insecure: bool) -> set[str]:
    """Normalized set of suspicious-pattern hits — used to diff a candidate
    against its cluster representative so we only promote *new* signals."""
    out: set[str] = set()
    if want_secret:
        for m in _SECRET_RX.finditer(text):
            out.add("secret:" + re.sub(r"\s+", " ", m.group(0))[:80])
    if want_insecure:
        for m in _INSECURE_RX.finditer(text):
            out.add("insecure:" + re.sub(r"\s+", " ", m.group(0))[:80])
    return out


def _rep_score(rel: str, size: int) -> tuple:
    """Pick the most production-relevant variant as the cluster representative."""
    low = rel.lower()
    env = (0 if "/prod" in low else
           1 if any(e in low for e in ("/cert", "/stag", "/stg")) else
           2 if any(e in low for e in ("/perf", "/qa")) else
           3)
    return (env, -size, rel)


def _dedup_configs(files: list[str], repo_root: Path, cfg) -> tuple[list[str], dict]:
    dd = dict(_DEDUP_DEFAULTS)
    user = getattr(getattr(cfg, "step1", None), "config_dedup", None)
    if user is not None:
        raw = (user if isinstance(user, dict)
               else getattr(user, "_data", None) or vars(user))
        dd.update({k: v for k, v in raw.items() if v is not None})
    if not dd["enabled"]:
        return files, {"enabled": False}

    exts = {e.lower() for e in dd["exts"]}
    min_cluster = int(dd["min_cluster_size"])
    max_bytes = int(dd["max_file_kb"]) * 1024

    candidates: list[str] = []
    passthrough: list[str] = []
    for rel in files:
        if Path(rel).suffix.lower() in exts:
            candidates.append(rel)
        else:
            passthrough.append(rel)

    if len(candidates) < min_cluster:
        return files, {"enabled": True, "candidates": len(candidates),
                       "clusters": 0, "dropped": 0, "promoted": 0}

    want_sec = dd["promote_on_secret_hit"]
    want_ins = dd["promote_on_insecure_value"]

    # Pass 1 — read + shape-hash. Parallel because Windows file I/O (and AV
    # on-access scanning) dominates; threading gives ~6-8x here.
    def _load(rel: str):
        p = repo_root / rel
        try:
            sz = p.stat().st_size
            if sz > max_bytes:
                return rel, sz, None, None
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return rel, 0, None, None
        return rel, sz, _shape_hash(text, p.suffix.lower()), text

    clusters: dict[str, list[tuple[str, int]]] = defaultdict(list)
    texts: dict[str, str] = {}
    unclustered: list[str] = []
    from concurrent.futures import ThreadPoolExecutor
    workers = int(dd.get("io_workers", 16))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for rel, sz, h, text in ex.map(_load, candidates):
            if h is None:
                unclustered.append(rel)
            else:
                clusters[h].append((rel, sz))
                texts[rel] = text

    keep: list[str] = list(passthrough) + unclustered
    promoted: list[tuple[str, str]] = []
    dropped: list[str] = []
    cluster_report: list[dict] = []

    # Pass 2 — only large clusters need the (expensive) suspicious-set diff.
    for h, members in clusters.items():
        if len(members) < min_cluster:
            keep.extend(r for r, _ in members)
            continue
        members.sort(key=lambda m: _rep_score(m[0], m[1]))
        reps: dict[str, str] = {}
        if dd["keep_per_top_dir"]:
            for rel, _ in members:
                reps.setdefault(rel.split("/", 1)[0], rel)
        else:
            reps["*"] = members[0][0]
        rep_set = set(reps.values())
        rep_sus: set[str] = set()
        for r in rep_set:
            rep_sus |= _suspicious_set(texts[r], want_sec, want_ins)
        keep.extend(rep_set)

        c_dropped: list[str] = []
        for rel, _ in members:
            if rel in rep_set:
                continue
            sus = _suspicious_set(texts[rel], want_sec, want_ins)
            extra = sus - rep_sus
            if extra:
                keep.append(rel)
                promoted.append((rel, sorted(extra)[0]))
                rep_sus |= sus
            else:
                c_dropped.append(rel)
        dropped.extend(c_dropped)
        cluster_report.append({
            "shape": h[:12],
            "size": len(members),
            "reps": sorted(rep_set),
            "dropped": len(c_dropped),
            "sample": members[0][0],
        })
    texts.clear()

    cluster_report.sort(key=lambda c: -c["size"])
    report = {
        "enabled": True,
        "candidates": len(candidates),
        "unparseable_kept": len(unclustered),
        "clusters": len([c for c in cluster_report if c["size"] >= min_cluster]),
        "kept_reps": sum(len(c["reps"]) for c in cluster_report),
        "promoted": len(promoted),
        "promoted_files": promoted[:50],
        "dropped": len(dropped),
        "dropped_files": dropped,
        "top_clusters": cluster_report[:10],
    }

    if dropped:
        top = ", ".join(f"{c['sample']} x{c['size']}"
                        for c in cluster_report[:3])
        print(f"  [s1] config-dedup: {len(candidates)} config files -> "
              f"{report['clusters']} shape-clusters; "
              f"kept {report['kept_reps']} reps + {len(promoted)} promoted, "
              f"dropped {len(dropped)} near-duplicates", file=sys.stderr)
        print(f"  [s1]   largest: {top}", file=sys.stderr)
        if promoted:
            print(f"  [s1]   promoted (suspicious value not in rep): "
                  f"{', '.join(p for p, _ in promoted[:5])}"
                  + (f" ... +{len(promoted)-5} more" if len(promoted) > 5 else ""),
                  file=sys.stderr)
    return sorted(keep), report

# ─── Deterministic call-graph supplement ─────────────────────────────────────
# The agent's call_graph is LLM-guessed: sparse, unvalidated, bare function
# names. Taint chunks / neighbor context / connected-component grouping in
# s3/s4 all depend on it. This pass (a) drops hallucinated names, (b) fills
# missing edges by regex-scanning source for calls to known functions, and
# (c) records def-site file:line for every function it sees so downstream
# steps can locate intermediate hops.
#
# P5: nodes are FILE-QUALIFIED (`rel/path/File.java::method`) so polymorphic
# names like save()/process() don't collapse the whole repo into one BFS
# component or shadow real entry→sink paths in s3.

QSEP = "::"
MODULE_SCOPE = "<module>"


def q_join(file: str, name: str) -> str:
    return f"{file}{QSEP}{name}"


def q_split(qname: str) -> tuple[str, str]:
    if QSEP in qname:
        f, _, n = qname.rpartition(QSEP)
        return f, n
    return "", qname


def q_file(qname: str) -> str:
    return q_split(qname)[0]


def q_name(qname: str) -> str:
    return q_split(qname)[1]


def _resolve_callee_files(name: str, caller_file: str,
                          def_files: dict[str, set[str]],
                          max_targets: int) -> list[str]:
    """Pick ≤max_targets def-site files for bare `name` when called from
    `caller_file`. Same-file > unique > longest-common-dir-prefix."""
    cands = def_files.get(name)
    if not cands:
        return []
    if caller_file in cands:
        return [caller_file]
    if len(cands) == 1:
        return list(cands)
    cp = caller_file.split("/")
    def _score(f: str) -> int:
        n = 0
        for a, b in zip(cp, f.split("/")):
            if a == b:
                n += 1
            else:
                break
        return n
    return sorted(cands, key=_score, reverse=True)[:max_targets]


_DEF_RXS: tuple[re.Pattern, ...] = (
    re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\*?\s+(\w+)\s*\("),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*[(<]"),
    re.compile(r"^\s*fn\s+(\w+)"),
    re.compile(r"^\s*sub\s+(\w+)"),
    re.compile(
        r"^\s*(?:@\w+\s*)?"
        r"(?:(?:public|private|protected|internal|static|final|override|"
        r"virtual|abstract|async|synchronized|native|inline|extern)\s+)+"
        r"[\w<>\[\],.?*&\s]+?\b(\w+)\s*\("
    ),
    re.compile(r"^\s*(?:[\w*&:]+\s+){1,2}(\w+)\s*\([^;()]*\)\s*\{"),
    re.compile(r"^\s{2,}(?:async\s+|static\s+|get\s+|set\s+)?(\w+)\s*\([^;()]*\)\s*\{"),
)
_NOT_A_DEF = frozenset({
    "if", "for", "while", "switch", "catch", "return", "throw", "new", "else",
    "do", "try", "with", "using", "lock", "super", "this", "typeof", "delete",
    "sizeof", "instanceof", "synchronized", "yield", "await", "assert", "print",
})
_CALL_TOKEN_RX = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(")


def _scan_defs(lines: list[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for i, ln in enumerate(lines, 1):
        for rx in _DEF_RXS:
            m = rx.match(ln)
            if m and m.group(1) not in _NOT_A_DEF:
                out.append((i, m.group(1)))
                break
    return out


def _supplement_call_graph(data: dict, all_files: list[str],
                           repo_root: Path, cfg) -> None:
    s1 = getattr(cfg, "step1", None)
    do_supp = getattr(s1, "call_graph_supplement", True) if s1 else True
    do_validate = getattr(s1, "call_graph_validate", True) if s1 else True
    rounds = int(getattr(s1, "call_graph_rounds", 3)) if s1 else 3
    max_targets = int(getattr(s1, "call_graph_max_targets", 3)) if s1 else 3
    if not do_supp and not do_validate:
        return

    raw_cg: dict[str, set[str]] = defaultdict(set)
    for k, vs in (data.get("call_graph") or {}).items():
        if k:
            raw_cg[q_name(k)].update(q_name(v) for v in (vs or []) if v)

    seeds: set[str] = set()
    for ep in data.get("entry_points") or []:
        if ep.get("function"):
            seeds.add(ep["function"])
    for s in data.get("unsafe_sinks") or []:
        if s.get("function"):
            seeds.add(s["function"])
    seeds.update(raw_cg.keys())
    for vs in raw_cg.values():
        seeds.update(vs)
    seeds = {s for s in seeds if s and s not in _NOT_A_DEF and len(s) >= 3}

    src_files: list[tuple[str, list[str], list[tuple[int, str]]]] = []
    seen_call_tokens: set[str] = set()
    fn_locs: dict[str, set[str]] = defaultdict(set)
    def_files: dict[str, set[str]] = defaultdict(set)
    for rel in all_files:
        if Path(rel).suffix.lower() not in EXT_TO_LANG:
            continue
        p = repo_root / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        defs = _scan_defs(lines)
        for lineno, name in defs:
            fn_locs[name].add(f"{rel}:{lineno}")
            def_files[name].add(rel)
        for m in _CALL_TOKEN_RX.finditer(text):
            seen_call_tokens.add(m.group(1))
        src_files.append((rel, lines, defs))

    seen_any = seen_call_tokens | set(fn_locs)

    # ── Qualify + validate the agent-emitted graph ───────────────────────
    cg: dict[str, set[str]] = defaultdict(set)
    n_agent_edges = sum(len(v) for v in raw_cg.values())
    n_dropped = 0
    for caller, callees in raw_cg.items():
        if do_validate and seen_any and caller not in seen_any:
            n_dropped += len(callees)
            continue
        caller_sites = sorted(def_files.get(caller, ()))[:max_targets] or [""]
        for callee in callees:
            if do_validate and seen_any and callee not in seen_any:
                n_dropped += 1
                continue
            for cf in caller_sites:
                tgts = (_resolve_callee_files(callee, cf, def_files, max_targets)
                        if cf else sorted(def_files.get(callee, ()))[:max_targets])
                if not tgts:
                    if do_validate:
                        n_dropped += 1
                    else:
                        cg[q_join(cf, caller) if cf else caller].add(callee)
                    continue
                for tf in tgts:
                    cg[q_join(cf, caller) if cf else caller].add(q_join(tf, callee))

    # ── Supplement: regex-scan source, emit qualified edges ──────────────
    n_added = 0
    if do_supp and seeds:
        targets = (seeds & seen_any) if seen_any else set(seeds)
        known: set[str] = set(targets)
        for _ in range(max(1, rounds)):
            if not targets:
                break
            esc = sorted((re.escape(t) for t in targets), key=len, reverse=True)[:600]
            rx = re.compile(r"(?<!\w)(" + "|".join(esc) + r")\s*\(")
            new_targets: set[str] = set()
            for rel, lines, defs in src_files:
                cur = None
                di = 0
                for lineno, ln in enumerate(lines, 1):
                    while di < len(defs) and defs[di][0] <= lineno:
                        cur = defs[di][1]
                        di += 1
                    for m in rx.finditer(ln):
                        callee = m.group(1)
                        enclosing = cur if cur is not None else MODULE_SCOPE
                        if enclosing == callee:
                            continue
                        qcur = q_join(rel, enclosing)
                        for tf in _resolve_callee_files(callee, rel, def_files,
                                                        max_targets):
                            qcal = q_join(tf, callee)
                            if qcal not in cg[qcur]:
                                cg[qcur].add(qcal)
                                n_added += 1
                        if cur is not None and cur not in known:
                            new_targets.add(cur)
            known |= new_targets
            targets = new_targets

    data["call_graph"] = {k: sorted(v) for k, v in cg.items() if v}
    relevant: set[str] = set()
    for k, vs in data["call_graph"].items():
        relevant.add(q_name(k))
        relevant.update(q_name(v) for v in vs)
    data["call_graph_files"] = {k: sorted(v) for k, v in fn_locs.items()
                                if k in relevant}

    n_edges_after = sum(len(v) for v in data["call_graph"].values())
    print(f"  [s1] call-graph: agent={n_agent_edges} edges "
          f"→ validate -{n_dropped} hallucinated "
          f"→ supplement +{n_added} regex "
          f"= {n_edges_after} qualified edges over "
          f"{len(data['call_graph'])} nodes, "
          f"{len(data['call_graph_files'])} located fns "
          f"({len(src_files)} source files scanned)", file=sys.stderr)


SYSTEM = """You are a security-focused codebase mapper. Explore this repository
using your built-in tools (Read, Glob, Grep) to build a structural
understanding.

1. Start with Glob to see the file layout and identify the primary language.
2. Grep for unsafe sinks (strcat, strcpy, sprintf, memcpy, system, exec, eval,
   pickle.loads, yaml.load, deserialize, etc — adapt to the language).
3. Grep for entry points (main, HTTP handlers, RPC handlers, socket listeners,
   CLI parsers, deserializers).
4. Read key files to understand purpose (one-line summary per module).
5. Build a rough call graph for paths from entry points to unsafe sinks.

Be efficient — broad searches first, then targeted reads.

IMPORTANT: Your FINAL output must be ONLY a JSON object with this exact schema
(no prose before or after):
{
  "language": "primary language",
  "modules": [{"name":"str", "files":["path"], "loc":1234, "purpose":"one-line"}],
  "entry_points": [{"file":"str", "function":"str", "kind":"network|ipc|file|cli|deserialization|other", "reachable_from_unauth":true}],
  "unsafe_sinks": [{"file":"str", "line":123, "function":"str", "snippet":"the line"}],
  "call_graph": {"caller_func": ["callee_func"]},
  "notes": "free-form observations"
}

Do NOT include raw source code in the output. Include file paths, line numbers,
function names, and short snippets (max 120 chars each) only."""


def run(repo_root: str, cfg, known_cves: list[CVE], controls: list[Control]) -> ContextPackage:
    cve_block = "\n".join(f"  - {c.id}: {c.summary}" for c in known_cves) or "  (none)"

    # Option B: tell the agent up front which dirs/patterns to skip so it
    # doesn't burn the max_budget_usd reading test/build/vendor code. This is
    # advisory only — Option A below enforces it deterministically.
    excl_dirs, _excl_exts, _excl_globs = _exclusion_sets(cfg)
    skip_dirs = ", ".join(sorted(excl_dirs))

    user_prompt = f"""Map this repository for security analysis.

Known CVEs already filed (do NOT re-flag these as new findings):
{cve_block}

OUT OF SCOPE — do NOT Glob into, Grep through, or Read files under any
directory named one of these (tests / build artifacts / vendor / infra; they
are not production attack surface and waste your tool budget):
  {skip_dirs}

Also skip individual test files matching:
  *_test.*  *.test.*  *.spec.*  *Test.java  *Tests.java  *IT.java  conftest.py

Do not report unsafe_sinks, entry_points or modules from those paths.

Explore the codebase thoroughly, then output the JSON ContextPackage."""

    # Parse allowed_tools from config (it's a list in YAML)
    allowed_tools = cfg.step1.allowed_tools
    if isinstance(allowed_tools, list):
        tools = allowed_tools
    else:
        tools = ["Read", "Glob", "Grep", "Bash"]

    raw = agentic(
        user_prompt,
        model=cfg.models.preprocess,
        system_prompt=SYSTEM,
        allowed_tools=tools,
        cwd=repo_root,
        max_budget_usd=cfg.step1.max_budget_usd,
        max_turns=getattr(cfg.step1, "max_turns", None),
    )

    # The agentic output may have tool-use chatter before the final JSON.
    # Extract the last JSON block.
    #
    # degrade — don't abort the whole scan — when the mapper emits empty
    # or non-JSON output, mirroring s4/s8's fallback behaviour. The downstream
    # ground-truth walk (_walk_repo) and the deterministic call-graph supplement
    # below repopulate file inventory + edges, so an empty agent map still yields
    # a usable ContextPackage (we just lose the LLM's sink/entry-point guesses).
    try:
        data = extract_json(raw)
        if not isinstance(data, dict):
            raise ValueError(f"expected JSON object, got {type(data).__name__}")
    except Exception as e:  # noqa: BLE001 — model output is heterogeneous
        head = (raw or "")[:500].replace("\n", "\\n")
        print(f"  [s1] WARN: mapper response not parseable ({e}); proceeding "
              f"with deterministic inventory only. raw[:500]={head!r}",
              file=sys.stderr)
        data = {}

    # The model occasionally wraps the payload in a single container key
    # (e.g. {"context_package": {...}} or {"ContextPackage": {...}}) because
    # the prompt says "output the JSON ContextPackage". Unwrap it.
    if (isinstance(data, dict) and "language" not in data
            and len(data) == 1):
        inner = next(iter(data.values()))
        if isinstance(inner, dict) and ("language" in inner
                                         or "modules" in inner
                                         or "entry_points" in inner):
            print(f"  [s1] unwrapping model output from "
                  f"{next(iter(data))!r} container", file=sys.stderr)
            data = inner

    # Inject repo_root, ground-truth file list, CVEs, controls (not generated by the model)
    all_files, excluded = _walk_repo(repo_root, cfg)
    all_files, dedup_report = _dedup_configs(all_files, Path(repo_root), cfg)
    excluded["config_dedup"] = dedup_report

    # Option A: deterministically strip any agent-emitted path that isn't in
    # the exclusion-filtered ground-truth inventory. The agent ignores the
    # prompt skip-list ~10% of the time; this guarantees test/mock/vendor
    # paths never reach s3 chunking regardless. Paths are normalized so
    # './foo', 'foo', '<abs>/foo' and 'foo\\bar' all match the inventory form.
    keep = set(all_files)
    # In --group-by-app mode repo_root is the app dir and each repo is a
    # top-level subdir. The agent sometimes reports paths relative to the
    # repo it explored (omitting that prefix), so fall back to trying each
    # top-level dir as a prefix before discarding.
    top_dirs = sorted(d.name for d in Path(repo_root).iterdir()
                      if d.is_dir() and d.name not in ("checkpoints",
                                                       "security-scan"))

    def _resolve_in_scope(path: str) -> str | None:
        rel = _norm_rel(repo_root, path)
        if rel in keep:
            return rel
        for td in top_dirs:
            cand = f"{td}/{rel}"
            if cand in keep:
                return cand
        return None

    n_sinks_raw = len(data.get("unsafe_sinks") or [])
    n_eps_raw = len(data.get("entry_points") or [])

    data["unsafe_sinks"] = [
        dict(s, file=hit)
        for s in (data.get("unsafe_sinks") or [])
        if (hit := _resolve_in_scope(s.get("file", "")))
    ]
    data["entry_points"] = [
        dict(e, file=hit)
        for e in (data.get("entry_points") or [])
        if (hit := _resolve_in_scope(e.get("file", "")))
    ]
    for m in (data.get("modules") or []):
        m["files"] = [hit for f in (m.get("files") or [])
                      if (hit := _resolve_in_scope(f))]

    n_sinks_drop = n_sinks_raw - len(data["unsafe_sinks"])
    n_eps_drop = n_eps_raw - len(data["entry_points"])
    if n_sinks_drop or n_eps_drop:
        print(f"  [s1] filtered agent output: -{n_sinks_drop} sinks, "
              f"-{n_eps_drop} entry points (excluded/test/nonexistent paths)",
              file=sys.stderr)

    data["repo_root"] = repo_root
    # `language` is a required field with no default; on the degraded path
    # (empty agent output) the model never supplied one. Derive a deterministic
    # fallback from the most common source extension so model_validate succeeds.
    if not data.get("language"):
        ext_counts: dict[str, int] = {}
        for f in all_files:
            lang = EXT_TO_LANG.get(Path(f).suffix.lower())
            if lang:
                ext_counts[lang] = ext_counts.get(lang, 0) + 1
        data["language"] = (max(ext_counts, key=ext_counts.get)
                            if ext_counts else "unknown")
    data["all_files"] = all_files
    data["excluded"] = excluded
    data["known_cves"] = [c.model_dump() for c in known_cves]
    data["design_controls"] = [c.model_dump() for c in controls]

    _supplement_call_graph(data, all_files, Path(repo_root), cfg)

    # Off-schema enum/int values (e.g. kind="rpc", line=null) are coerced by
    # field_validator(mode="before") hooks in models.py — see _coerce_enum /
    # _coerce_int. model_validate() therefore never raises on a stray value.
    pkg = ContextPackage.model_validate(data)
    n_ex_dirs = sum(excluded["dirs"].values())
    n_ex_exts = sum(excluded["exts"].values())
    n_ex_globs = sum(excluded["globs"].values())
    n_ex_size = excluded["oversize"]
    n_ex_dedup = (excluded.get("config_dedup") or {}).get("dropped", 0) or 0
    n_in_scope = len(pkg.all_files)
    n_total = n_in_scope + n_ex_dirs + n_ex_exts + n_ex_globs + n_ex_size + n_ex_dedup
    print(f"  [s1] file inventory: {n_total} on disk -> {n_in_scope} in scope "
          f"(excluded: {n_ex_dirs} dir, {n_ex_exts} ext, {n_ex_globs} glob, "
          f"{n_ex_size} oversize, {n_ex_dedup} config-dedup)", file=sys.stderr)
    print(f"  [s1] done: {len(pkg.modules)} modules, "
          f"{len(pkg.entry_points)} entry points, "
          f"{len(pkg.unsafe_sinks)} sinks, {n_in_scope} files in scope",
          file=sys.stderr)
    return pkg
