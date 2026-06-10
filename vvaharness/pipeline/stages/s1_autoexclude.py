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
Auto-derive a per-target step1 exclusion overlay.

Walks the freshly cloned repo / app dir in Python to build a deterministic
survey (dir tree + file counts + extension histogram + build-file excerpts),
then sends that survey as a single SDK prompt to Opus and asks which
directories, extensions and glob patterns are NON-production noise. The
result is written as a step1 overlay YAML that config.apply_step1_overlay()
can layer on top of the global step1 — so the real s1→s9 scan only sees
genuine attack surface.

The model is told what is ALREADY excluded (built-ins + config.yaml step1 +
any user-supplied overlay) so it returns only repo-specific additions.
"""
from __future__ import annotations
import os
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

from vvaharness.backends.llm import prompt
from vvaharness.pipeline.stages.s1_preprocess import _exclusion_sets, _DEDUP_DEFAULTS, glob_hit


_SYSTEM = """You are a build/scan triage agent. You will be shown a
deterministic survey of a source tree (directory layout, file counts,
extension histogram, and excerpts from build/README files). Decide which
parts are NOT production code so a security scanner can skip them.

Examples of things to EXCLUDE: generated/auto-gen code, vendored or
third-party copies, test fixtures and sample data, IDE/editor metadata,
build/CI output, documentation-only trees, demo/example apps, large data
dumps, migration snapshots, localisation bundles.

Be CONSERVATIVE — when unsure whether something is production code, do NOT
exclude it. Never exclude application source, configuration that affects
runtime behaviour, or infrastructure-as-code that provisions production.

You MUST reply with a single fenced ```yaml block and nothing else."""


# Build/manifest files whose first few lines help the model tell prod vs demo.
_EXCERPT_NAMES = re.compile(
    r"^(readme(\..*)?|package\.json|pom\.xml|build\.gradle(\.kts)?|"
    r"setup\.(py|cfg)|pyproject\.toml|cargo\.toml|go\.mod|makefile|"
    r"dockerfile|composer\.json|gemfile|.*\.csproj|.*\.sln|angular\.json|"
    r"lerna\.json|nx\.json|turbo\.json)$",
    re.IGNORECASE,
)
_EXCERPT_CHARS = 1500
_EXCERPT_MAX = 12
_TREE_DEPTH = 2
_TREE_MAX_CHILDREN = 60
_EXT_TOP_N = 40
_LARGEST_N = 15

_DEDUP_KEYS = {"enabled": bool, "exts": list, "min_cluster_size": int,
               "keep_per_top_dir": bool, "promote_on_secret_hit": bool,
               "promote_on_insecure_value": bool, "max_file_kb": int}


def _survey(repo_root: Path, base_dirs: set[str], base_exts: set[str],
            base_globs: list[str]) -> tuple[str, int]:
    """Single os.walk pass producing the three survey blocks. Already-excluded
    dirs/exts/globs are skipped so counts reflect what s1 would actually see."""
    def globbed(rel: str) -> bool:
        # Same root-aware predicate as the authoritative walk (shared helper),
        # so the survey can't disagree with what s1 actually excludes.
        return glob_hit(rel, base_globs) is not None

    # rel-posix-dir → (subdirs:set[str], file_count:int, depth:int)
    tree: dict[str, list] = {"": [set(), 0, 0]}
    ext_hist: Counter[str] = Counter()
    excerpts: list[tuple[str, str]] = []
    largest: list[tuple[int, str]] = []
    n_files = 0
    root_resolved = Path(repo_root).resolve()

    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = str(PurePosixPath(Path(dirpath).relative_to(repo_root)))
        rel_dir = "" if rel_dir == "." else rel_dir
        depth = 0 if not rel_dir else rel_dir.count("/") + 1
        dirnames[:] = sorted(
            d for d in dirnames
            if d.lower() not in base_dirs
            and not globbed(f"{rel_dir}/{d}" if rel_dir else d)
        )
        if depth <= _TREE_DEPTH:
            node = tree.setdefault(rel_dir, [set(), 0, depth])
            node[0].update(dirnames)
        for fn in filenames:
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            # Mirror _walk_repo's exclusion predicate exactly (final suffix OR
            # full-name endswith) so survey counts match the authoritative walk;
            # key the histogram on the single final suffix it reports.
            name = fn.lower()
            suffix = Path(fn).suffix.lower()
            if any(suffix == e or name.endswith(e) for e in base_exts) or globbed(rel):
                continue
            ext = suffix or "(none)"
            n_files += 1
            ext_hist[ext] += 1
            try:
                sz = (Path(dirpath) / fn).stat().st_size
            except OSError:
                sz = 0
            if len(largest) < _LARGEST_N or sz > largest[-1][0]:
                largest.append((sz, rel))
                largest.sort(reverse=True)
                del largest[_LARGEST_N:]
            anc = rel_dir
            while True:
                if anc in tree:
                    tree[anc][1] += 1
                if not anc:
                    break
                anc = anc.rpartition("/")[0]
            if (depth <= _TREE_DEPTH and len(excerpts) < _EXCERPT_MAX
                    and sz <= 5_000_000 and _EXCERPT_NAMES.match(fn)):
                # Skip the read for an oversized file (e.g. a multi-GB README):
                # we only keep a small slice, so don't pull the whole thing into
                # memory first. The cheap int compare short-circuits the regex.
                fp = Path(dirpath) / fn
                # Never read a symlink whose target resolves outside the repo —
                # its content is off-host data that would be embedded in the
                # auto-exclude prompt.
                if fp.is_symlink():
                    try:
                        if not fp.resolve(strict=False).is_relative_to(
                                root_resolved):
                            continue
                    except OSError:
                        continue
                try:
                    txt = fp.read_text(
                        encoding="utf-8", errors="replace")[:_EXCERPT_CHARS]
                    excerpts.append((rel, txt.rstrip()))
                except OSError:
                    pass

    def render_tree() -> str:
        lines = [f"./    ({tree[''][1]} files)"]
        for rel, (subs, cnt, depth) in sorted(tree.items()):
            if not rel:
                continue
            indent = "  " * depth
            lines.append(f"{indent}{PurePosixPath(rel).name}/    ({cnt} files)")
            if depth == _TREE_DEPTH and subs:
                kids = sorted(subs)
                shown = kids[:_TREE_MAX_CHILDREN]
                lines.extend(f"{indent}  {k}/" for k in shown)
                if len(kids) > _TREE_MAX_CHILDREN:
                    lines.append(f"{indent}  … (+{len(kids) - _TREE_MAX_CHILDREN} more)")
        return "\n".join(lines)

    ext_block = "\n".join(
        f"  {ext:<16} {n:>7}" for ext, n in ext_hist.most_common(_EXT_TOP_N)
    ) or "  (none)"
    if len(ext_hist) > _EXT_TOP_N:
        ext_block += f"\n  … (+{len(ext_hist) - _EXT_TOP_N} more extensions)"

    exc_block = "\n\n".join(
        f"### {rel}\n```\n{txt}\n```" for rel, txt in excerpts
    ) or "(no README/build files found at depth ≤2)"

    large_block = "\n".join(
        f"  {sz / 1024:8.1f} KB  {rel}" for sz, rel in largest
    ) or "  (none)"

    survey = (
        f"## Directory tree (depth ≤{_TREE_DEPTH + 1}, already-excluded dirs hidden, "
        f"counts = files that survive current exclusions)\n"
        f"```\n{render_tree()}\n```\n\n"
        f"## Extension histogram (top {_EXT_TOP_N})\n"
        f"```\n{ext_block}\n```\n\n"
        f"## Largest {_LARGEST_N} files (after current exclusions)\n"
        f"```\n{large_block}\n```\n\n"
        f"## Build / README excerpts\n{exc_block}"
    )
    return survey, n_files


def _extract_yaml(text: str) -> dict:
    m = re.search(r"```(?:yaml|yml)?\s*\n(.*?)\n```", text, re.S | re.I)
    blob = m.group(1) if m else text
    # yaml.safe_load raises YAMLError on malformed YAML. The run()
    # docstring promises it ALWAYS writes an overlay file (so --resume can
    # detect a prior run and callers can apply unconditionally); an uncaught
    # parse error here breaks that contract. Degrade to an empty overlay
    # instead — no model-proposed exclusions, but the file still gets written.
    try:
        data = yaml.safe_load(blob) or {}
    except yaml.YAMLError as e:
        print(f"  [auto-step1] WARN: model YAML unparseable ({e}); "
              f"writing empty overlay.", file=sys.stderr)
        return {}
    if isinstance(data, dict) and set(data) == {"step1"} and isinstance(data["step1"], dict):
        data = data["step1"]
    return data if isinstance(data, dict) else {}


def _norm_list(v, *, lower: bool = False) -> list[str]:
    if not v:
        return []
    if isinstance(v, str):
        v = [v]
    out: list[str] = []
    for x in v:
        if not isinstance(x, str):
            continue
        x = x.strip().strip("/\\")
        if not x:
            continue
        out.append(x.lower() if lower else x)
    seen: set[str] = set()
    uniq = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def run(repo_root: str | Path, cfg, *, out_path: str | Path) -> Path:
    """Survey `repo_root`, write a step1 overlay YAML to `out_path`, return it.

    Always writes a file (possibly with empty lists) so callers can apply it
    unconditionally and so --resume can detect a prior run."""
    repo_root = str(repo_root)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    base_dirs, base_exts, base_globs = _exclusion_sets(cfg)
    cur_max_kb = int(getattr(cfg.step1, "max_file_kb", 1024))
    cur_dedup = dict(_DEDUP_DEFAULTS)
    user_dd = getattr(cfg.step1, "config_dedup", None)
    if user_dd is not None:
        raw_dd = (user_dd if isinstance(user_dd, dict)
                  else getattr(user_dd, "_data", None) or vars(user_dd))
        # filter out None values before merging, mirroring
        # s1_preprocess._dedup_configs. A user override of
        # `config_dedup: {exts: null}` otherwise nulls out the default exts
        # and the `list(cur_dedup['exts'])` below would crash on None.
        cur_dedup.update({k: v for k, v in raw_dd.items() if v is not None})

    survey, n_files = _survey(Path(repo_root), base_dirs, base_exts, base_globs)
    model = getattr(cfg.models, "autoexclude", None) or cfg.models.preprocess
    max_tok = int(getattr(cfg.step1, "auto_exclude_max_tokens", 8000))

    user_prompt = f"""Below is a deterministic survey of a repository. Propose
ADDITIONAL scan exclusions so the security scanner only sees production code.

Already excluded (do NOT repeat these — propose only repo-specific extras):
  dirs : {", ".join(sorted(base_dirs))}
  exts : {", ".join(sorted(base_exts))}
  globs: {", ".join(base_globs)}

Current max_file_kb = {cur_max_kb}
Current config_dedup = {{exts: {list(cur_dedup['exts'])}, min_cluster_size: {cur_dedup['min_cluster_size']}}}

{survey}

Return ONLY a fenced YAML block with these keys (omit any key you have no
change for — do NOT emit empty/null placeholders):

```yaml
exclude_dirs:   # directory NAMES (any depth), e.g. "generated", "samples"
  - ...
exclude_exts:   # file extensions WITH leading dot, e.g. ".pb.go", ".min.js"
  - ...
exclude_globs:  # repo-relative posix fnmatch, e.g. "**/*.g.dart", "tools/codegen/**"
  - ...
max_file_kb: 1024   # OPTIONAL int. Only emit if the largest-files list shows
                    # genuine source bigger than the current limit (raise it)
                    # or only data dumps above a lower threshold (lower it).
config_dedup:       # OPTIONAL. Only emit keys you want to change.
  exts: [...]       # FULL list (REPLACES current). Include defaults you want
                    # to keep plus repo-specific formats e.g. ".tfvars", ".cue".
  min_cluster_size: 3
```

Whole sub-repos that are clearly test-automation, demo, or tooling-only may
be excluded via exclude_globs (e.g. "that-repo/**"). Be conservative."""

    print(f"  [auto-step1] surveying {repo_root} ({n_files} files, "
          f"prompt {len(user_prompt)} chars)", file=sys.stderr)
    raw = prompt(
        user_prompt,
        model=model,
        system_prompt=_SYSTEM,
        max_tokens=max_tok,
        tag="s1 autoexclude",
    )

    data = _extract_yaml(raw)
    base_dirs_l = {d.lower() for d in base_dirs}
    base_exts_l = {e.lower() for e in base_exts}

    dirs = [d for d in _norm_list(data.get("exclude_dirs"))
            if d.lower() not in base_dirs_l]
    exts = []
    for e in _norm_list(data.get("exclude_exts"), lower=True):
        if not e.startswith("."):
            e = "." + e
        if e not in base_exts_l:
            exts.append(e)
    globs = [g for g in _norm_list(data.get("exclude_globs"))
             if g not in set(base_globs)]

    overlay: dict = {"exclude_dirs": dirs, "exclude_exts": exts,
                     "exclude_globs": globs}

    mfk = data.get("max_file_kb")
    if isinstance(mfk, (int, float)) and int(mfk) > 0 and int(mfk) != cur_max_kb:
        overlay["max_file_kb"] = int(mfk)

    dd_in = data.get("config_dedup")
    if isinstance(dd_in, dict):
        dd_out: dict = {}
        for k, typ in _DEDUP_KEYS.items():
            if k not in dd_in:
                continue
            v = dd_in[k]
            if typ is list:
                xs = [("." + e.lstrip(".")).lower()
                      for e in _norm_list(v, lower=True)]
                if xs:
                    dd_out[k] = xs
            elif typ is bool and isinstance(v, bool):
                dd_out[k] = v
            elif typ is int and isinstance(v, (int, float)):
                dd_out[k] = int(v)
        if dd_out:
            overlay["config_dedup"] = dd_out

    out.write_text(
        "# Auto-generated by vvaharness auto-step1 — appended to global step1.\n"
        + yaml.safe_dump(overlay, sort_keys=False, default_flow_style=False),
        encoding="utf-8",
    )
    extras = []
    if "max_file_kb" in overlay:
        extras.append(f"max_file_kb={overlay['max_file_kb']}")
    if "config_dedup" in overlay:
        extras.append(f"config_dedup={sorted(overlay['config_dedup'])}")
    print(f"  [auto-step1] wrote {out}  "
          f"(+{len(dirs)} dirs, +{len(exts)} exts, +{len(globs)} globs"
          f"{', ' + ', '.join(extras) if extras else ''})",
          file=sys.stderr)
    return out
