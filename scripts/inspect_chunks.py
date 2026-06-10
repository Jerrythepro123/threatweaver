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
Inspect s1/s2/s3 checkpoints without running deepdive.

Usage:
  python inspect_chunks.py --repo <target>            # full report
  python inspect_chunks.py --repo <target> --file src/auth/Login.java
  python inspect_chunks.py --repo <target> --json manifest.json

Run the pipeline with `--stop-after s3` first so the checkpoints exist.
"""
from __future__ import annotations
import argparse
import json
import pickle
import sys
from collections import deque
from pathlib import Path

# Pickles reference models.* — ensure project root is importable when this
# script is launched from elsewhere.

import vvaharness.models as models  # noqa: F401


def _latest_ckpt(ckpt_dir: Path, step: str) -> Path | None:
    hits = sorted(ckpt_dir.glob(f"*_{step}.pkl"), key=lambda p: p.stat().st_mtime)
    return hits[-1] if hits else None


def _load(ckpt_dir: Path, step: str, run_id: str | None):
    p = (ckpt_dir / f"{run_id}_{step}.pkl") if run_id else _latest_ckpt(ckpt_dir, step)
    if not p or not p.exists():
        return None, None
    with open(p, "rb") as f:
        return pickle.load(f), p


def _count_loc(p: Path) -> int:
    try:
        return sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))
    except OSError:
        return 0


def _fmt(n: int) -> str:
    return f"{n/1000:.1f}k" if n >= 1000 else str(n)


def _bfs_reaches(start: str, graph: dict, sinks: set[str], max_hops: int) -> set[str]:
    if not start:
        return set()
    hit: set[str] = set()
    seen = {start}
    q = deque([(start, 0)])
    while q:
        node, d = q.popleft()
        for nx in graph.get(node, ()):
            if nx in seen:
                continue
            seen.add(nx)
            if nx in sinks:
                hit.add(nx)
            if d + 1 < max_hops:
                q.append((nx, d + 1))
    return hit


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, help="target repo (contains checkpoints/)")
    ap.add_argument("--run-id", help="specific run id; default = most recent")
    ap.add_argument("--file", help="show which chunk(s) contain this file")
    ap.add_argument("--json", nargs="?", const="-",
                    help="dump TaskManifest as JSON (to path, or stdout if bare)")
    ap.add_argument("--max-hops", type=int, default=12,
                    help="BFS depth for orphaned-sink check")
    args = ap.parse_args()

    repo = Path(args.repo).resolve()
    ckpt_dir = repo / "checkpoints"
    if not ckpt_dir.is_dir():
        print(f"error: no checkpoints/ under {repo}", file=sys.stderr)
        return 1

    ctx, ctx_p = _load(ckpt_dir, "s1", args.run_id)
    tm, _ = _load(ckpt_dir, "s2", args.run_id)
    manifest, man_p = _load(ckpt_dir, "s3", args.run_id)
    if ctx is None or manifest is None:
        print(f"error: missing s1/s3 checkpoint in {ckpt_dir} "
              f"(run pipeline with --stop-after s3 first)", file=sys.stderr)
        return 1

    print(f"# Inspect — {repo.name}")
    print(f"  ctx:      {ctx_p.name}")
    print(f"  manifest: {man_p.name}\n")

    # ── ContextPackage summary ───────────────────────────────────────────
    cg = ctx.call_graph or {}
    n_edges = sum(len(v) for v in cg.values())
    print("## s1 ContextPackage")
    print(f"  language        : {ctx.language}")
    print(f"  files in scope  : {len(ctx.all_files)}")
    print(f"  modules         : {len(ctx.modules)}")
    print(f"  entry points    : {len(ctx.entry_points)}  "
          f"({sum(1 for e in ctx.entry_points if e.reachable_from_unauth)} unauth)")
    print(f"  unsafe sinks    : {len(ctx.unsafe_sinks)}")
    print(f"  call-graph      : {len(cg)} nodes / {n_edges} edges  "
          f"({len(getattr(ctx, 'call_graph_files', {}) or {})} located fns)")
    if tm:
        print(f"  threat model    : {len(tm.assets)} assets, "
              f"{len(tm.trust_boundaries)} boundaries, {len(tm.threats)} threats")
    print()

    # ── Orphaned sinks (no entry→sink path in call graph) ────────────────
    sink_fns = {s.function for s in ctx.unsafe_sinks if s.function}
    entry_files = {e.file for e in ctx.entry_points}
    reached: set[str] = set()
    for ep in ctx.entry_points:
        reached |= _bfs_reaches(ep.function, cg, sink_fns, args.max_hops)
    orphans = [s for s in ctx.unsafe_sinks
               if s.function not in reached and s.file not in entry_files]
    ns = len(ctx.unsafe_sinks)
    print("## Taint reachability")
    print(f"  {ns - len(orphans)}/{ns} sinks "
          f"({(100*(ns-len(orphans))/ns) if ns else 0:.0f}%) "
          f"reachable from ≥1 entry point (max_hops={args.max_hops})")
    if orphans:
        print(f"  ORPHANED ({len(orphans)}):")
        for s in orphans:
            print(f"    - {s.file}:{s.line}  {s.function}()  «{(s.snippet or '')[:60]}»")
    print()

    # ── Chunk table ──────────────────────────────────────────────────────
    # ctx.repo_root is the absolute path recorded at scan time. If the
    # repo was scanned elsewhere (e.g. an orchestrator clone that has since
    # been purged or relocated), those paths no longer resolve and every chunk
    # would silently report 0 LOC. Prefer the live --repo the user passed,
    # falling back to the pickled scan-time root only if chunk files don't
    # exist under --repo.
    pickled_root = Path(ctx.repo_root)
    loc_root = repo
    # Decide which root resolves chunk files; warn if neither does.
    probe_files = [f for c in manifest.sorted_chunks() for f in c.files][:25]
    live_hits = sum(1 for f in probe_files if (repo / f).exists())
    pickled_hits = sum(1 for f in probe_files if (pickled_root / f).exists())
    if probe_files and live_hits == 0 and pickled_hits > 0:
        loc_root = pickled_root
        print(f"  [warn] chunk files not found under --repo {repo}; "
              f"using pickled scan-time root {pickled_root} for LOC",
              file=sys.stderr)
    elif probe_files and live_hits == 0 and pickled_hits == 0:
        print(f"  [warn] chunk files resolve under neither --repo {repo} nor "
              f"pickled scan-time root {pickled_root}; LOC will read 0",
              file=sys.stderr)
    repo_root = loc_root
    chunks = manifest.sorted_chunks()
    rows: list[tuple] = []
    for c in chunks:
        loc = sum(_count_loc(repo_root / f) for f in c.files)
        rows.append((c, loc))

    print(f"## s3 Chunks ({len(chunks)})")
    print(f"  {'id':<16} {'rank':>4} {'files':>5} {'LOC':>7} "
          f"{'threat':<6} {'langs':<14} hypothesis")
    print(f"  {'-'*16} {'-'*4} {'-'*5} {'-'*7} {'-'*6} {'-'*14} {'-'*40}")
    for c, loc in rows:
        langs = ",".join(c.languages[:3]) or "-"
        hyp = (c.hypothesis or "").replace("\n", " ")
        print(f"  {c.id:<16} {c.risk_rank:>4} {len(c.files):>5} {_fmt(loc):>7} "
              f"{c.threat_id or '-':<6} {langs:<14} {hyp[:60]}")
    print()

    # ── LOC distribution ─────────────────────────────────────────────────
    locs = sorted(loc for _, loc in rows)
    if locs:
        n = len(locs)
        print("## Chunk LOC distribution")
        print(f"  n={n}  min={_fmt(locs[0])}  p50={_fmt(locs[n//2])}  "
              f"p90={_fmt(locs[min(n-1, int(n*0.9))])}  max={_fmt(locs[-1])}  "
              f"total={_fmt(sum(locs))}")
        big = [(c.id, loc) for c, loc in rows if loc > 10000]
        if big:
            print(f"  >10k LOC ({len(big)}): "
                  + ", ".join(f"{cid}={_fmt(l)}" for cid, l in big))
        print()

    # ── Threat coverage ──────────────────────────────────────────────────
    if tm and tm.threats:
        covered = {c.threat_id for c in chunks if c.threat_id}
        ids = [t.id for t in tm.threats]
        missing = [t for t in ids if t not in covered]
        print("## Threat coverage")
        print(f"  {len(ids) - len(missing)}/{len(ids)} threats have ≥1 chunk")
        if missing:
            by_id = {t.id: t for t in tm.threats}
            for tid in missing:
                t = by_id[tid]
                print(f"  UNCOVERED {tid}: {getattr(t, 'threat', '')[:70]}")
        print()

    # ── --file lookup ────────────────────────────────────────────────────
    if args.file:
        needle = args.file.replace("\\", "/")
        hits = [c for c in chunks
                if any(needle == f or needle in f or f.endswith("/" + needle)
                       for f in c.files)]
        print(f"## File lookup: {needle}")
        if not hits:
            in_scope = any(needle == f or f.endswith("/" + needle)
                           for f in ctx.all_files)
            print(f"  NOT in any chunk "
                  f"({'in scope but unassigned — BUG' if in_scope else 'not in scope (excluded by s1)'})")
        else:
            for c in hits:
                print(f"  -> {c.id} (rank {c.risk_rank}, {len(c.files)} files)")
        print()

    # ── --json dump ──────────────────────────────────────────────────────
    if args.json:
        payload = {
            "context": {
                "language": ctx.language,
                "files_in_scope": len(ctx.all_files),
                "entry_points": [e.model_dump() for e in ctx.entry_points],
                "unsafe_sinks": [s.model_dump() for s in ctx.unsafe_sinks],
                "call_graph_nodes": len(cg),
                "call_graph_edges": n_edges,
            },
            "orphaned_sinks": [
                {"file": s.file, "line": s.line, "function": s.function}
                for s in orphans
            ],
            "chunks": [
                dict(c.model_dump(), loc=loc) for c, loc in rows
            ],
        }
        out = json.dumps(payload, indent=2)
        if args.json == "-":
            print(out)
        else:
            Path(args.json).write_text(out, encoding="utf-8")
            print(f"  wrote {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
