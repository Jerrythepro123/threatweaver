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
Step 3 — the strategist LLM receives the ContextPackage (no raw code) and produces a
risk-ranked TaskManifest. Single CLI call; repeating this wastes tokens.
"""
from __future__ import annotations
import re
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath

from vvaharness.models import ContextPackage, TaskManifest, Chunk, ChunkSize
from vvaharness.backends.llm import prompt
from vvaharness.util.json_extract import extract_json
from vvaharness.lang.hints import (
    detect_languages,
    EXT_TO_LANG,
    is_c_cpp_file,
    is_iac_file,
)
from vvaharness.pipeline.stages.s1_preprocess import q_join, q_file, q_name

SYSTEM = """You are a vulnerability research strategist. You receive a structured
map of a codebase — NOT the source code itself — and produce a prioritized
hunting plan.

Your job:
1. Rank attack surfaces by risk. Unauth-reachable entry points + unsafe sinks
   in the same data flow path = highest priority.
2. Hunt for VARIANTS of known CVEs. If CVE-X is a heap overflow in parser.c,
   look for sibling parsers with the same pattern.
3. Account for design controls. A bug behind strong auth ranks lower than the
   same bug pre-auth.
4. Tie every chunk to a THREAT. The THREAT MODEL section lists ranked threats
   T1..Tn. Each chunk MUST cite the threat_id it tests. Every threat should be
   covered by at least one chunk; if a threat has no plausible code surface,
   omit it — do NOT invent a chunk.
5. Chunk the work. Each chunk = a coherent set of files to deep-dive together.
   Use the CALL GRAPH section: when caller -> callee crosses files, put BOTH
   files in the same chunk so the entry-point and its sink are reviewed
   together. Tag size: small (<2k loc), medium (<8k), large (more).
6. For LARGE chunks, name the entry-point functions to anchor a sliding window.

Respond with ONLY a JSON object, no prose:
{
  "rationale": "one paragraph explaining your ranking",
  "chunks": [
    {
      "id": "chunk-01",
      "size": "small|medium|large",
      "risk_rank": 1,
      "files": ["src/parser.c", "src/parser.h"],
      "focus_entry_points": ["parse_request"],
      "hypothesis": "Specific reasoning about what to hunt and why",
      "threat_id": "T3",
      "related_cves": ["CVE-2024-1234"]
    }
  ]
}"""


def run(ctx: ContextPackage, cfg) -> TaskManifest:
    ctx = _native_only_context(ctx)
    user_prompt = ctx.to_prompt_block()

    raw = prompt(
        user_prompt,
        model=cfg.models.decompose,
        system_prompt=SYSTEM,
        max_tokens=getattr(cfg.step3, "max_tokens", None),
        timeout=getattr(cfg.step3, "timeout", 1800),
        tag="s3 decompose",
    )

    # degrade — don't abort the whole scan — on malformed/empty/wrong-shape
    # strategist output, mirroring how s4/s8 fall back instead of crashing.
    # extract_json raises ValueError on empty/non-JSON; TaskManifest requires
    # chunks + rationale (no defaults) so a valid-but-wrong-shape response raises
    # ValidationError. Either way we recover with an empty manifest: the taint /
    # catch-all / specialist passes below still sweep every ground-truth file,
    # so coverage is preserved (only the LLM's risk RANKING is lost).
    try:
        data = extract_json(raw)
        manifest = TaskManifest.model_validate(data)
    except Exception as e:  # provider/model output is heterogeneous
        head = (raw or "")[:500].replace("\n", "\\n")
        print(f"  [s3] WARN: strategist response not usable ({e}); "
              f"proceeding with deterministic coverage only (no LLM ranking). "
              f"raw[:500]={head!r}", file=sys.stderr)
        manifest = TaskManifest(chunks=[], rationale=(
            f"s3 strategist output unusable ({e}); risk ranking unavailable. "
            f"All files covered via deterministic taint/catch-all/specialist "
            f"passes."))

    # ── Coverage guarantee ───────────────────────────────────────────────
    # Normalize model-emitted paths against the ground-truth list, drop
    # hallucinated paths, then sweep any uncovered files into catch-all chunks.
    _normalize_chunk_files(manifest, ctx)
    cb = _char_budget(cfg)
    if cb is not None:
        print(f"    [s3] pack_by=tokens  budget="
              f"{getattr(cfg.step3, 'chunk_token_budget', 180000)}tok "
              f"− overhead={getattr(cfg.step3, 'chunk_overhead_tokens', 80000)}tok "
              f"→ {cb} chars/chunk  (legacy *_chunk_loc caps ignored)",
              file=sys.stderr)
    else:
        print("    [s3] pack_by=loc  (legacy *_chunk_loc caps active)",
              file=sys.stderr)
    n_taint = _add_taint_chunks(manifest, ctx, cfg)
    _split_oversize_risk_chunks(manifest, ctx, cfg)
    n_catchall = _add_catchall_chunks(manifest, ctx, cfg)

    # ── Language tagging ─────────────────────────────────────────────────
    repo_root = Path(ctx.repo_root)
    for c in manifest.chunks:
        c.languages = detect_languages(c.files, repo_root=repo_root)

    # ── Specialist passes (repo-wide; lenses defined in _lang_hints.SPECIALIST_HINTS) ──
    n_spec = _add_specialist_chunks(manifest, ctx, cfg)

    _report_threat_coverage(manifest, ctx)
    _report_chunk_loc(manifest, ctx, cfg)

    print(f"  [s3] done: {len(manifest.chunks)} chunks "
          f"({n_taint} taint, {n_catchall} catch-all, {n_spec} specialist), "
          f"top risk = {manifest.sorted_chunks()[0].id if manifest.chunks else 'none'}",
          file=sys.stderr)
    return manifest


def _native_only_context(ctx: ContextPackage) -> ContextPackage:
    """Return an s3-scoped copy containing only C/C++ code surfaces.

    Stage 5 currently accepts only low-level memory findings in C/C++ files.
    Applying the same language gate before decomposition prevents non-native
    files from consuming strategist output slots, deterministic chunks, and s4
    model calls.  The input object is intentionally not mutated: reporting can
    still describe the repository's full inventory and explain that only its
    native-code portion was scanned.
    """
    native_files = [file for file in ctx.all_files if is_c_cpp_file(file)]
    native_set = set(native_files)

    def _site_file(site: str) -> str:
        qualified = q_file(site)
        if qualified:
            return qualified
        path, sep, line = site.rpartition(":")
        return path if sep and line.isdigit() else site

    call_graph_files = {
        name: [site for site in sites if _site_file(site) in native_set]
        for name, sites in ctx.call_graph_files.items()
    }
    call_graph_files = {
        name: sites for name, sites in call_graph_files.items() if sites
    }

    def _native_node(node: str) -> bool:
        file = q_file(node)
        if file:
            return file in native_set
        # Bare legacy function names have no path to classify. Keep them when
        # no deterministic definition-site information exists; any files they
        # later suggest are still normalized against native_files.
        return node not in ctx.call_graph_files or node in call_graph_files

    call_graph = {
        caller: [callee for callee in callees if _native_node(callee)]
        for caller, callees in ctx.call_graph.items()
        if _native_node(caller)
    }

    modules = []
    for module in ctx.modules:
        files = [file for file in module.files if file in native_set]
        if files:
            modules.append(module.model_copy(update={"files": files}))

    scoped = ctx.model_copy(deep=True, update={
        "language": "c-cpp",
        "all_files": native_files,
        "modules": modules,
        "entry_points": [
            entry for entry in ctx.entry_points if entry.file in native_set
        ],
        "unsafe_sinks": [
            sink for sink in ctx.unsafe_sinks if sink.file in native_set
        ],
        "call_graph": call_graph,
        "call_graph_files": call_graph_files,
    })
    print(
        f"    [s3] native scope: {len(native_files)}/{len(ctx.all_files)} "
        "files retained before chunk generation",
        file=sys.stderr,
    )
    return scoped


# ─────────────────────────────────────────────────────────────────────────────
# Coverage helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_chunk_files(manifest: TaskManifest, ctx: ContextPackage) -> None:
    """Map model-emitted paths onto ctx.all_files; drop anything that doesn't exist."""
    truth = set(ctx.all_files)
    by_name: dict[str, list[str]] = defaultdict(list)
    for f in ctx.all_files:
        by_name[PurePosixPath(f).name].append(f)

    for chunk in manifest.chunks:
        fixed: list[str] = []
        for f in chunk.files:
            cand = f.replace("\\", "/")
            while cand.startswith("./"):
                cand = cand[2:]
            if cand in truth:
                fixed.append(cand)
                continue
            # try basename match (model sometimes drops directories)
            matches = by_name.get(PurePosixPath(cand).name, [])
            if len(matches) == 1:
                fixed.append(matches[0])
            else:
                print(f"    [s3] dropped non-existent file from {chunk.id}: {f}",
                      file=sys.stderr)
        chunk.files = list(dict.fromkeys(fixed))  # dedupe, keep order


_SECURITY_CONFIG_NAMES = {
    "web.xml", "struts.xml", "struts-config.xml", "applicationcontext.xml",
    "spring-security.xml", "beans.xml", "faces-config.xml", "shiro.ini",
    "security.xml", "ejb-jar.xml", "jboss-web.xml", "weblogic.xml",
    "androidmanifest.xml", "info.plist",
    "application.properties", "application.yml", "application.yaml",
    "appsettings.json", "web.config", "app.config",
}
_SECURITY_CONFIG_EXTS = {".xml", ".properties"}


def _is_source(f: str) -> bool:
    p = PurePosixPath(f)
    ext = p.suffix.lower()
    if ext in EXT_TO_LANG:
        return True
    name = p.name.lower()
    if name in _SECURITY_CONFIG_NAMES:
        return True
    # Descriptor XML / .properties under canonical Java config roots — not data XML.
    if ext in _SECURITY_CONFIG_EXTS:
        parts = f.lower().split("/")
        return any(seg in parts for seg in ("web-inf", "meta-inf", "resources", "conf", "config"))
    # IaC / CI / container configs — Dockerfile, *.tf, .github/workflows/*.yml,
    # helm/k8s manifests etc. The iac specialist sweeps these.
    if is_iac_file(f):
        return True
    return False


def _file_call_graph(ctx: ContextPackage) -> dict[str, set[str]]:
    """Project the qualified call_graph onto an undirected FILE graph.
    Every node is `file::name` (P5), so the file is read straight off the
    key — no more component-walk over unlocated bare names."""
    adj: dict[str, set[str]] = defaultdict(set)
    for caller, callees in (ctx.call_graph or {}).items():
        cf = q_file(caller)
        if not cf:
            continue
        for cal in callees:
            tf = q_file(cal)
            if tf and tf != cf:
                adj[cf].add(tf)
                adj[tf].add(cf)
    return adj


def _cohesive_groups(files: list[str], ctx: ContextPackage) -> list[tuple[str, list[str]]]:
    """
    Partition `files` into semantically related groups so a researcher sees
    callers and callees together. Preference order:
      1. ctx.modules (s1's agentic grouping — already relation-aware)
      2. call-graph connected components (controller+service+DAO stay together
         even when they live under /web/, /svc/, /dao/)
      3. depth-2 directory (last resort for files with no graph edges)
    Every input file lands in exactly one group.
    """
    pending = set(files)
    groups: list[tuple[str, list[str]]] = []

    for m in ctx.modules:
        hit = [f for f in m.files if f in pending]
        if hit:
            groups.append((m.name, hit))
            pending.difference_update(hit)

    adj = _file_call_graph(ctx)
    visited: set[str] = set()
    for f in sorted(pending):
        if f in visited or f not in adj:
            continue
        comp, stack = [], [f]
        while stack:
            n = stack.pop()
            if n in visited or n not in pending:
                continue
            visited.add(n)
            comp.append(n)
            stack.extend(adj.get(n, ()))
        if comp:
            groups.append((f"cg:{PurePosixPath(comp[0]).stem}", sorted(comp)))
    pending.difference_update(visited)

    by_dir: dict[str, list[str]] = defaultdict(list)
    for f in sorted(pending):
        parts = f.split("/")
        key = "/".join(parts[:2]) if len(parts) > 1 else "."
        by_dir[key].append(f)
    for key in sorted(by_dir):
        groups.append((key, by_dir[key]))

    return groups


def _report_threat_coverage(manifest: TaskManifest, ctx: ContextPackage) -> None:
    tm = ctx.threat_model
    if not tm or not tm.threats:
        return
    valid = {t.id for t in tm.threats}
    covered: set[str] = set()
    for c in manifest.chunks:
        if c.threat_id and c.threat_id not in valid:
            print(f"    [s3] {c.id}: unknown threat_id {c.threat_id!r} → dropped",
                  file=sys.stderr)
            c.threat_id = None
        if c.threat_id:
            covered.add(c.threat_id)
    missing = sorted(valid - covered)
    print(f"    [s3] threat coverage: {len(covered)}/{len(valid)} threats have ≥1 chunk"
          + (f"; UNCOVERED: {', '.join(missing)}" if missing else ""),
          file=sys.stderr)


def _pick_hop_files(candidates, anchors: list[str], cap: int) -> list[str]:
    """Return ≤`cap` candidate files, ranked by longest common directory
    prefix with any anchor (entry/sink file). Java package == dir path, so
    same-package definitions sort first. cap<=0 ⇒ no cap."""
    cands = list(dict.fromkeys(candidates))
    if cap <= 0 or len(cands) <= cap:
        return cands
    aps = [a.split("/") for a in anchors if a]

    def _aff(f: str) -> int:
        fp = f.split("/")
        best = 0
        for ap in aps:
            n = 0
            for x, y in zip(fp, ap):
                if x != y:
                    break
                n += 1
            best = max(best, n)
        return best

    cands.sort(key=lambda f: (-_aff(f), f))
    return cands[:cap]


def _add_taint_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Walk ctx.call_graph from each entry point to each unsafe sink and emit one
    chunk per reachable (entry, sink) pair containing every file we can resolve
    along the path. Guarantees the s4 researcher sees source AND sink together,
    which is the precondition for a confirmed data-flow finding.
    """
    if not getattr(cfg.step3, "taint_chunks", True):
        return 0
    if not ctx.entry_points or not ctx.unsafe_sinks:
        print("    [s3] taint: skipped (no entry points or sinks from s1)",
              file=sys.stderr)
        return 0

    graph = ctx.call_graph or {}
    graph_nodes: set[str] = set(graph)
    for vs in graph.values():
        graph_nodes.update(vs)
    by_bare: dict[str, list[str]] = defaultdict(list)
    for k in graph_nodes:
        by_bare[q_name(k)].append(k)

    def _match_qnodes(file: str, name: str) -> list[str]:
        cands = by_bare.get(name, [])
        hit = [k for k in cands if q_file(k) == file]
        if hit:
            return hit
        # Path-suffix match, but anchored on a "/" boundary so a partial
        # filename component can't match: "auth.py" must NOT match
        # "src/oauth.py". A == B, or one ends with "/" + the other.
        def _path_suffix(a: str, b: str) -> bool:
            return a == b or a.endswith("/" + b) or b.endswith("/" + a)
        hit = [k for k in cands if _path_suffix(q_file(k), file)]
        return hit or [q_join(file, name)]

    sink_qnodes: set[str] = set()
    sink_by_qn: dict[str, list] = defaultdict(list)
    for s in ctx.unsafe_sinks:
        if not s.function:
            continue
        for qn in _match_qnodes(s.file, s.function):
            sink_qnodes.add(qn)
            sink_by_qn[qn].append(s)

    repo_root = Path(ctx.repo_root)
    max_hops = getattr(cfg.step3, "taint_max_hops", 8)
    max_chunks = getattr(cfg.step3, "taint_max_chunks", 40)
    per_hop = int(getattr(cfg.step3, "taint_files_per_hop", 5) or 0)

    # Taint chunks are the highest-signal work — rank them ABOVE the LLM's
    # risk chunks so s4 processes them first.
    for c in manifest.chunks:
        c.risk_rank += max_chunks

    threats = ctx.threat_model.threats if ctx.threat_model else []

    def _tok(s: str) -> set[str]:
        return set(re.findall(r"[a-z0-9]+", s.lower()))

    # Per-threat surface tokens are loop-invariant across entry points, so
    # tokenize each threat surface once here rather than on every _threat_for
    # call.
    _threat_tokens = [(t, _tok(t.surface)) for t in threats if t.surface]

    def _threat_for(ep) -> str | None:
        # Associate a taint chunk with a threat by matching the threat's
        # surface (an entry-point/function NAME) to the entry function on a
        # whole-token / exact basis. Looser substring matching (incl. matching
        # against the file PATH) over-tagged this coverage metric, so it is
        # avoided. Exact (case-insensitive) wins; otherwise the first threat
        # sharing a whole token with the function name.
        fn_lower = (ep.function or "").lower()
        fn_tokens = _tok(fn_lower)
        best: str | None = None
        for t, surf_tokens in _threat_tokens:
            if t.surface.lower() == fn_lower:
                return t.id
            if best is None and fn_tokens and (surf_tokens & fn_tokens):
                best = t.id
        return best

    seen_paths: set[tuple] = set()
    reached_fns: set[str] = set()
    entry_files = {e.file for e in ctx.entry_points}
    added = 0
    entries = sorted(ctx.entry_points,
                     key=lambda e: (not e.reachable_from_unauth, e.kind))

    all_file_set = set(ctx.all_files)
    for ep in entries:
        if added >= max_chunks:
            break
        hits: list[tuple[str, list[str]]] = []
        for start in _match_qnodes(ep.file, ep.function):
            hits.extend(_bfs_to_sinks(start, graph, sink_qnodes, max_hops))
        reached_fns.update(qn for qn, _ in hits)
        # Direct sink in the entry file with no graph edge → still a chunk.
        if not hits:
            hits = [(q_join(s.file, s.function),
                     [q_join(ep.file, ep.function), q_join(s.file, s.function)])
                    for s in ctx.unsafe_sinks if s.file == ep.file]
        for sink_qn, path in hits:
            if added >= max_chunks:
                break
            sinks_here = sink_by_qn.get(sink_qn, ())
            sink_files = [s.file for s in sinks_here] or [q_file(sink_qn)]
            anchors = [ep.file, *sink_files]
            hop_files = [q_file(fn) for fn in path if q_file(fn)]
            files = _pick_hop_files(hop_files, anchors,
                                    per_hop * max(1, len(path)))
            files.append(ep.file)
            files.extend(sink_files)
            files = [f for f in dict.fromkeys(files) if f in all_file_set]
            if not files:
                continue
            sig = (ep.function, sink_qn, tuple(sorted(files)))
            if sig in seen_paths:
                continue
            seen_paths.add(sig)
            added += 1
            sink_refs = ", ".join(f"{s.file}:{s.line}"
                                  for s in sinks_here[:3]) or q_file(sink_qn)
            unauth = "UNAUTH " if ep.reachable_from_unauth else ""
            manifest.chunks.append(Chunk(
                id=f"taint-{added:02d}",
                size=_size_for(sum(_count_loc(repo_root / f) for f in files)),
                risk_rank=added,
                files=files,
                focus_entry_points=[ep.function],
                hypothesis=(
                    f"Taint path: {unauth}{ep.kind} input at "
                    f"{ep.function}() [{ep.file}] flows via "
                    f"{' -> '.join(q_name(n) for n in path)} to sink "
                    f"{q_name(sink_qn)}() [{sink_refs}]. Verify every hop for "
                    f"sanitization/validation; if none, this is exploitable."
                ),
                related_cves=[],
                threat_id=_threat_for(ep),
            ))

    reached_sink_objs = {id(s) for qn in reached_fns
                         for s in sink_by_qn.get(qn, ())}
    orphans = [s for s in ctx.unsafe_sinks
               if id(s) not in reached_sink_objs and s.file not in entry_files]
    n_sinks = len(ctx.unsafe_sinks)
    pct = (100 * (n_sinks - len(orphans)) / n_sinks) if n_sinks else 0
    sample = ", ".join(f"{s.file}:{s.line}" for s in orphans[:6])
    if len(orphans) > 6:
        sample += f", …(+{len(orphans) - 6})"
    print(f"    [s3] taint reachability: {n_sinks - len(orphans)}/{n_sinks} "
          f"sinks ({pct:.0f}%) on ≥1 entry→sink path"
          + (f"; ORPHANED: {sample}" if orphans else ""), file=sys.stderr)

    if added:
        print(f"    [s3] taint: {added} entry→sink path chunks "
              f"({len(ctx.entry_points)} entries × {len(ctx.unsafe_sinks)} sinks, "
              f"graph={len(graph)} nodes)", file=sys.stderr)
    else:
        # Nothing reachable — undo the rank shift so ordering is unchanged.
        for c in manifest.chunks:
            c.risk_rank -= max_chunks
        print("    [s3] taint: 0 reachable entry→sink paths in call graph",
              file=sys.stderr)
    return added


def _bfs_to_sinks(start: str, graph: dict[str, list[str]],
                  sinks: set[str], max_hops: int) -> list[tuple[str, list[str]]]:
    """Return [(sink_fn, path_funcs)] for every sink reachable from `start`."""
    if not start:
        return []
    out: list[tuple[str, list[str]]] = []
    visited = {start}
    frontier = [(start, [start])]
    while frontier:
        nxt = []
        for node, path in frontier:
            for callee in graph.get(node, ()):
                if callee in visited:
                    continue
                visited.add(callee)
                p = path + [callee]
                if callee in sinks:
                    out.append((callee, p))
                if len(p) <= max_hops:
                    nxt.append((callee, p))
        frontier = nxt
    return out


def _size_for(loc: int) -> ChunkSize:
    if loc < 2000:
        return ChunkSize.SMALL
    if loc < 8000:
        return ChunkSize.MEDIUM
    return ChunkSize.LARGE


def _char_budget(cfg) -> int | None:
    """Shard-boundary char cap when step3.pack_by == 'tokens', else None.
    chars ≈ tokens × 4; budget = (context window − fixed overhead) × 4."""
    if str(getattr(cfg.step3, "pack_by", "loc")).lower() != "tokens":
        return None
    budget = int(getattr(cfg.step3, "chunk_token_budget", 180_000))
    overhead = int(getattr(cfg.step3, "chunk_overhead_tokens", 80_000))
    return max(10_000, (budget - overhead) * 4)


def _split_oversize_risk_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    """Re-pack any LLM-emitted chunk whose total LOC exceeds step3.risk_chunk_loc
    into chunk-NN-a, chunk-NN-b, … so s4 never sends a prompt past the model's
    context window. Preserves risk_rank, hypothesis, CVEs and entry points."""
    max_loc = getattr(cfg.step3, "risk_chunk_loc", 8000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    if not max_loc and char_cap is None:
        return
    repo_root = Path(ctx.repo_root)

    out: list[Chunk] = []
    for c in manifest.chunks:
        loc = sum(_count_loc(repo_root / f) for f in c.files)
        if char_cap is not None:
            chars = sum(_count_chars(repo_root / f) for f in c.files)
            fits = chars <= char_cap and len(c.files) <= max_files
            cap_txt = f"{char_cap} chars (~{char_cap//4} tok)"
            got_txt = f"{chars} chars"
        else:
            fits = loc <= max_loc and len(c.files) <= max_files
            cap_txt = f"{max_loc} LOC"
            got_txt = f"{loc} LOC"
        if fits:
            c.size = _size_for(loc)
            out.append(c)
            continue
        groups = _cohesive_groups(c.files, ctx)
        buckets = _pack(groups, repo_root, max_loc, max_files,
                        max_chars=char_cap)
        print(f"    [s3] {c.id}: {got_txt} / {len(c.files)} files > cap "
              f"({cap_txt} / {max_files} files) → split into {len(buckets)}",
              file=sys.stderr)
        for i, (_, files, bloc) in enumerate(buckets):
            suffix = chr(ord("a") + i) if i < 26 else str(i + 1)
            out.append(c.model_copy(update={
                "id": f"{c.id}-{suffix}",
                "files": files,
                "size": _size_for(bloc),
            }))
    manifest.chunks = out


def _pack(groups: list[tuple[str, list[str]]], repo_root: Path,
          max_loc: int, max_files: int, *,
          max_chars: int | None = None) -> list[tuple[str, list[str], int]]:
    """Split each group into (label, files, loc) buckets.

    Shard boundary is decided by `max_chars` (bytes ≈ tokens×4) when given,
    otherwise by `max_loc` — so step3.pack_by switches the metric without
    touching callers. The returned `loc` is always real line count so
    `_size_for()` and the LOC distribution report stay correct in both modes.
    Groups that shard into N>1 buckets get a `[shard k/N]` label suffix."""
    use_chars = max_chars is not None
    out: list[tuple[str, list[str], int]] = []
    for label, files in groups:
        shards: list[tuple[list[str], int]] = []
        b_files: list[str] = []
        b_loc = b_chars = 0
        for f in files:
            loc = _count_loc(repo_root / f)
            chars = _count_chars(repo_root / f) if use_chars else 0
            over = ((b_chars + chars > max_chars) if use_chars
                    else (b_loc + loc > max_loc))
            if b_files and (over or len(b_files) >= max_files):
                shards.append((b_files, b_loc))
                b_files, b_loc, b_chars = [], 0, 0
            b_files.append(f)
            b_loc += loc
            b_chars += chars
        if b_files:
            shards.append((b_files, b_loc))
        n = len(shards)
        for k, (bf, bl) in enumerate(shards, 1):
            lbl = label if n == 1 else f"{label} [shard {k}/{n}]"
            out.append((lbl, bf, bl))
    return out


# Files that can't realistically carry an exploitable vuln. Dropped from
# catch-all coverage so 90+ chunks of docs/locks/snapshots don't get scanned.
# Credential-prone configs (.env, .npmrc, .yarnrc, *.key/pem/p12…) are KEPT.
_CATCHALL_SKIP_EXTS = {
    ".md", ".mdx", ".txt", ".rst", ".adoc",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
    ".css", ".scss", ".sass", ".less",
    ".lock", ".log", ".map", ".min.js", ".min.css",
    ".snap", ".d.ts",
    ".csv", ".tsv", ".xls", ".xlsx",
    ".po", ".pot", ".mo",
}
_CATCHALL_SKIP_NAMES = {
    "license", "changelog", "changes", "authors", "contributors", "notice",
    "readme", "codeowners", ".gitignore", ".gitattributes", ".editorconfig",
    ".prettierrc", ".prettierignore", ".eslintignore", ".dockerignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "go.sum", "cargo.lock", "composer.lock",
}
_CATCHALL_SKIP_DIR_PARTS = {
    "__snapshots__", "__fixtures__", "fixtures", "__mocks__", "mocks",
    "docs", "doc", "examples", "example", "samples",
}


def _catchall_eligible(rel: str) -> bool:
    p = Path(rel)
    name = p.name.lower()
    if name in _CATCHALL_SKIP_NAMES:
        return False
    # Match either the single final suffix (".js") or any trailing
    # multi-suffix tail (".min.js") against the skip set. A bare
    # ``suffixes in SET`` check missed multi-dotted names like
    # ``foo.bundle.min.js`` whose full joined suffixes (".bundle.min.js")
    # is not itself a skip key — so test every trailing dotted tail.
    name = p.name.lower()
    if p.suffix.lower() in _CATCHALL_SKIP_EXTS:
        return False
    if any(name.endswith(ext) for ext in _CATCHALL_SKIP_EXTS):
        return False
    if any(part.lower() in _CATCHALL_SKIP_DIR_PARTS for part in p.parts[:-1]):
        return False
    return True


def _add_catchall_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """Create low-rank chunks for every file not already assigned to a chunk."""
    covered: set[str] = set()
    for c in manifest.chunks:
        covered.update(c.files)
    uncovered = [f for f in ctx.all_files if f not in covered]
    if not getattr(cfg.step3, "catchall_enabled", True):
        print(f"    [s3] coverage: {len(uncovered)} uncovered files — "
              f"catch-all DISABLED (step3.catchall_enabled: false)",
              file=sys.stderr)
        return 0
    eligible = [f for f in uncovered if _catchall_eligible(f)]
    if not eligible:
        if uncovered:
            print(f"    [s3] coverage: {len(uncovered)} uncovered files "
                  f"(all non-source → 0 catch-all chunks)", file=sys.stderr)
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "catchall_chunk_loc", 20000)
    max_files = getattr(cfg.step3, "catchall_max_files",
                        getattr(cfg.step3, "max_files_per_chunk", 100))
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)

    groups = _cohesive_groups(eligible, ctx)
    buckets = _pack(groups, repo_root, max_loc, max_files,
                    max_chars=_char_budget(cfg))

    for idx, (label, files, loc) in enumerate(buckets, 1):
        manifest.chunks.append(_mk_catchall(idx, label, files, loc, base_rank + idx))

    print(f"    [s3] coverage: {len(uncovered)} uncovered "
          f"→ {len(eligible)} eligible → {len(buckets)} catch-all chunks",
          file=sys.stderr)
    return len(buckets)


def _add_specialist_chunks(manifest: TaskManifest, ctx: ContextPackage, cfg) -> int:
    """
    Append repo-wide specialist passes (crypto, logic-bug). These see ALL source
    files regardless of risk-ranking — they hunt for cross-cutting bug classes
    that per-chunk language researchers miss.

    Sharding is module-aware (via _cohesive_groups) and restricted to actual
    source files so specialists don't waste budget on YAML/shell/markdown.
    """
    enabled = getattr(cfg.step3, "specialists", None)
    if enabled is None:
        enabled = ["crypto", "logic-bug"]
    source = [f for f in ctx.all_files if _is_source(f)]
    enabled = _gate_specialists(enabled, ctx, source)
    if not enabled:
        print("    [s3] specialists: all gated off (no matching surface)", file=sys.stderr)
        return 0
    if not enabled or not source:
        return 0

    repo_root = Path(ctx.repo_root)
    max_loc = getattr(cfg.step3, "specialist_chunk_loc", 6000)
    max_files = getattr(cfg.step3, "max_files_per_chunk", 25)
    char_cap = _char_budget(cfg)
    base_rank = max((c.risk_rank for c in manifest.chunks), default=0)

    # Default bucketing covers all source. Specialists that need a narrower
    # scope (currently just `iac`) override below.
    default_buckets = _pack(_cohesive_groups(source, ctx),
                            repo_root, max_loc, max_files,
                            max_chars=char_cap)

    n_added = 0
    for spec in enabled:
        if spec == "iac":
            iac_source = [f for f in source if is_iac_file(f)]
            if not iac_source:
                print("    [s3] specialist 'iac' has 0 IaC files in source — skipped",
                      file=sys.stderr)
                continue
            spec_buckets = _pack(_cohesive_groups(iac_source, ctx),
                                 repo_root, max_loc, max_files,
                                 max_chars=char_cap)
            print(f"    [s3] specialist 'iac': scoped to {len(iac_source)} "
                  f"IaC file(s) → {len(spec_buckets)} shard(s)",
                  file=sys.stderr)
        else:
            spec_buckets = default_buckets
        for shard, (label, files, loc) in enumerate(spec_buckets, 1):
            manifest.chunks.append(_mk_specialist(
                spec, shard, label, files, loc, base_rank + n_added + 1,
                detect_languages(files, repo_root=repo_root)))
            n_added += 1

    print(f"    [s3] specialists: {', '.join(enabled)} -> {n_added} chunks "
          f"({len(source)}/{len(ctx.all_files)} source files)",
          file=sys.stderr)
    return n_added


_CRYPTO_RX = re.compile(
    r"\b(AES|RSA|HMAC|SHA-?(1|2|256|384|512)|MD5|PBKDF2|bcrypt|scrypt|argon2"
    r"|Cipher|KeyPair|SecretKey|X509|PKCS|TLS|SSLContext|jwt|jose|nacl|sodium"
    r"|hashlib|hmac\.|cryptography\.|javax\.crypto|BouncyCastle|OpenSSL"
    r"|Crypt::|Digest::|Mcrypt|RandomNumberGenerator|SecureRandom)\b",
    re.IGNORECASE,
)

_DESER_RX = re.compile(
    r"\b(ObjectInputStream|readObject|XMLDecoder|XStream|SnakeYAML|yaml\.load"
    r"|pickle\.|marshal\.load|unserialize|BinaryFormatter|Kryo|Hessian"
    r"|JdkSerializationRedisSerializer|Marshal\.load)\b",
)

_BATCH_ETL_RX = re.compile(
    r"\b(struct\.(?:un)?pack|codecs\.(?:encode|decode)\([^)]*ebcdic"
    r"|cp037|cp1047|COMP-3|packed[_-]?decimal|RECFM|LRECL"
    r"|glob\.glob|os\.listdir|shutil\.(?:move|copy)|csv\.(?:writer|reader)"
    r"|EXEC\s+PGM=|//\w+\s+DD\b|DISP=\()\b",
    re.IGNORECASE,
)


def _has_batch_surface(ctx: ContextPackage, repo_root: Path,
                       source: list[str]) -> bool:
    if any(ep.kind in {"file", "cli"} for ep in ctx.entry_points):
        return True
    langs = set(detect_languages(ctx.all_files, repo_root=repo_root))
    if langs & {"cobol", "jcl"}:
        return True
    return _scan_any(repo_root, source, _BATCH_ETL_RX)


def _scan_any(repo_root: Path, files: list[str], rx: re.Pattern) -> bool:
    for rel in files:
        p = repo_root / rel
        try:
            if rx.search(p.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _has_authz_surface(ctx: ContextPackage) -> bool:
    if ctx.app_profile and ctx.app_profile.externally_facing:
        return True
    if any(ep.kind in {"network", "ipc"} or ep.reachable_from_unauth
           for ep in ctx.entry_points):
        return True
    if any(c.kind == "auth" for c in ctx.design_controls):
        return True
    if ctx.threat_model:
        for t in ctx.threat_model.threats:
            if t.actor in {"remote_unauth", "remote_auth"}:
                return True
    return False


def _gate_specialists(enabled: list[str], ctx: ContextPackage,
                      source: list[str]) -> list[str]:
    """Drop specialist passes whose target surface doesn't exist in this repo,
    so s4/s5 don't burn budget verifying guaranteed-FP findings."""
    repo_root = Path(ctx.repo_root)
    gates = {
        "access-control":  lambda: _has_authz_surface(ctx),
        "crypto":          lambda: _scan_any(repo_root, source, _CRYPTO_RX),
        "deserialization": lambda: _scan_any(repo_root, source, _DESER_RX),
        "batch-etl":       lambda: _has_batch_surface(ctx, repo_root, source),
        "iac":             lambda: any(is_iac_file(f) for f in ctx.all_files),
    }
    kept: list[str] = []
    for spec in enabled:
        gate = gates.get(spec)
        if gate is None or gate():
            kept.append(spec)
        else:
            print(f"    [s3] specialist '{spec}' gated OFF — no matching surface in repo",
                  file=sys.stderr)
    return kept


def _mk_specialist(spec: str, shard: int, label: str, files: list[str], loc: int,
                   rank: int, langs: list[str]) -> Chunk:
    return Chunk(
        id=f"spec-{spec}-{shard:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=[],
        hypothesis=f"{spec} specialist sweep over module '{label}'.",
        related_cves=[],
        languages=langs,
        specialist=spec,
    )


def _mk_catchall(idx: int, dir_name: str, files: list[str], loc: int, rank: int) -> Chunk:
    return Chunk(
        id=f"catchall-{idx:02d}",
        size=_size_for(loc),
        risk_rank=rank,
        files=files,
        focus_entry_points=[],
        hypothesis=f"Coverage sweep of '{dir_name}' — files not assigned to any "
                   f"risk-ranked chunk. Hunt for any vulnerability class.",
        related_cves=[],
    )


def _report_chunk_loc(manifest: TaskManifest, ctx: ContextPackage, cfg) -> None:
    repo_root = Path(ctx.repo_root)
    locs = sorted(sum(_count_loc(repo_root / f) for f in c.files)
                  for c in manifest.chunks)
    if not locs:
        return
    n = len(locs)
    cap = getattr(cfg.step3, "risk_chunk_loc", 8000) or 0
    over = sum(1 for x in locs if cap and x > cap)
    fmt = lambda x: f"{x/1000:.1f}k" if x >= 1000 else str(x)
    print(f"    [s3] chunk LOC: n={n} min={fmt(locs[0])} "
          f"p50={fmt(locs[n // 2])} p90={fmt(locs[min(n - 1, int(n * 0.9))])} "
          f"max={fmt(locs[-1])}"
          + (f"  ({over} over risk_chunk_loc={cap})" if cap else ""),
          file=sys.stderr)


_CHARS_CACHE: dict[str, int] = {}


def _count_chars(p: Path) -> int:
    """File size in bytes (≈ chars for source). stat() only — no read, so
    pack_by:tokens adds ~zero I/O over LOC mode even on 20k-file trees."""
    k = str(p)
    v = _CHARS_CACHE.get(k)
    if v is not None:
        return v
    try:
        v = p.stat().st_size
    except OSError:
        v = 0
    _CHARS_CACHE[k] = v
    return v


def _count_loc(p: Path) -> int:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0
