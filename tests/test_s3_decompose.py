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

"""Behavioral tests for the taint threat-tag matching helper in s3_decompose.

The helper under test is the ``_threat_for(ep)`` closure inside
``_add_taint_chunks``. It associates a taint chunk with a threat by matching
the threat's ``surface`` against the entry function name on a whole-token /
exact basis. The security-relevant behavior:

  * exact (case-insensitive) name match wins outright;
  * otherwise the FIRST threat sharing a whole alphanumeric TOKEN with the
    function name is chosen;
  * it must NOT match a substring buried inside another token, and it must
    NOT match against the file PATH (over-tagging the coverage metric).

``_threat_for`` is a nested closure and cannot be imported, so we drive it
through the public ``_add_taint_chunks`` entry point and read the resulting
chunk's ``threat_id``.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from vvaharness.models import (
    Chunk,
    ContextPackage,
    EntryPoint,
    ModuleInfo,
    Sink,
    TaskManifest,
    Threat,
    ThreatModel,
)
from vvaharness.pipeline.stages import s3_decompose


# ─────────────────────────────────────────────────────────────────────────────
# Global-state isolation: _count_loc / _count_chars consult a module-level
# byte cache (_CHARS_CACHE). Reset it so test order never matters.
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):
    monkeypatch.setattr(s3_decompose, "_CHARS_CACHE", {}, raising=True)
    yield


def _make_cfg():
    """Minimal cfg with the step3 knobs _add_taint_chunks reads."""
    step3 = SimpleNamespace(
        taint_chunks=True,
        taint_max_hops=8,
        taint_max_chunks=40,
        taint_files_per_hop=5,
        pack_by="loc",
    )
    return SimpleNamespace(step3=step3)


def _threat(tid: str, surface: str) -> Threat:
    return Threat(
        id=tid,
        threat=f"threat {tid}",
        actor="remote_unauth",
        surface=surface,
        asset="user-data",
        impact="high",
        likelihood="likely",
    )


def _ctx_with(threats, *, fn="handle_login", ep_file="app/login.py",
              sink_fn="run_query", repo_root="/nonexistent-repo") -> ContextPackage:
    """ContextPackage with exactly one entry→sink taint path so that
    _add_taint_chunks emits exactly one taint chunk whose threat_id is the
    output of _threat_for(ep)."""
    ep_node = f"{ep_file}::{fn}"
    sink_node = f"{ep_file}::{sink_fn}"
    return ContextPackage(
        repo_root=repo_root,
        language="python",
        call_graph={ep_node: [sink_node]},
        entry_points=[EntryPoint(file=ep_file, function=fn, kind="network",
                                 reachable_from_unauth=True)],
        unsafe_sinks=[Sink(file=ep_file, line=42, function=sink_fn)],
        all_files=[ep_file],
        threat_model=ThreatModel(threats=threats),
    )


def _run(ctx) -> TaskManifest:
    manifest = TaskManifest(chunks=[], rationale="test")
    n = s3_decompose._add_taint_chunks(manifest, ctx, _make_cfg())
    assert n == 1, f"expected exactly one taint chunk, got {n}"
    return manifest


def _taint_chunk(manifest: TaskManifest) -> Chunk:
    taints = [c for c in manifest.chunks if c.id.startswith("taint-")]
    assert len(taints) == 1
    return taints[0]


# ─────────────────────────────────────────────────────────────────────────────
# Sanity: the harness actually produces a taint chunk we can inspect.
# ─────────────────────────────────────────────────────────────────────────────
def test_taint_chunk_is_emitted_and_anchors_entry_function():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    chunk = _taint_chunk(manifest)
    assert chunk.focus_entry_points == ["handle_login"]
    assert "app/login.py" in chunk.files


# ─────────────────────────────────────────────────────────────────────────────
# Exact (case-insensitive) match wins.
# ─────────────────────────────────────────────────────────────────────────────
def test_exact_match_assigns_threat_id():
    manifest = _run(_ctx_with([_threat("T1", "handle_login")]))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_exact_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T7", "Handle_Login")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T7"


def test_exact_match_beats_an_earlier_token_match():
    # T1 shares the "login" token (token match), but T2 is an exact match.
    # Exact must win even though it appears later in the list.
    threats = [_threat("T1", "login"), _threat("T2", "handle_login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


# ─────────────────────────────────────────────────────────────────────────────
# Whole-token match (no exact match available).
# ─────────────────────────────────────────────────────────────────────────────
def test_shared_token_match_when_no_exact():
    # function "handle_login" shares token "login" with surface "login_v2".
    manifest = _run(_ctx_with([_threat("T9", "login_v2")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T9"


def test_first_token_sharing_threat_wins():
    # Both T1 and T2 share a token with handle_login; the FIRST in list wins.
    threats = [_threat("T1", "do_login"), _threat("T2", "handle_request")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T1"


def test_token_match_is_case_insensitive():
    manifest = _run(_ctx_with([_threat("T3", "USER_LOGIN")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T3"


# ─────────────────────────────────────────────────────────────────────────────
# Security-relevant negatives: no substring-in-token, no path matching.
# ─────────────────────────────────────────────────────────────────────────────
def test_substring_inside_a_token_does_not_match():
    # surface "log" is a substring of the token "login" but is NOT a whole
    # token of "handle_login" → must NOT match.
    manifest = _run(_ctx_with([_threat("T5", "log")], fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_reverse_substring_does_not_match():
    # function token "auth" is a substring of surface token "authenticate";
    # token equality fails both directions → no match.
    manifest = _run(_ctx_with([_threat("T6", "authenticate")], fn="auth"))
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_the_file_path_does_not_match():
    # The entry FILE path contains "login" (app/login.py) but the function is
    # "process". A surface equal to a path component must NOT tag the chunk —
    # matching is against the function NAME only, never the path.
    ctx = _ctx_with([_threat("T8", "login")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


def test_surface_matching_path_directory_does_not_match():
    ctx = _ctx_with([_threat("T8", "app")], fn="process",
                    ep_file="app/login.py", sink_fn="run_query")
    manifest = _run(ctx)
    assert _taint_chunk(manifest).threat_id is None


# ─────────────────────────────────────────────────────────────────────────────
# Edge cases.
# ─────────────────────────────────────────────────────────────────────────────
def test_empty_surface_is_skipped():
    # An empty-surface threat is ignored; the real token match still wins.
    threats = [_threat("T1", ""), _threat("T2", "login")]
    manifest = _run(_ctx_with(threats, fn="handle_login"))
    assert _taint_chunk(manifest).threat_id == "T2"


def test_no_threats_yields_none():
    manifest = _run(_ctx_with([]))
    assert _taint_chunk(manifest).threat_id is None


def test_no_matching_threat_yields_none():
    manifest = _run(_ctx_with([_threat("T1", "totally_unrelated")],
                              fn="handle_login"))
    assert _taint_chunk(manifest).threat_id is None


def test_digit_tokens_participate_in_matching():
    # tokens are [a-z0-9]+, so a shared numeric token counts.
    manifest = _run(_ctx_with([_threat("T4", "endpoint_v2")], fn="parse_v2"))
    assert _taint_chunk(manifest).threat_id == "T4"


# ─────────────────────────────────────────────────────────────────────────────
# Cross-check the documented tokenization regex directly so the behavioral
# expectations above are anchored to the same rule the source uses.
# ─────────────────────────────────────────────────────────────────────────────
def test_tokenization_rule_matches_source_intent():
    tok = lambda s: set(re.findall(r"[a-z0-9]+", s.lower()))
    # whole-token overlap exists
    assert tok("handle_login") & tok("login_v2")
    # substring-only does NOT create token overlap
    assert not (tok("handle_login") & tok("log"))
    assert not (tok("auth") & tok("authenticate"))


def test_native_scope_filters_before_chunk_generation_without_mutating_input():
    native_entry = "src/server.cpp::serve"
    native_sink = "src/parser.cc::parse"
    python_entry = "tools/generate.py::main"
    ctx = ContextPackage(
        repo_root="/repo",
        language="python",
        all_files=[
            "src/server.cpp",
            "src/parser.cc",
            "include/server.hpp",
            "tools/generate.py",
            "web/client.ts",
        ],
        modules=[
            ModuleInfo(
                name="server",
                files=["src/server.cpp", "tools/generate.py"],
            ),
            ModuleInfo(name="generator", files=["tools/generate.py"]),
        ],
        entry_points=[
            EntryPoint(
                file="src/server.cpp",
                function="serve",
                kind="network",
                reachable_from_unauth=True,
            ),
            EntryPoint(
                file="tools/generate.py", function="main", kind="cli"
            ),
        ],
        unsafe_sinks=[
            Sink(file="src/parser.cc", line=42, function="memcpy"),
            Sink(file="tools/generate.py", line=7, function="eval"),
        ],
        call_graph={
            native_entry: [native_sink, python_entry],
            python_entry: [native_entry],
        },
        call_graph_files={
            native_entry: ["src/server.cpp:10"],
            native_sink: ["src/parser.cc:42"],
            python_entry: ["tools/generate.py:3"],
        },
    )

    scoped = s3_decompose._native_only_context(ctx)

    assert scoped.language == "c-cpp"
    assert scoped.all_files == [
        "src/server.cpp",
        "src/parser.cc",
        "include/server.hpp",
    ]
    assert [module.name for module in scoped.modules] == ["server"]
    assert scoped.modules[0].files == ["src/server.cpp"]
    assert [entry.file for entry in scoped.entry_points] == ["src/server.cpp"]
    assert [sink.file for sink in scoped.unsafe_sinks] == ["src/parser.cc"]
    assert scoped.call_graph == {native_entry: [native_sink]}
    assert set(scoped.call_graph_files) == {native_entry, native_sink}

    # Reporting and later metrics retain the original full repository scope.
    assert "tools/generate.py" in ctx.all_files
    assert len(ctx.modules) == 2


def test_model_chunk_paths_are_normalized_against_native_scope_only():
    ctx = ContextPackage(
        repo_root="/repo",
        language="typescript",
        all_files=["src/server.cpp", "src/server.h", "web/client.ts"],
    )
    scoped = s3_decompose._native_only_context(ctx)
    manifest = TaskManifest(
        rationale="test",
        chunks=[
            Chunk(
                id="chunk-01",
                files=["src/server.cpp", "web/client.ts"],
                hypothesis="server request parsing",
            )
        ],
    )

    s3_decompose._normalize_chunk_files(manifest, scoped)

    assert manifest.chunks[0].files == ["src/server.cpp"]
    assert "web/client.ts" not in scoped.to_prompt_block()
