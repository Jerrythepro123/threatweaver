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

"""Tests for dynamic ASAN build acceptance and adaptive verification budgets."""
import json
from types import SimpleNamespace

from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import asan_verify


_ASAN_BUILD_LOG = (
    "$ timeout 600 cmake --build build --target server\n"
    "[rc=0]\n"
    "linked with -fsanitize=address\n"
)


_REAL_ASAN_LOG = (
    "$ timeout 12 ./build/parser trigger.bin\n"
    "[rc=-6]\n"
    "==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n"
    "    #0 0x1234 in parse src/parser.cpp:10\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.cpp:10 in parse\n"
)


def test_runtime_confirmation_requires_captured_asan_failure():
    assert asan_verify._actual_asan_trigger(_REAL_ASAN_LOG)
    assert asan_verify._first_crashing_command([_REAL_ASAN_LOG]) == (
        "timeout 12 ./build/parser trigger.bin")


def test_runtime_confirmation_rejects_model_or_generic_asan_text():
    assert not asan_verify._actual_asan_trigger(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow")
    assert not asan_verify._actual_asan_trigger(
        "$ ./build/parser\n[rc=1]\nAddressSanitizer was enabled")


def test_runtime_confirmation_rejects_zero_exit_or_incomplete_report():
    assert not asan_verify._actual_asan_trigger(
        _REAL_ASAN_LOG.replace("[rc=-6]", "[rc=0]"))
    assert not asan_verify._actual_asan_trigger(
        _REAL_ASAN_LOG.replace(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow "
            "src/parser.cpp:10 in parse\n", ""))


def test_build_requires_declared_runnable_artifact(tmp_path):
    assert not asan_verify._asan_build_succeeded(
        [_ASAN_BUILD_LOG], {}, tmp_path)


def test_build_accepts_existing_declared_artifact(tmp_path):
    server = tmp_path / "build" / "bin" / "server"
    server.parent.mkdir(parents=True)
    server.write_bytes(b"executable")

    assert asan_verify._asan_build_succeeded(
        [_ASAN_BUILD_LOG],
        {"verification_artifacts": ["build/bin/server"]},
        tmp_path,
    )


def test_build_rejects_artifact_outside_repo(tmp_path):
    outside = tmp_path.parent / "outside-server"
    outside.write_bytes(b"executable")

    assert not asan_verify._asan_build_succeeded(
        [_ASAN_BUILD_LOG],
        {"verification_artifacts": ["../outside-server"]},
        tmp_path,
    )


def _finding(**updates):
    values = {
        "chunk_id": "chunk",
        "file": "src/parser.cpp",
        "line_start": 10,
        "line_end": 12,
        "vuln_class": VulnClass.HEAP_OVERFLOW,
        "title": "Parser write exceeds allocation",
        "description": "An unchecked length reaches a buffer write.",
        "code_snippet": "buffer[index] = value;",
        "confidence": 0.9,
    }
    values.update(updates)
    return Finding(**values)


def _ctx(tmp_path):
    return ContextPackage(repo_root=str(tmp_path), language="c-cpp")


def test_long_cross_component_chain_has_higher_complexity(tmp_path):
    simple = _finding()
    complex_finding = _finding(
        title="Remote server race reaches backend use-after-free",
        exploit_scenario="HTTP request -> queue -> callback -> worker -> GPU backend -> sink",
        preconditions=["server enabled", "concurrent stream", "model loaded"],
    )

    assert asan_verify._chain_complexity(simple, _ctx(tmp_path)) == 1
    assert asan_verify._chain_complexity(complex_finding, _ctx(tmp_path)) == 5


def test_adaptive_budget_uses_model_estimate(tmp_path, monkeypatch):
    monkeypatch.setattr(asan_verify, "agentic", lambda *a, **k: json.dumps({
        "complexity": 4,
        "estimated_seconds": 1600,
        "recommended_turns": 36,
        "recommended_budget_usd": 13.0,
        "chain_factors": ["server startup", "multi-hop callback chain"],
        "rationale": "Complex server path",
    }))
    block = SimpleNamespace(
        adaptive_timeout=True,
        per_bug_timeout=300,
        min_per_bug_timeout=300,
        max_per_bug_timeout=1800,
        min_repro_turns=8,
        max_repro_turns=40,
        min_repro_budget_usd=1.0,
        max_repro_budget_usd=15.0,
        estimate_timeout=30,
        estimate_max_turns=2,
        estimate_max_budget_usd=0.1,
        max_turns=24,
        max_budget_usd=15.0,
    )
    cfg = SimpleNamespace(
        step6_verify=SimpleNamespace(asan=block),
        models=SimpleNamespace(verify="test-model"),
    )

    budget = asan_verify._adaptive_budget(
        _finding(), _ctx(tmp_path), cfg, tmp_path, idx=1)

    assert budget.timeout == 1600
    assert budget.max_turns == 36
    assert budget.max_budget_usd == 13.0
    assert budget.complexity == 4
    saved = json.loads((tmp_path / "time-estimate.json").read_text())
    assert saved["timeout_seconds"] == 1600


def test_model_complexity_cannot_underallocate_resources(tmp_path, monkeypatch):
    monkeypatch.setattr(asan_verify, "agentic", lambda *a, **k: json.dumps({
        "complexity": 5,
        "estimated_seconds": 300,
        "recommended_turns": 8,
        "recommended_budget_usd": 1.0,
        "rationale": "Long indirect chain",
    }))
    block = SimpleNamespace(
        adaptive_timeout=True,
        per_bug_timeout=300,
        min_per_bug_timeout=300,
        max_per_bug_timeout=1800,
        min_repro_turns=8,
        max_repro_turns=40,
        min_repro_budget_usd=1.0,
        max_repro_budget_usd=15.0,
        estimate_timeout=30,
        estimate_max_turns=2,
        estimate_max_budget_usd=0.1,
        max_turns=24,
        max_budget_usd=15.0,
    )
    cfg = SimpleNamespace(
        step6_verify=SimpleNamespace(asan=block),
        models=SimpleNamespace(verify="test-model"),
    )

    budget = asan_verify._adaptive_budget(
        _finding(), _ctx(tmp_path), cfg, tmp_path, idx=1)

    assert budget.timeout == 1800
    assert budget.max_turns == 40
    assert budget.max_budget_usd == 15.0
