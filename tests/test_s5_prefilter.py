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

"""Tests for the stage-5 C/C++ memory-safety scope gate."""
from types import SimpleNamespace

import pytest

from vvaharness.models import ContextPackage, Finding, VulnClass
from vvaharness.pipeline.stages import s5_prefilter


def _finding(file: str, vuln_class: VulnClass) -> Finding:
    return Finding(
        chunk_id="chunk", file=file, line_start=10, line_end=11,
        vuln_class=vuln_class, title="finding", description="description",
        code_snippet="code", source_ref=f"{file}:10", sink_ref=f"{file}:11",
        confidence=0.9,
    )


def _run(*findings: Finding, allowed_classes=None, asan=None):
    ctx = ContextPackage(
        repo_root="/repo", language="c-cpp",
        all_files=[finding.file for finding in findings],
    )
    cfg = SimpleNamespace(
        step5_prefilter=SimpleNamespace(
            min_pre_confidence=0.0, require_evidence=False,
            allowed_classes=allowed_classes),
        step6_verify=SimpleNamespace(asan=asan),
        step7_dedup=SimpleNamespace(
            line_tolerance=10, pre_verify_threshold=0, semantic=False),
    )
    return s5_prefilter.run(list(findings), ctx, cfg)


@pytest.mark.parametrize("vuln_class", [
    VulnClass.UAF,
    VulnClass.HEAP_OVERFLOW,
    VulnClass.STACK_OVERFLOW,
    VulnClass.FMT_STRING,
    VulnClass.INT_OVERFLOW,
    VulnClass.TYPE_CONFUSION,
])
def test_keeps_low_level_memory_findings_in_c_cpp(vuln_class):
    finding = _finding("src/parser.cpp", vuln_class)

    kept, dropped = _run(finding)

    assert kept == [finding]
    assert dropped == []


@pytest.mark.parametrize("file", [
    "src/parser.c", "src/parser.cc", "src/parser.CPP", "include/parser.h",
    "include\\parser.hpp",
])
def test_recognizes_c_cpp_sources_and_headers(file):
    finding = _finding(file, VulnClass.HEAP_OVERFLOW)

    kept, dropped = _run(finding)

    assert kept == [finding]
    assert dropped == []


def test_drops_memory_finding_outside_c_cpp():
    finding = _finding("src/parser.py", VulnClass.HEAP_OVERFLOW)

    kept, dropped = _run(finding)

    assert kept == []
    assert dropped[0].detail == "not a C/C++ source or header file"


def test_drops_non_memory_finding_in_c_cpp():
    finding = _finding("src/parser.cpp", VulnClass.INJECTION)

    kept, dropped = _run(finding)

    assert kept == []
    assert dropped[0].detail == "vulnerability class not enabled by stage-5 policy"


@pytest.mark.parametrize("vuln_class", [
    VulnClass.RACE,
    VulnClass.INJECTION,
    VulnClass.DESERIALIZATION,
    VulnClass.LOGIC,
    VulnClass.INFO_LEAK,
    VulnClass.OTHER,
])
def test_configured_policy_keeps_non_memory_c_cpp_findings(vuln_class):
    finding = _finding("src/parser.cpp", vuln_class)

    kept, dropped = _run(finding, allowed_classes=[vuln_class.value])

    assert kept == [finding]
    assert dropped == []


def test_required_asan_policy_drops_class_not_selected_for_runtime_verification():
    finding = _finding("src/parser.cpp", VulnClass.LOGIC)
    asan = SimpleNamespace(
        enabled=True, all_classes=False,
        classes=[VulnClass.HEAP_OVERFLOW.value],
    )

    kept, dropped = _run(
        finding, allowed_classes=[VulnClass.LOGIC.value], asan=asan)

    assert kept == []
    assert len(dropped) == 1
    assert dropped[0].reason == "EXCLUDED"
    assert dropped[0].detail == (
        "vulnerability class not eligible for required ASAN verification")


def test_required_asan_policy_keeps_explicitly_selected_class():
    finding = _finding("src/parser.cpp", VulnClass.OTHER)
    asan = SimpleNamespace(
        enabled=True, all_classes=False, classes=[VulnClass.OTHER.value],
    )

    kept, dropped = _run(
        finding, allowed_classes=[VulnClass.OTHER.value], asan=asan)

    assert kept == [finding]
    assert dropped == []


def test_invalid_configured_class_fails_loudly():
    finding = _finding("src/parser.cpp", VulnClass.LOGIC)

    with pytest.raises(ValueError, match="invalid step5_prefilter.allowed_classes"):
        _run(finding, allowed_classes=["not-a-real-class"])


def test_run_reports_filter_phase_progress(capsys):
    finding = _finding("src/parser.cpp", VulnClass.HEAP_OVERFLOW)

    kept, dropped = _run(finding)

    assert kept == [finding]
    assert dropped == []
    stderr = capsys.readouterr().err
    assert "[s5-progress] START candidates=1" in stderr
    assert "[s5-progress] POLICY completed=1/1 kept=1 dropped=0" in stderr
    assert "[s5-progress] STRUCTURAL-DEDUP input=1 kept=1 dropped=0" in stderr
    assert "[s5-progress] DONE input=1 kept=1 dropped=0" in stderr
