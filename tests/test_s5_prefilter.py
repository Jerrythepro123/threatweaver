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


def _run(*findings: Finding):
    ctx = ContextPackage(
        repo_root="/repo", language="c-cpp",
        all_files=[finding.file for finding in findings],
    )
    cfg = SimpleNamespace(
        step5_prefilter=SimpleNamespace(
            min_pre_confidence=0.0, require_evidence=False),
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
    assert dropped[0].detail == "not a low-level memory-safety finding"
