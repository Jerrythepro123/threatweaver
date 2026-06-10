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

"""Unit tests for the deterministic dedup helpers in s7_dedup.

Covers overlapping/nested same-file range merging, the "additional call site"
attachment (disjoint-only, so an overlapping re-detection is not counted as a
new site), and de-duplication of the collapsed-location set. Pure functions.
"""
from vvaharness.pipeline.stages import s7_dedup
from vvaharness.models import Finding, VulnClass


def _f(file: str, ls: int, le: int, vc: VulnClass = VulnClass.OTHER) -> Finding:
    return Finding(
        chunk_id="c", file=file, line_start=ls, line_end=le,
        vuln_class=vc, title="t", description="d", code_snippet="x",
        confidence=0.9,
    )


def test_collapse_trivial_merges_overlapping_ranges():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {1: 0}


def test_collapse_trivial_keeps_disjoint_ranges_separate():
    findings = [_f("a.py", 10, 12), _f("a.py", 80, 82)]
    canon = s7_dedup._collapse_trivial(findings, line_tol=3)
    assert canon == {}


def test_attach_duplicates_skips_same_site_overlap():
    findings = [_f("a.py", 10, 20), _f("a.py", 15, 25)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert findings[0].duplicates == []


def test_attach_duplicates_records_disjoint_site():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0}, {1: "dup"})
    assert len(findings[0].duplicates) == 1
    assert findings[0].duplicates[0].file == "b.py"


def test_attach_duplicates_dedupes_identical_locations():
    findings = [_f("a.py", 10, 12), _f("b.py", 50, 52), _f("b.py", 50, 52)]
    s7_dedup._attach_duplicates(findings, {1: 0, 2: 0}, {1: "d", 2: "d"})
    assert len(findings[0].duplicates) == 1
