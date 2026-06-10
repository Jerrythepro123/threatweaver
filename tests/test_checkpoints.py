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

"""Unit tests for vvaharness.orchestrator.checkpoints — the restricted
unpickler: every legitimate payload must round-trip (no --resume regression),
and a tampered checkpoint referencing a disallowed callable must be refused
(no code execution) rather than deserialised.
"""
from __future__ import annotations
import os
import pickle

import pytest

from vvaharness.orchestrator import checkpoints as ck
from vvaharness.models import (ContextPackage, ThreatModel, TaskManifest,
                               Finding, FinalReport, RankedFinding, Severity)

RID = "testrun"


def _finding() -> Finding:
    return Finding(chunk_id="c1", file="a.py", line_start=1, line_end=2,
                   vuln_class="other", title="t", description="d",
                   code_snippet="x=1", confidence=0.5)


@pytest.mark.parametrize("step,obj", [
    ("s1", ContextPackage(repo_root="/r", language="python",
                          all_files=["a.py"], notes="n")),
    ("s2", ThreatModel(system_context="sc", open_questions=["q"])),
    ("s3", TaskManifest(chunks=[], rationale="why")),
    ("s4", [_finding()]),
    ("s8", FinalReport(repo_root="/r", summary="s", raw_findings_count=1,
                       chains=[],
                       findings=[RankedFinding(finding=_finding(),
                                               severity=Severity.LOW,
                                               exploitability_notes="e")])),
])
def test_checkpoint_roundtrips_legit_payloads(tmp_path, step, obj):
    ck.save_ckpt(tmp_path, RID, step, obj)
    got = ck.load_ckpt(tmp_path, RID, step)
    assert got is not None and type(got) is type(obj)


def test_checkpoint_refuses_malicious_payload_no_code_exec(tmp_path, capsys):
    marker = tmp_path / "PWNED"

    class _Evil:
        def __reduce__(self):
            return (os.system, (f"touch {marker}",))

    with open(ck._ckpt_path(tmp_path, RID, "s7"), "wb") as fh:
        pickle.dump(_Evil(), fh)

    result = ck.load_ckpt(tmp_path, RID, "s7")

    assert result is None                # refused → stage re-runs
    assert not marker.exists()           # the gadget never executed
    assert "untrusted" in capsys.readouterr().err
