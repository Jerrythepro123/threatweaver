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

"""Exit code when validation selects no validatable findings.

An idempotent re-run after every finding is already validated must succeed (0),
not report failure; only a repo with no remediation DTOs at all is an error (1).
"""

from vvaharness.validation.cli._run import _empty_selection_rc


def _write_dto(repo, slug="01_finding"):
    d = repo / "security-remediation" / slug
    d.mkdir(parents=True)
    (d / "remediate_report.json").write_text("{}")


def test_zero_when_dtos_exist_but_none_validatable(tmp_path):
    # DTOs are present (e.g. all already `validated`) -> nothing to do -> success.
    _write_dto(tmp_path)
    assert _empty_selection_rc(tmp_path) == 0


def test_one_when_no_remediation_dtos_at_all(tmp_path):
    assert _empty_selection_rc(tmp_path) == 1
