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

"""Security regressions for vvaharness.orchestrator.batch — inline-credential
scrubbing in logs/summaries, and rejection of option-shaped clone refs."""
from __future__ import annotations
import pytest

from vvaharness.orchestrator import batch


def test_scrub_url_secrets_masks_inline_userinfo():
    s = "git clone https://x-access-token:ghp_SECRET@github.com/o/r.git failed"
    out = batch._scrub_url_secrets(s)
    assert "ghp_SECRET" not in out
    assert "x-access-token" not in out
    assert "https://***@github.com/o/r.git" in out


def test_parse_repo_file_rejects_option_shaped_ref(tmp_path):
    # A ref beginning with "-" would be consumed by `git clone` as an option
    # (e.g. --upload-pack=…) — it must be rejected up front, not cloned.
    lst = tmp_path / "repos.txt"
    lst.write_text("app1,repo1,--upload-pack=touch /tmp/x\n", encoding="utf-8")
    with pytest.raises(ValueError) as ei:
        batch._parse_repo_file(lst)
    assert "may not start with '-'" in str(ei.value)
