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

"""Shared fixtures for the vvaharness test suite.

Isolates the process-global singletons that several modules expose, so the
full suite is order-independent no matter which files run together:
  - util.errlog._path  — the structured error-log sink, redirected to a
    per-test temp file so log() never appends to a real on-disk log.
  - util.tokens.TOKENS — the process-wide token counter, reset (including its
    `_phase`, which TOKENS.reset() does not clear) before and after each test.

Per-backend singletons (sdk/oai/claude_cli `._cfg`, `_client`, drift sets) are
intentionally NOT reset here — each lives in exactly one test module and is
reset locally, so hoisting them would needlessly couple unrelated backends and
force every test module to import all three SDKs.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_errlog_path(tmp_path, monkeypatch):
    from vvaharness.util import errlog
    monkeypatch.setattr(errlog, "_path", tmp_path / "errors.jsonl")


@pytest.fixture(autouse=True)
def _reset_token_counter():
    from vvaharness.util.tokens import TOKENS
    TOKENS.reset()
    TOKENS._phase = "unlabeled"
    yield
    TOKENS.reset()
    TOKENS._phase = "unlabeled"
