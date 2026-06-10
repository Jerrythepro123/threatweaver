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

"""Inbound source redaction in s4 (_redact_source).

Source code is packed verbatim into the s4 deep-dive prompt. A provider /
gateway PII guard rejects requests that contain live PII (e.g. US SSNs), so
the code MUST be scrubbed before it leaves the process. Historically this hook
masked card numbers only; these tests lock in that SSNs, credentials and keys
are masked too, and that line structure is preserved.

All values below are synthetic test data — the canonical public test SSN
078-05-1120 and well-known test PAN 4111-1111-1111-1111. Offline/deterministic.
"""
from vvaharness.pipeline.stages.s4_deepdive import _redact_source


def test_masks_ssn():
    out = _redact_source("user.ssn = '078-05-1120'  # lookup\n", "u.py")
    assert "078-05-1120" not in out
    assert "[REDACTED-SSN]" in out


def test_masks_pan_and_ssn_together():
    src = "PAN = '4111111111111111'\nSSN = '078-05-1120'\n"
    out = _redact_source(src, "x.py")
    assert "078-05-1120" not in out
    assert "4111111111111111" not in out


def test_masks_credential_assignment():
    out = _redact_source('api_key = "abcdef123456789"\n', "cfg.py")
    assert "abcdef123456789" not in out
    assert "[REDACTED-SECRET]" in out


def test_preserves_line_count():
    # Finding line numbers depend on the line count being unchanged.
    src = "line one\nssn 078-05-1120 here\nline three\n"
    out = _redact_source(src, "x.py")
    assert len(out.splitlines()) == len(src.splitlines())


def test_clean_code_unchanged():
    src = "def add(a, b):\n    return a + b\n"
    assert _redact_source(src, "x.py") == src


def test_invalid_ssn_left_untouched():
    # area 666 is not a valid SSN -> must not be masked (precision).
    src = "ref = '666-05-1120'\n"
    assert _redact_source(src, "x.py") == src
