# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Regression coverage for the detection-only scan command."""

import inspect

from vvaharness.orchestrator.scan import scan_repo


def test_scan_repo_does_not_invoke_remediation_or_validation():
    source = inspect.getsource(scan_repo)
    assert "_run_remediation(" not in source
    assert "_run_validation(" not in source
    assert "total=11" not in source
