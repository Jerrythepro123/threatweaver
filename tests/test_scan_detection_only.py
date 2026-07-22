# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""Regression coverage for the detection-only scan command."""

import inspect

from vvaharness.orchestrator.scan import _log_stage456_counts, scan_repo


def test_scan_repo_does_not_invoke_remediation_or_validation():
    source = inspect.getsource(scan_repo)
    assert "_run_remediation(" not in source
    assert "_run_validation(" not in source
    assert "total=11" not in source


def test_scan_repo_checkpoints_static_and_asan_verification_separately():
    source = inspect.getsource(scan_repo)

    assert 'load_ckpt(ckpt_dir, run_id, "s6-static")' in source
    assert 'save_ckpt(ckpt_dir, run_id, "s6-static"' in source
    assert 'load_ckpt(ckpt_dir, run_id, "s6-asan")' in source
    assert 'save_ckpt(ckpt_dir, run_id, "s6-asan"' in source
    assert "s6_verify.run_static(" in source
    assert "s6_verify.run_asan(" in source


def test_standard_stage456_count_snapshot(capsys):
    _log_stage456_counts(
        "dynamic", findings=12, static_confirmed=7, dynamic_confirmed=4)

    assert capsys.readouterr().err.strip() == (
        "[stage456-progress] phase=dynamic findings=12 "
        "static_confirmed=7 dynamic_confirmed=4")
