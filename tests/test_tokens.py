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

"""Unit tests for vvaharness.util.tokens process-wide token accounting."""
import pytest

from vvaharness.util import tokens as tokens_mod
from vvaharness.util.tokens import TOKENS, _TokenCounter


@pytest.fixture(autouse=True)
def _reset_global_tokens():
    """Isolate the process-wide TOKENS singleton across the full suite."""
    TOKENS.reset()
    # _phase is not cleared by reset(); restore it explicitly so test order
    # can never leak a non-default current phase into another test.
    TOKENS._phase = "unlabeled"
    yield
    TOKENS.reset()
    TOKENS._phase = "unlabeled"


def _usage(inp=0, out=0, cw=0, cr=0):
    return {
        "input_tokens": inp,
        "output_tokens": out,
        "cache_creation_input_tokens": cw,
        "cache_read_input_tokens": cr,
    }


def test_add_basic_accumulation():
    c = _TokenCounter()
    c.add(_usage(inp=100, out=50))
    assert c.prompt == 100
    assert c.completion == 50
    assert c.calls == 1
    assert c.calls_with_usage == 1


def test_add_accumulates_across_multiple_calls():
    c = _TokenCounter()
    c.add(_usage(inp=10, out=5))
    c.add(_usage(inp=20, out=7))
    assert c.prompt == 30
    assert c.completion == 12
    assert c.calls == 2
    assert c.calls_with_usage == 2


def test_prompt_includes_cache_write_but_not_cache_read():
    # Headline prompt = fresh input + cache-write. cache-read is tracked
    # separately and must NOT inflate the prompt total.
    c = _TokenCounter()
    c.add(_usage(inp=100, out=10, cw=40, cr=1000))
    assert c.prompt == 140  # 100 fresh + 40 cache-write
    assert c.completion == 10
    snap = c.snapshot()
    bucket = snap["by_phase"]["unlabeled"]
    assert bucket["prompt"] == 140
    assert bucket["cache_write"] == 40
    assert bucket["cache_read"] == 1000


def test_add_none_is_safe_counts_call_only():
    c = _TokenCounter()
    c.add(None)
    assert c.calls == 1
    assert c.calls_with_usage == 0
    assert c.prompt == 0
    assert c.completion == 0
    # The phase bucket records the call even without usage.
    assert c.by_phase["unlabeled"]["calls"] == 1


def test_add_non_dict_is_safe():
    c = _TokenCounter()
    c.add("not-a-dict")  # type: ignore[arg-type]
    c.add(12345)  # type: ignore[arg-type]
    assert c.calls == 2
    assert c.calls_with_usage == 0
    assert c.prompt == 0


def test_add_missing_fields_treated_as_zero():
    c = _TokenCounter()
    c.add({})  # empty dict is a dict -> counts as usage but all zeros
    assert c.calls_with_usage == 1
    assert c.prompt == 0
    assert c.completion == 0


def test_add_none_valued_fields_are_none_safe():
    # Anthropic usage dicts often carry None for cache fields.
    c = _TokenCounter()
    c.add({
        "input_tokens": None,
        "output_tokens": 5,
        "cache_creation_input_tokens": None,
        "cache_read_input_tokens": None,
    })
    assert c.prompt == 0
    assert c.completion == 5
    assert c.calls_with_usage == 1


def test_phase_context_routes_to_named_bucket():
    c = _TokenCounter()
    with c.phase("s4"):
        c.add(_usage(inp=10, out=2))
    snap = c.snapshot()
    assert snap["by_phase"]["s4"]["prompt"] == 10
    assert snap["by_phase"]["s4"]["completion"] == 2
    assert snap["by_phase"]["s4"]["calls"] == 1
    assert "unlabeled" not in snap["by_phase"]


def test_phase_restores_previous_phase():
    c = _TokenCounter()
    assert c._phase == "unlabeled"
    with c.phase("s6"):
        assert c._phase == "s6"
    assert c._phase == "unlabeled"


def test_phase_restores_on_exception():
    c = _TokenCounter()
    with pytest.raises(ValueError):
        with c.phase("s9"):
            raise ValueError("boom")
    assert c._phase == "unlabeled"


def test_phase_nesting_restores_intermediate():
    c = _TokenCounter()
    with c.phase("outer"):
        with c.phase("inner"):
            c.add(_usage(inp=3))
        assert c._phase == "outer"
        c.add(_usage(inp=4))
    snap = c.snapshot()
    assert snap["by_phase"]["inner"]["prompt"] == 3
    assert snap["by_phase"]["outer"]["prompt"] == 4


def test_global_totals_aggregate_across_phases():
    c = _TokenCounter()
    with c.phase("a"):
        c.add(_usage(inp=10, out=1))
    with c.phase("b"):
        c.add(_usage(inp=20, out=2))
    assert c.prompt == 30
    assert c.completion == 3
    assert c.calls == 2


def test_snapshot_shape_and_total():
    c = _TokenCounter()
    c.add(_usage(inp=100, out=50))
    c.add(None)
    snap = c.snapshot()
    assert snap["prompt"] == 100
    assert snap["completion"] == 50
    assert snap["total"] == 150
    assert snap["calls"] == 2
    assert snap["calls_with_usage"] == 1
    assert set(snap.keys()) == {
        "prompt", "completion", "total", "calls",
        "calls_with_usage", "by_phase",
    }


def test_snapshot_by_phase_is_a_copy():
    c = _TokenCounter()
    c.add(_usage(inp=5))
    snap = c.snapshot()
    snap["by_phase"]["unlabeled"]["prompt"] = 99999
    # Mutating the snapshot must not corrupt the live counter.
    assert c.by_phase["unlabeled"]["prompt"] == 5


def test_reset_clears_all_totals_and_phases():
    c = _TokenCounter()
    with c.phase("s4"):
        c.add(_usage(inp=10, out=2))
    c.add(None)
    c.reset()
    assert c.prompt == 0
    assert c.completion == 0
    assert c.calls == 0
    assert c.calls_with_usage == 0
    assert c.snapshot()["by_phase"] == {}


def test_module_singleton_is_token_counter():
    assert isinstance(TOKENS, _TokenCounter)
    assert tokens_mod.TOKENS is TOKENS


def test_singleton_add_and_snapshot():
    # Exercise the actual process-wide singleton (reset by autouse fixture).
    TOKENS.add(_usage(inp=42, out=8, cw=2, cr=500))
    snap = TOKENS.snapshot()
    assert snap["prompt"] == 44  # 42 + 2 cache-write
    assert snap["completion"] == 8
    assert snap["total"] == 52
    assert snap["by_phase"]["unlabeled"]["cache_read"] == 500
