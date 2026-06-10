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

"""
Process-wide token accounting shared by every model backend (cli + sdk).

Both backends call TOKENS.add(usage_dict) so ScanMetrics sees one unified
total regardless of how each step reached the model.

Per-phase buckets: the orchestrator wraps each step in `with TOKENS.phase("sN")`.
Phases never overlap (s4/s6 thread pools run inside one phase), so a single
global current-phase string is sufficient.
"""
from __future__ import annotations
import threading
from collections import defaultdict
from contextlib import contextmanager


def _bucket() -> dict:
    return {"prompt": 0, "completion": 0, "cache_read": 0,
            "cache_write": 0, "calls": 0}


class _TokenCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._phase = "unlabeled"
        self.prompt = 0
        self.completion = 0
        self.calls = 0
        self.calls_with_usage = 0
        self.by_phase: dict[str, dict] = defaultdict(_bucket)

    @contextmanager
    def phase(self, name: str):
        prev, self._phase = self._phase, name
        try:
            yield
        finally:
            self._phase = prev

    def add(self, usage: dict | None) -> None:
        with self._lock:
            self.calls += 1
            b = self.by_phase[self._phase]
            b["calls"] += 1
            if not isinstance(usage, dict):
                return
            self.calls_with_usage += 1
            fresh = int(usage.get("input_tokens", 0) or 0)
            cw = int(usage.get("cache_creation_input_tokens", 0) or 0)
            cr = int(usage.get("cache_read_input_tokens", 0) or 0)
            out = int(usage.get("output_tokens", 0) or 0)
            # Headline "prompt" = billable input (fresh + cache-write). cache-read
            # is ~10% cost and tracked separately so it doesn't inflate the total.
            self.prompt += fresh + cw
            self.completion += out
            b["prompt"] += fresh + cw
            b["completion"] += out
            b["cache_read"] += cr
            b["cache_write"] += cw

    def reset(self) -> None:
        with self._lock:
            self.prompt = self.completion = self.calls = self.calls_with_usage = 0
            self.by_phase = defaultdict(_bucket)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "prompt": self.prompt,
                "completion": self.completion,
                "total": self.prompt + self.completion,
                "calls": self.calls,
                "calls_with_usage": self.calls_with_usage,
                "by_phase": {k: dict(v) for k, v in self.by_phase.items()},
            }


TOKENS = _TokenCounter()
