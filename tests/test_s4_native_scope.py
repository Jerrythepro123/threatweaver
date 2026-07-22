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

"""Regression tests for the native-language guard at the s4 boundary."""

from vvaharness.models import Chunk
from vvaharness.pipeline.stages import s4_deepdive


def test_s4_native_guard_filters_mixed_chunks_and_drops_empty_chunks():
    mixed = Chunk(
        id="mixed",
        files=["src/server.cpp", "web/client.ts", "scripts/build.py"],
        languages=["c-cpp", "typescript", "python"],
        hypothesis="mixed",
    )
    non_native = Chunk(
        id="web",
        files=["web/client.ts"],
        languages=["typescript"],
        hypothesis="web",
    )

    scoped = s4_deepdive._native_only_chunks([mixed, non_native])

    assert [chunk.id for chunk in scoped] == ["mixed"]
    assert scoped[0].files == ["src/server.cpp"]
    assert scoped[0].languages == ["c-cpp"]

    # Checkpoint DTOs are not mutated while enforcing the resumed-scan guard.
    assert mixed.files == [
        "src/server.cpp", "web/client.ts", "scripts/build.py"
    ]
    assert non_native.files == ["web/client.ts"]


def test_s4_native_guard_recognizes_headers_and_windows_paths():
    chunk = Chunk(
        id="headers",
        files=["include\\server.hpp", "include/detail.h", "README.md"],
        hypothesis="headers",
    )

    scoped = s4_deepdive._native_only_chunks([chunk])

    assert scoped[0].files == ["include\\server.hpp", "include/detail.h"]
