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

"""The single seam for writing the VVAHARNESS_* environment the agent config reads."""

from __future__ import annotations

import os


def set_env(key: str, value: str) -> None:
    """Set an VVAHARNESS_* process environment variable."""
    os.environ[key] = value
