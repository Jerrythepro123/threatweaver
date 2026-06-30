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

"""``StrEnum`` compatibility shim.

``enum.StrEnum`` is Python 3.11+. The project floor is 3.10, so on 3.10 we
provide a minimal backport: members are real ``str`` instances and ``str()`` /
``format()`` yield the member *value* (not ``ClassName.MEMBER``), matching the
3.11 semantics the enums in this package rely on.
"""
from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:  # pragma: no cover - exercised only on Python 3.10
    from enum import Enum

    class StrEnum(str, Enum):
        """Python 3.10 backport of :class:`enum.StrEnum`."""

        __str__ = str.__str__
        __format__ = str.__format__


__all__ = ["StrEnum"]
