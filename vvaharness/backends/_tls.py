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

"""Shared TLS-config coercion for the backend clients.

`verify_ssl` is usually a YAML boolean (a real ``bool``), but a value templated
from the environment (e.g. ``${VERIFY_SSL:-false}``) or written as a quoted YAML
scalar arrives as a *string*. A string is truthy, so an un-coerced ``"false"``
would silently leave TLS verification enabled (the backends test ``verify is
False`` / pass the value straight to httpx). ``coerce_verify`` normalises the
common string booleans to a real ``bool`` while leaving any other string — which
is a CA-bundle path — and real bools untouched.
"""
from __future__ import annotations

_TRUE = {"true", "1", "yes", "on"}
_FALSE = {"false", "0", "no", "off"}


def coerce_verify(value):
    """Return ``value`` with string booleans mapped to real ``bool``.

    - ``bool`` / ``None`` → returned unchanged.
    - a string matching a known boolean literal (case-insensitive) → ``bool``.
    - any other string (a CA-bundle path) → returned unchanged.
    """
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _FALSE:
            return False
        if low in _TRUE:
            return True
    return value
