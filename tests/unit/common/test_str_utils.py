# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import pytest

from picuscan.misc.strutils import join


class A:
    def __str__(self):
        return "foo"

    def __bytes__(self):
        return b"bar"


JOIN_TESTS = [
    ([1, 2, 3], ", ", "1, 2, 3"),
    ([1, 2, 3], b", ", b"1, 2, 3"),
    ([Path("/usr")], "", "/usr"),
    ([Path("/usr")], b"", b"/usr"),
    ([A()], "", "foo"),
    ([A()], b"", b"bar"),
]


@pytest.mark.parametrize(["iterable", "sep", "expected"], JOIN_TESTS)
def test_join(iterable: Iterable[object], sep: str | bytes, expected: str | bytes):
    assert join(iterable, sep) == expected
