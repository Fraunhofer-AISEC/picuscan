# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from collections.abc import Container
from fnmatch import fnmatchcase


class GlobSet(Container[t.AnyStr]):
    """
    A set of file path patterns.

    Example usage:
    ```python
    globset = GlobSet(["*.c"])
    assert "foo.c" in globset
    assert "bar.cpp" not in globset
    ```
    """

    def __init__(self, rules: t.Iterable[t.AnyStr], /):
        self._rules: frozenset[t.AnyStr] = frozenset(rules)

    def __contains__(self, x: object, /) -> bool:
        return any(fnmatchcase(x, rule) for rule in self._rules if isinstance(x, type(rule)))

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}([{', '.join(map(repr, self._rules))}])"
