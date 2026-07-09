# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t

_T = t.TypeVar("_T")


def partition(func: t.Callable[[_T], object], iterable: t.Iterable[_T]) -> tuple[list[_T], list[_T]]:
    """Partition `iterable` into two lists, where the first list contains the
    elements of `iterable` for which the predicate `func` holds and the second
    contains the rest."""
    a: list[_T] = []
    b: list[_T] = []
    for o in iterable:
        if func(o):
            a.append(o)
        else:
            b.append(o)
    return a, b
