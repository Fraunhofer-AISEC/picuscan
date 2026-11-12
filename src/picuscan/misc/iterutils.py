# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t


def partition[T](func: t.Callable[[T], object], iterable: t.Iterable[T]) -> tuple[list[T], list[T]]:
    """Partition `iterable` into two lists, where the first list contains the
    elements of `iterable` for which the predicate `func` holds and the second
    contains the rest."""
    a: list[T] = []
    b: list[T] = []
    for o in iterable:
        if func(o):
            a.append(o)
        else:
            b.append(o)
    return a, b
