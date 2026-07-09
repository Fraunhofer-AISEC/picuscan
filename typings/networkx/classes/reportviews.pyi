# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Generic, Iterator, TypeVar

_T = TypeVar("_T")

class DiDegreeView(Generic[_T]):
    def __iter__(self) -> Iterator[tuple[_T, int]]: ...

class InDegreeView(DiDegreeView[_T]): ...
