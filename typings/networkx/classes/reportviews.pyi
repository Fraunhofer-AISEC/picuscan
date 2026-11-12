# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Iterator
from typing import Generic, TypeVar

_T = TypeVar("_T")

class DiDegreeView(Generic[_T]):
    def __iter__(self) -> Iterator[tuple[_T, int]]: ...

class InDegreeView(DiDegreeView[_T]): ...
