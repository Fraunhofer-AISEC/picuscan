# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from os import PathLike

StrBytesPath = str | bytes | PathLike[str] | PathLike[bytes]
StrPath = str | PathLike[str]

FileDescriptorOrPath = int | StrBytesPath

OpenTextMode = t.Literal["r", "w"]
OpenBinaryMode = t.Literal["rb", "wb"]

JsonNumber = int | float
JsonValue = JsonNumber | str | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


def is_str(x: object) -> t.TypeGuard[str]:
    return isinstance(x, str)


def is_list(x: object) -> t.TypeGuard[list[object]]:
    return isinstance(x, list)


def is_tuple(x: object) -> t.TypeGuard[tuple[object, ...]]:
    return isinstance(x, tuple)


_T = t.TypeVar("_T")


def is_tuple_with(x: object, elements: t.Callable[[object], t.TypeGuard[_T]]) -> t.TypeGuard[tuple[_T, ...]]:
    return is_tuple(x) and all(map(elements, x))


def is_set(x: object) -> t.TypeGuard[set[object]]:
    return isinstance(x, set)


def is_frozenset(x: object) -> t.TypeGuard[frozenset[object]]:
    return isinstance(x, frozenset)


def is_dict(x: object) -> t.TypeGuard[dict[object, object]]:
    return isinstance(x, dict)
