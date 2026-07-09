# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import IO, Any, Callable, Iterable

__all__ = ("parse",)

_DictConstructor = Callable[[Iterable[tuple[object, object]]], Any]

def parse(xml_input: str | bytes | IO[bytes], *, dict_constructor: _DictConstructor = ...) -> Any: ...
