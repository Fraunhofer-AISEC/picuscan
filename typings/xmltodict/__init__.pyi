# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable, Iterable
from typing import IO, Any, TypeAlias

__all__ = ("parse",)

_DictConstructor: TypeAlias = Callable[[Iterable[tuple[object, object]]], Any]

def parse(xml_input: str | bytes | IO[bytes], *, dict_constructor: _DictConstructor = ...) -> Any: ...
