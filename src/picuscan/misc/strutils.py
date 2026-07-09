# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
import os
import shlex
import typing as t


class _Shell(enum.Enum):
    SHELL = enum.auto()


SHELL: t.Final[t.Literal[_Shell.SHELL]] = _Shell.SHELL


@t.overload
def join(iterable: t.Iterable[object], sep: t.AnyStr) -> t.AnyStr: ...


@t.overload
def join(iterable: t.Iterable[object], sep: t.Literal[_Shell.SHELL]) -> str: ...


def join(iterable: t.Iterable[object], sep: str | bytes | t.Literal[_Shell.SHELL]) -> str | bytes:
    """
    Join the members of `iterable`, using the seperator `sep`. If a
    value in `iterable` is not a (byte) string, it will be automatically
    converted.
    @sep: If the passed value is `SHELL`, treat `iterable` as a split
    shell command and use `shlex.join()` to concatenate it.
    """
    if isinstance(sep, str):
        return sep.join(map(_str, iterable))
    elif isinstance(sep, bytes):
        return sep.join(map(_bytes, iterable))
    else:
        return shlex.join(map(_str, iterable))


def _str(o: object) -> str:
    try:
        o = os.fspath(o)  # type: ignore
    except TypeError:
        pass
    if isinstance(o, bytes):
        return o.decode()
    return str(o)


def _bytes(o: object) -> bytes:
    if isinstance(o, t.SupportsBytes):
        return bytes(o)
    s = str(o)
    return s.encode()


def snake_case(s: str) -> str:
    """Convert `s` to `snake_case`."""
    buf: list[str] = list()
    last_char = None
    for c in s:
        if c.isupper():
            c = c.lower()
            if buf and last_char != "_":
                buf.append("_")
        elif c == "-":
            c = "_"
        buf.append(c)
        last_char = c
    return "".join(buf)


_P = t.ParamSpec("_P")


class LazyString:
    """A string-like object. Its string representation is computed on access."""

    __slots__ = ("_initializer", "_cache")

    def __init__(self, initializer: t.Callable[_P, str], *args: _P.args, **kwds: _P.kwargs):
        self._initializer = initializer, args, kwds
        self._cache: str | None = None

    def __str__(self) -> str:
        if self._cache is None:
            initializer, args, kwds = self._initializer
            self._cache = initializer(*args, **kwds)
            # We don't need this anymore. Delete it so it can be garbage collected.
            del self._initializer
        return self._cache

    def __repr__(self) -> str:
        return repr(str(self))

    def __hash__(self) -> int:
        return hash(str(self))
