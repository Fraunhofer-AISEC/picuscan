# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import typing as t

_T = t.TypeVar("_T")


async def alist(iterable: t.AsyncIterable[_T], /) -> list[_T]:
    """Collect the members of `iterable` into a list."""
    result: list[_T] = []
    async for x in iterable:
        result.append(x)
    return result


async def afrozenset(iterable: t.AsyncIterable[_T], /) -> frozenset[_T]:
    """Collect the members of `iterable` into a frozen set."""
    return frozenset(await aset(iterable))


async def aset(iterable: t.AsyncIterable[_T], /) -> set[_T]:
    """Collect the members of `iterable` into a set."""
    result: set[_T] = set()
    async for x in iterable:
        result.add(x)
    return result


async def atuple(iterable: t.AsyncIterable[_T], /) -> tuple[_T, ...]:
    """Collect the members of `iterable` into a tuple."""
    return tuple(await alist(iterable))


_K = t.TypeVar("_K")
_V = t.TypeVar("_V")


async def adict(iterable: t.AsyncIterable[tuple[_K, _V]], /) -> dict[_K, _V]:
    """Collect the key-value pairs of `iterable` into a dictionary."""
    result: dict[_K, _V] = {}
    async for k, v in iterable:
        result[k] = v
    return result


async def noop() -> None:
    """A no-op coroutine."""
    pass


@t.overload
def gather(
    iterable: t.Iterable[t.Awaitable[_T]], *, return_exceptions: t.Literal[False] = ...
) -> t.Awaitable[t.Sequence[_T]]: ...


@t.overload
def gather(
    iterable: t.Iterable[t.Awaitable[_T]], *, return_exceptions: bool
) -> t.Awaitable[t.Sequence[_T | BaseException]]: ...


def gather(
    iterable: t.Iterable[t.Awaitable[_T]], *, return_exceptions: bool = False
) -> t.Awaitable[t.Sequence[_T | BaseException]]:
    """This is just a wrapper around `asyncio.gather` that provides better type
    safety in some cases."""
    return asyncio.gather(*iterable, return_exceptions=return_exceptions)
