# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import typing as t


async def alist[T](iterable: t.AsyncIterable[T], /) -> list[T]:
    """Collect the members of `iterable` into a list."""
    result: list[T] = []
    async for x in iterable:
        result.append(x)
    return result


async def afrozenset[T](iterable: t.AsyncIterable[T], /) -> frozenset[T]:
    """Collect the members of `iterable` into a frozen set."""
    return frozenset(await aset(iterable))


async def aset[T](iterable: t.AsyncIterable[T], /) -> set[T]:
    """Collect the members of `iterable` into a set."""
    result: set[T] = set()
    async for x in iterable:
        result.add(x)
    return result


async def atuple[T](iterable: t.AsyncIterable[T], /) -> tuple[T, ...]:
    """Collect the members of `iterable` into a tuple."""
    return tuple(await alist(iterable))


async def adict[K, V](iterable: t.AsyncIterable[tuple[K, V]], /) -> dict[K, V]:
    """Collect the key-value pairs of `iterable` into a dictionary."""
    result: dict[K, V] = {}
    async for k, v in iterable:
        result[k] = v
    return result


async def noop() -> None:
    """A no-op coroutine."""


@t.overload
def gather[T](
    iterable: t.Iterable[t.Awaitable[T]], *, return_exceptions: t.Literal[False] = ...
) -> t.Awaitable[t.Sequence[T]]: ...


@t.overload
def gather[T](
    iterable: t.Iterable[t.Awaitable[T]], *, return_exceptions: bool
) -> t.Awaitable[t.Sequence[T | BaseException]]: ...


def gather[T](
    iterable: t.Iterable[t.Awaitable[T]], *, return_exceptions: bool = False
) -> t.Awaitable[t.Sequence[T | BaseException]]:
    """This is just a wrapper around `asyncio.gather` that provides better type
    safety in some cases."""
    return asyncio.gather(*iterable, return_exceptions=return_exceptions)
