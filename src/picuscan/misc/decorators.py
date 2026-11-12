# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import functools
import typing as t

import attrs
import click

F = t.TypeVar("F", bound=t.Callable[..., t.Any])


def unasync[**P, T](func: t.Callable[P, t.Coroutine[t.Any, t.Any, T]]) -> t.Callable[P, T]:
    """Turn an async function into a blocking one."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwds: P.kwargs) -> T:
        return asyncio.run(func(*args, **kwds))

    return wrapper


@attrs.frozen
class collect_params[**P, T]:
    """`collect_params(f)(g)(*args, **kwds)` is equivalent to `g(f(*args, **kwds))`."""

    collect: t.Callable[P, T]

    def __call__[R](self, func: t.Callable[[T], R]) -> t.Callable[P, R]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwds: P.kwargs) -> R:
            return func(self.collect(*args, **kwds))

        return wrapper


def add_options(options: t.Sequence[click.Parameter]) -> t.Callable[[F], F]:
    """A decorator to manually add a list/tuple of Click Options."""

    def decorator(f: F) -> F:
        # If 'f' isn't a click.Command yet, we initialize the params list
        if not hasattr(f, "__click_params__"):
            f.__click_params__ = []  # type: ignore[attr-defined]  # ty: ignore[invalid-assignment]

        f.__click_params__.extend(options)  # type: ignore[attr-defined]  # ty: ignore[missing-attribute]
        return f

    return decorator
