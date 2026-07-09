# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import functools
import typing as t

import attrs
import click

_P = t.ParamSpec("_P")
_T = t.TypeVar("_T")
F = t.TypeVar("F", bound=t.Callable[..., t.Any])


def unasync(func: t.Callable[_P, t.Coroutine[t.Any, t.Any, _T]]) -> t.Callable[_P, _T]:
    """Turn an async function into a blocking one."""

    @functools.wraps(func)
    def wrapper(*args: _P.args, **kwds: _P.kwargs) -> _T:
        return asyncio.run(func(*args, **kwds))

    return wrapper


_R = t.TypeVar("_R")


@attrs.frozen
class collect_params(t.Generic[_P, _T]):
    """`collect_params(f)(g)(*args, **kwds)` is equivalent to `g(f(*args, **kwds))`."""

    collect: t.Callable[_P, _T]

    def __call__(self, func: t.Callable[[_T], _R]) -> t.Callable[_P, _R]:
        @functools.wraps(func)
        def wrapper(*args: _P.args, **kwds: _P.kwargs) -> _R:
            return func(self.collect(*args, **kwds))

        return wrapper


def add_options(options: t.Sequence[click.Parameter]) -> t.Callable[[F], F]:
    """A decorator to manually add a list/tuple of Click Options."""

    def decorator(f: F) -> F:
        # If 'f' isn't a click.Command yet, we initialize the params list
        if not hasattr(f, "__click_params__"):
            f.__click_params__ = []  # type: ignore

        f.__click_params__.extend(options)  # type: ignore
        return f

    return decorator
