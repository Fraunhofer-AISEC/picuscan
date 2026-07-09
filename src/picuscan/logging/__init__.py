# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import functools
import itertools
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Mapping, ParamSpec, TypeVar

from picuscan.misc.strutils import LazyString

from ._ansi import ANSIFormatter
from ._tqdm import TqdmStreamHandler

get_logger = logging.getLogger


def install() -> None:
    """Configure the logging system so that the output is colorful, and
    it plays nicely with the `tqdm` library."""
    handler = TqdmStreamHandler()
    if handler.stream.isatty():
        handler.setFormatter(ANSIFormatter())
    logging.basicConfig(handlers=[handler])


_P = ParamSpec("_P")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class Tracer:
    """This is a helper class for tracing function calls. See the
    `trace()` and `trace_async()` methods for more details."""

    logger: logging.Logger
    level: int = field(default=logging.DEBUG, kw_only=True)

    def trace(self, func: Callable[_P, _T]) -> Callable[_P, _T]:
        """This is a decorator which logs all calls to the decorated
        function. The log message includes the parameters as well as the
        return value."""

        @functools.wraps(func)
        def wrapper(*args: _P.args, **kwds: _P.kwargs) -> _T:
            call_str = LazyString(_format_call, func, args, kwds)
            self.logger.log(self.level, "Calling %s", call_str)
            value = func(*args, **kwds)
            self.logger.log(self.level, "Returning from %s = %s", call_str, value)
            return value

        return wrapper

    def trace_async(self, func: Callable[_P, Awaitable[_T]]) -> Callable[_P, Awaitable[_T]]:
        """Like `trace()`, but will await the return value of the
        decorated function before logging it."""

        @functools.wraps(func)
        async def wrapper(*args: _P.args, **kwds: _P.kwargs) -> _T:
            call_str = LazyString(_format_call, func, args, kwds)
            self.logger.log(self.level, "Calling %s", call_str)
            value = await func(*args, **kwds)
            self.logger.log(self.level, "Returning from %s = %s", call_str, value)
            return value

        return wrapper


_NO_DEFAULT = object()


def _format_call(func: Callable[..., object], args: Iterable[object], kwds: Mapping[str, object]) -> str:
    stringified_args = map(repr, args)
    defaults = func.__kwdefaults__ or {}
    stringified_kwds = (f"{k}={v!r}" for k, v in kwds.items() if defaults.get(k, _NO_DEFAULT) is not v)
    params_str = ", ".join(itertools.chain(stringified_args, stringified_kwds))
    return f"{func.__name__}({params_str})"
