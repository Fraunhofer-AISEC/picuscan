# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from collections.abc import Iterator
from typing import IO, Any, AnyStr, Generic, Literal, overload

import click
from typing_extensions import Self

from picuscan.config import get_current_config
from picuscan.typing import StrBytesPath

_StrMode = Literal["w", "w+"]
_BytesMode = Literal["wb", "w+b"]


@overload
def temp_file(
    mode: _StrMode,
    *,
    encoding: str | None = ...,
    newline: str | None = ...,
    suffix: str | None = ...,
    dir: StrBytesPath | None = ...,
    delete: bool = ...,
) -> _TemporaryFile[str]: ...


@overload
def temp_file(
    mode: _BytesMode = ..., *, suffix: str | None = ..., dir: StrBytesPath | None = ..., delete: bool = ...
) -> _TemporaryFile[bytes]: ...


@overload
def temp_file(
    mode: str,
    *,
    encoding: str | None = ...,
    newline: str | None = ...,
    suffix: str | None = ...,
    dir: StrBytesPath | None = ...,
    delete: bool = ...,
) -> _TemporaryFile[Any]: ...


def temp_file(mode: str = "w+b", **kwds: Any) -> _TemporaryFile[Any]:
    if "delete" not in kwds:
        if config := get_current_config(silent=True):
            kwds["delete"] = not config.keep_tmps
    return _TemporaryFile(tempfile.NamedTemporaryFile(mode, prefix=_prefix(), **kwds))


class _TemporaryFileImpl(Generic[AnyStr]):
    __slots__ = ("_file", "path")

    def __init__(self, file: IO[AnyStr]):
        self._file: IO[AnyStr] = file
        self.path = Path(file.name)

    def __getattr__(self, name: str, /) -> Any:
        return getattr(self._file, name)

    def __iter__(self) -> Iterator[AnyStr]:
        return iter(self._file)

    def __enter__(self) -> Self:
        self._file.__enter__()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None, /
    ) -> bool | None:
        return self._file.__exit__(exc_type, exc, tb)


_TemporaryFile = _TemporaryFileImpl


@contextmanager
def temp_dir() -> Iterator[Path]:
    try:
        config = get_current_config()
        keep_tmps = config.keep_tmps
    except Exception:
        keep_tmps = False
    prefix = _prefix()
    if keep_tmps:
        p = tempfile.mkdtemp(prefix=prefix)
        yield Path(p)
    else:
        with tempfile.TemporaryDirectory(prefix=prefix) as p:
            yield Path(p)


_PREFIX = "picuscan."


def _prefix() -> str:
    if ctx := click.get_current_context(silent=True):
        if cmd := ctx.invoked_subcommand:
            return f"{_PREFIX}{cmd}."
    return _PREFIX
