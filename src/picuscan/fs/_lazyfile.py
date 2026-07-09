# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t

from picuscan.typing import FileDescriptorOrPath, OpenBinaryMode, OpenTextMode


@t.overload
def lazyfile(
    file: FileDescriptorOrPath,
    mode: OpenTextMode = "r",
    buffering: int = ...,
    encoding: str | None = ...,
    errors: str | None = ...,
    newline: str | None = ...,
    closefd: bool = ...,
) -> t.IO[str]: ...


@t.overload
def lazyfile(
    file: FileDescriptorOrPath,
    mode: OpenBinaryMode,
    buffering: int = ...,
    encoding: None = ...,
    errors: None = ...,
    newline: None = ...,
    closefd: bool = ...,
) -> t.IO[bytes]: ...


@t.overload
def lazyfile(
    file: FileDescriptorOrPath,
    mode: str,
    buffering: int = ...,
    encoding: str | None = ...,
    errors: str | None = ...,
    newline: str | None = ...,
    closefd: bool = ...,
) -> t.IO[t.Any]: ...


def lazyfile(file: FileDescriptorOrPath, mode: str = "r", *args: t.Any, **kwds: t.Any) -> t.IO[t.Any]:
    return t.cast(t.IO[t.Any], _LazyFile(file, mode, *args, **kwds))


class _LazyFile:
    __slots__ = ("_name", "_mode", "_args", "_kwds", "_file")

    def __init__(self, file: FileDescriptorOrPath, mode: str, *args: t.Any, **kwds: t.Any):
        self._name = file
        self._mode = mode
        self._args = args
        self._kwds = kwds
        self._file: t.IO[t.Any] | None = None

    @property
    def _open(self) -> t.IO[t.Any]:
        if self._file is None:
            self._file = open(self._name, self._mode, *self._args, **self._kwds)
            del self._name, self._mode, self._args, self._kwds  # No need to keep these in memory
        return self._file

    def close(self) -> None:
        if self._file is not None:
            self._file.close()

    def __getattr__(self, name: str, /) -> t.Any:
        return getattr(self._open, name)

    def __iter__(self) -> t.Iterator[t.Any]:
        return iter(self._open)

    def __str__(self) -> str:
        if self._file is None:
            return f"<{self.__class__.__name__} name={self._name!r} mode={self._mode!r}>"
        return str(self._file)

    def __repr__(self) -> str:
        return str(self)

    def __enter__(self) -> _LazyFile:
        return self

    def __exit__(self, *args: object, **kwds: object) -> None:
        self.close()
