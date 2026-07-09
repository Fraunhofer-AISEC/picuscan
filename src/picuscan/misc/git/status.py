# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import Container, Iterator, Literal, Protocol, Union, get_args


class Flag(str, enum.Enum):
    UNMODIFIED = " "
    MODIFIED = "M"
    ADDED = "A"
    DELETED = "D"
    RENAMED = "R"
    COPIED = "C"
    UNMERGED = "U"
    UNTRACKED = "?"
    IGNORED = "!"


_RegularFlag = Literal[Flag.UNMODIFIED, Flag.MODIFIED, Flag.ADDED, Flag.DELETED, Flag.UNMERGED]
_RenamedCopiedFlag = Literal[Flag.RENAMED, Flag.COPIED]

_REGULAR_FLAGS: set[_RegularFlag] = set(get_args(_RegularFlag))
_RENAMED_COPIED_FLAGS: set[_RenamedCopiedFlag] = set(get_args(_RenamedCopiedFlag))


class _Entry(Protocol):
    @property
    def index(self) -> Flag: ...

    @property
    def work_tree(self) -> Flag: ...


class _Mixin:
    def is_dirty(self: _Entry, index: bool = True, work_tree: bool = True, untracked: bool = True) -> bool:
        flags = {Flag.UNMODIFIED}
        if untracked:
            flags.add(Flag.UNTRACKED)
        return (index and self.index not in flags) or (work_tree and self.work_tree not in flags)

    @property
    def untracked(self: _Entry) -> bool:
        return self.index == Flag.UNTRACKED and self.work_tree == Flag.UNTRACKED


@dataclass
class _Regular(_Mixin):
    index: _RegularFlag
    work_tree: _RegularFlag
    path: Path


@dataclass
class _RenamedCopiedInIndex(_Mixin):
    index: _RenamedCopiedFlag
    work_tree: _RegularFlag
    path: Path
    orig: Path


@dataclass
class _RenamedCopiedInWorkTree(_Mixin):
    index: _RegularFlag
    work_tree: _RenamedCopiedFlag
    path: Path
    orig: Path


@dataclass
class _Untracked(_Mixin):
    index: Literal[Flag.UNTRACKED]
    work_tree: Literal[Flag.UNTRACKED]
    path: Path


@dataclass
class _Ignored(_Mixin):
    index: Literal[Flag.IGNORED]
    work_tree: Literal[Flag.IGNORED]
    path: Path


Entry = Union[_Regular, _RenamedCopiedInIndex, _RenamedCopiedInWorkTree, _Untracked, _Ignored]


class Status(tuple[Entry]):
    def is_dirty(self, index: bool = True, work_tree: bool = True, untracked: bool = True) -> bool:
        return any(e.is_dirty(index, work_tree, untracked) for e in self)


def parse(s: str, paths: Container[Path] | None = None) -> Status:
    """Parse the output of `git status`. The output should be in the
    porcelain format version 1 and null-terminated. See the flags
    `--porcelain` and `-z` of `git status`."""
    return Status(_parse(s, paths))


def _parse(s: str, paths: Container[Path] | None) -> Iterator[Entry]:
    it = iter(s.split("\0"))
    while line := next(it, None):
        try:
            x = Flag(line[0])
            y = Flag(line[1])
        except IndexError as exc:
            raise ParseError("Expected XY status code") from exc
        except ValueError as exc:
            raise ParseError(exc) from exc
        if p := line[3:]:
            path = Path(p)
            if paths is not None and path not in paths:
                continue
        else:
            raise ParseError("Expected path")
        if x in _REGULAR_FLAGS and y in _REGULAR_FLAGS:
            yield _Regular(x, y, path)
        elif x in _RENAMED_COPIED_FLAGS or y in _RENAMED_COPIED_FLAGS:
            if orig_path := next(it, None):
                orig = Path(orig_path)
            else:
                raise ParseError("Expected original path")
            if x in _REGULAR_FLAGS:
                assert y in _RENAMED_COPIED_FLAGS
                yield _RenamedCopiedInWorkTree(x, y, path, orig)
            elif y in _REGULAR_FLAGS:
                assert x in _RENAMED_COPIED_FLAGS
                yield _RenamedCopiedInIndex(x, y, path, orig)
            else:
                raise ParseError(f"Unexpected status code {x}{y}")
        elif x == Flag.UNTRACKED and y == Flag.UNTRACKED:
            yield _Untracked(x, y, path)
        elif x == Flag.IGNORED and y == Flag.IGNORED:
            yield _Ignored(x, y, path)
        else:
            raise ParseError(f"Unexpected status code {x}{y}")


class ParseError(Exception):
    pass
