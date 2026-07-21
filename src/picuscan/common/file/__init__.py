# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import enum
import json
import shutil
import stat
import glob as py_glob
import subprocess
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import partial
from itertools import chain, repeat
from pathlib import Path
from typing import IO, Any, AnyStr, Collection, Container, Generic, Iterable, Iterator, Literal, Self, overload


class Type(enum.IntEnum):
    BLK = stat.S_IFBLK
    CHR = stat.S_IFCHR
    DIR = stat.S_IFDIR
    FIFO = stat.S_IFIFO
    LNK = stat.S_IFLNK
    REG = stat.S_IFREG
    SOCK = stat.S_IFSOCK


def find(
    path: Path,
    *,
    dirs: Path | Iterable[Path],
    types: Type | Container[Type] = Type.REG,
    recursive: bool = False,
    case_sensitive: bool = True,
) -> Iterator[Path]:
    dirs = [dirs] if isinstance(dirs, Path) else dirs
    if path.is_absolute():
        paths = iter([path] if _is(path, types) else [])
    elif recursive:
        paths = _find_recursive(path, dirs, case_sensitive)
    else:
        paths = _find(path, dirs, case_sensitive)
    paths = (p for p in paths if _is(p, types))
    return paths


def _find_recursive(path: Path, dirs: Iterable[Path], case_sensitive: bool) -> Iterator[Path]:
    paths: Iterator[Path] = chain.from_iterable(dir.glob("**/*") for dir in dirs)
    paths = (p for p in paths if _match(p, path, case_sensitive))
    return paths


def _find(path: Path, dirs: Iterable[Path], case_sensitive: bool) -> Iterator[Path]:
    if case_sensitive:
        paths: Iterator[Path] = (dir / path for dir in dirs)
    else:
        pattern = "/".join(repeat("*", len(path.parts)))
        paths = chain.from_iterable(dir.glob(pattern) for dir in dirs)
        paths = (p for p in paths if _match(p, path, False))
    return paths


def _match(p: Path, q: Path, case_sensitive: bool = True) -> bool:
    for a, b in zip(reversed(p.parts), reversed(q.parts)):
        if case_sensitive:
            if a != b:
                return False
        elif a.casefold() != b.casefold():
            return False
    return True


def glob(
    dir: Path,
    patterns: str | Collection[str] | None = None,
    exclude: str | Collection[str] | None = None,
    *,
    file_ok: bool = True,
    dir_ok: bool = True,
) -> Iterator[Path]:
    patterns = patterns or ["*"]
    patterns = [patterns] if isinstance(patterns, str) else patterns
    exclude = [] if exclude is None else exclude
    exclude = [exclude] if isinstance(exclude, str) else exclude
    if dir.is_dir():
        files: Iterable[Path] = dir.glob("**/*")
    elif dir.is_file():
        files = [dir]
    elif "*" in str(dir):
        files = [Path(_) for _ in py_glob.glob(str(dir))]
    else:
        raise ValueError(f"Invalid path for glob: {dir}")
    for p in files:
        if not dir_ok and p.is_dir():
            continue
        elif not (file_ok or p.is_dir()):
            continue
        matcher = partial(fnmatchcase, str(p))
        if any(map(matcher, patterns)) and not any(map(matcher, exclude)):
            yield p


def _is(p: Path, types: Type | Container[Type]) -> bool:
    types = [types] if isinstance(types, Type) else types
    st = p.lstat()
    return stat.S_IFMT(st.st_mode) in types


class _NotModified(Exception):
    pass


@overload
@contextmanager
def modify(file: Path, text: Literal[True] = ...) -> Iterator[_Modify[str]]: ...


@overload
@contextmanager
def modify(file: Path, text: Literal[False]) -> Iterator[_Modify[bytes]]: ...


@contextmanager
def modify(file: Path, text: bool = True) -> Iterator[_Modify[str] | _Modify[bytes]]:
    """Like `rewrite()`, but this tries to avoid unnecessary write
    operations while providing a nicer API for line-by-line processing."""
    with suppress(_NotModified):
        with rewrite(file, "w" if text else "wb") as new:
            with open(file, "r" if text else "rb") as current:
                m = _Modify(current)
                yield m
            if m.modified:
                new.writelines(m.pending)
            else:
                raise _NotModified


@dataclass
class _Modify(Generic[AnyStr]):
    file: IO[AnyStr]
    pending: list[AnyStr] = field(default_factory=list)
    modified: bool = False

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> AnyStr:
        s = next(self.file)
        self.pending.append(s)
        return s

    def replace(self, s: AnyStr) -> None:
        """Replace the current line with `s`."""
        if not self.modified and self.pending[-1] != s:
            self.modified = True
        self.pending[-1] = s


@overload
@contextmanager
def rewrite(
    file: Path, mode: Literal["w", "w+"] = ..., encoding: str | None = ..., newline: str | None = ..., suffix: str = ...
) -> Iterator[IO[str]]: ...


@overload
@contextmanager
def rewrite(file: Path, mode: Literal["wb", "w+b"], *, suffix: str = ...) -> Iterator[IO[bytes]]: ...


@overload
@contextmanager
def rewrite(
    file: Path, mode: str, encoding: str | None = ..., newline: str | None = ..., suffix: str = ...
) -> Iterator[IO[Any]]: ...


@contextmanager
def rewrite(
    file: Path, mode: str = "w", encoding: str | None = None, newline: str | None = None, suffix: str = "~"
) -> Iterator[IO[str] | IO[bytes]]:
    """Create a copy of `file` and open it for modification. In case of
    an error, discard the copy. Otherwise, replace the original with the
    (modified) copy."""
    assert mode in {"w", "w+", "wb", "w+b"}
    assert suffix
    new = file.with_name(f"{file.name}{suffix}")
    try:
        with open(new, mode, encoding=encoding, newline=newline) as f:
            yield f
        try:
            shutil.copymode(file, new)
        except Exception:
            pass
        shutil.move(new, file.resolve())
    except BaseException:
        new.unlink(missing_ok=True)
        raise


def tokei(path: Path, exclude: list[str] | None = None) -> tuple[dict[str, Any], list[str]]:
    args = ["tokei", "-o", "json", str(path)]
    if exclude:
        for src in exclude:
            args.append("-e")
            args.append(src)
    p = subprocess.run(args, stdout=subprocess.PIPE)
    out = p.stdout.decode()
    d = json.loads(out)
    count_c = 0
    count_cpp = 0
    count_h = 0
    files: list[str] = []
    if "C" in d:
        count_c = d["C"]["code"]
        files.extend(f["name"] for f in d["C"].get("reports", []))
    if "C++" in d:
        count_cpp = d["C++"]["code"]
        files.extend(f["name"] for f in d["C++"].get("reports", []))
    if "C/C++ Header" in d:
        count_h += d["C/C++ Header"]["code"]
        files.extend(f["name"] for f in d["C/C++ Header"].get("reports", []))
    if "C Header" in d:
        count_h += d["C Header"]["code"]
        files.extend(f["name"] for f in d["C Header"].get("reports", []))
    return ({"C/C++ Header": count_h, "C++": count_cpp, "C": count_c}, files)
