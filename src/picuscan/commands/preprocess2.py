# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
import sys
import typing as t
from contextlib import suppress
from hashlib import md5
from pathlib import Path
from typing import IO, Collection, Iterable, Iterator, Sequence

import attrs
import click
from tqdm import tqdm

from picuscan import compdb
from picuscan import logging
from picuscan.common.file import find, glob, modify
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.compdb import Command, CompilationDB
from picuscan.constants import C_CXX_SOURCE_SUFFIXES, C_CXX_SUFFIXES, CXX_SOURCE_SUFFIXES, Language
from picuscan.misc import paramtypes, git
from picuscan.misc.decorators import collect_params, unasync
from picuscan.misc.strutils import join

_DEFAULT_PATTERNS = sorted(f"*{ext}" for ext in C_CXX_SUFFIXES)
GIT_TEMPLATE = "Picuscan fixing include files"

logger = logging.get_logger(__name__)


@attrs.frozen(kw_only=True)
class _Params:
    dir: Path
    scope: t.Sequence[str]
    scope_file: Path | None
    pattern: t.Sequence[str]
    exclude: t.Sequence[str]
    header_list: t.IO[str] | None
    write_header_list: t.IO[str] | None
    include_list: t.IO[str] | None
    write_include_list: t.IO[str] | None
    compile_db: t.IO[bytes] | None
    write_compile_db: t.IO[str] | None
    git: bool


@click.command(help="Find missing headers & generate a compilation DB.")
@click.argument("dir", type=paramtypes.Path(file_okay=False), default=".")
@click.option("--scope", "-s", multiple=True, help="Specify paths in scope (whitelist) (dir is default)")
@click.option("--scope-file", "-f", type=paramtypes.Path(dir_okay=False), help="Read scope paths from file")
@click.option(
    "--pattern",
    "-p",
    multiple=True,
    default=_DEFAULT_PATTERNS,
    show_default=True,
    help="Process only the files that match this pattern.",
)
@click.option("--exclude", "-x", multiple=True, help="Exclude the files that match this pattern.")
@click.option("--header-list", "-l", type=click.File(), help="Read the list of missing header files from this file.")
@click.option(
    "--write-header-list",
    type=click.File("w"),
    help="Write the list of header files that are still missing to this file.",
)
@click.option("--include-list", type=click.File(), help="Read the list of include directories from this file.")
@click.option(
    "--write-include-list",
    type=click.File("w"),
    help="Write the list of include directories, where missing header files were found, to this file.",
)
@click.option(
    "--compile-db",
    type=click.File("rb"),
    help="Compilation database. Used as a starting point for the output compilation database when provided.",
)
@click.option("--write-compile-db", type=click.File("w"), help="Write the compilation database to this file.")
@click.option(
    "--git/--no-git",
    default=True,
    help="""Create a Git repository (if one doesn't already exist). Create snapshots of the input files, pre- and
    post-processing.""",
)
@collect_params(_Params)
@unasync
async def cli(params: _Params) -> None:
    try:
        if params.git:
            if await git.is_repository(params.dir):
                repo = git.Repository(params.dir)
            else:
                logger.info(f"Creating repository in {params.dir}")
                repo = await git.init(params.dir)
                await repo.add(["."])
                await repo.commit(message="Initial commit", allow_empty=True)
        else:
            repo = None
    except Exception as exc:
        logger.error(f"Failed to initialize repository in {params.dir}: {exc}")
        sys.exit(1)
    headers = set(map(lambda s: Path(s.strip()), params.header_list if params.header_list else []))

    compile_db = compdb.load(params.compile_db) if params.compile_db else None
    include_dirs = _include_dirs(params.include_list, compile_db)

    scope = params.scope
    if params.scope_file:
        scope = params.scope_file.read_text().strip().split("\n")
    if not scope:
        scope = [str(params.dir)]
    files = []
    for path in scope:
        files += list(glob(Path(path), params.pattern, params.exclude))
    logger.info(f"{len(files)} file(s) to preprocess")

    if headers:
        logger.info("Locating missing header files")
        found = _find_headers(headers, files, include_dirs)
        missing = headers - found.keys()
        if missing:
            logger.error("Failed to locate header(s): {}".format(join(missing, sep=", ")))
            if file := params.write_header_list:
                file.writelines(f"{p}\n" for p in missing)
        if case_insensitive := dict(_filter_case_insensitive(found)):
            for k, v in case_insensitive.items():
                logger.info(f"Correcting include(s): {k} -> {v}")
            _transform_files(files, case_insensitive)
        include_dirs.extend(set(_include_dirs_from_found(found, params.dir)))

    if file := params.write_include_list:
        file.writelines(f"{p}\n" for p in include_dirs)

    compile_db = _compile_db(files, params.dir, include_dirs, compile_db)
    if params.write_compile_db:
        compdb.dump(compile_db, params.write_compile_db)

    if repo:
        with suppress(Exception):
            await repo.add(files, ignore_errors=True)
            await repo.commit(GIT_TEMPLATE)


def _include_dirs(file: IO[str] | None, compile_db: CompilationDB | None) -> list[Path]:
    if compile_db:
        dirs = list(compile_db.include_dirs)
        if file:
            logger.warning(f"Skipping {file.name} since a compilation DB is provided")
    elif file:
        dirs = [Path(s.strip()) for s in file]
    else:
        dirs = []
    return dirs


def _find_headers(headers: Iterable[Path], dirs: Iterable[Path], include_dirs: Collection[Path]) -> dict[Path, Path]:
    found: dict[Path, Path] = {}

    for header in headers:
        if paths := find_header(header, dirs, include_dirs, case_sensitive=False):
            path = _select_header(paths)
            found[header] = path
            if len(paths) > 1 and _different(paths):
                logger.warning(
                    "Multiple candidates for {}: {} (selecting {})".format(header, join(paths, sep=", "), path)
                )
            else:
                logger.info(f"Located {header}: {path}")

    return found


def _select_header(paths: Sequence[Path]) -> Path:
    return paths[0]  # TODO: Improve this


def _different(paths: Iterable[Path]) -> bool:
    return len(set(_hash(p) for p in paths)) > 1


def _hash(p: Path) -> bytes:
    hash = md5()
    with open(p, "rb") as f:
        for s in f:
            hash.update(s)
    return hash.digest()


def _filter_case_insensitive(headers: dict[Path, Path]) -> Iterator[tuple[str, str]]:
    for header, path in headers.items():
        n = min(len(header.parts), len(path.parts))
        h = header.parts[-n:]
        p = path.parts[-n:]
        if h != p:
            yield str(header), os.sep.join(p)


_INCLUDE_PATTERN = re.compile(r'^(\s*#include\s*)(<.*>|".*")(.*)', re.S)


def _transform_files(files: Iterable[Path], mapping: dict[str, str]) -> None:
    with tqdm(files, bar_format=fixed_width_desc()) as t:
        for p in t:
            t.set_description(f"{p.name}")
            with modify(p) as m:
                for s in m:
                    m.replace(_transform_line(s, mapping))


def _transform_line(s: str, mapping: dict[str, str]) -> str:
    if match := re.match(_INCLUDE_PATTERN, s):
        pragma, include, rest = match.groups()
        header = include[1:-1]
        try:
            mapped = mapping[header]
            return f"{pragma}{include[0]}{mapped}{include[-1]}{rest}"
        except KeyError:
            pass

    return s


def _include_dirs_from_found(headers: dict[Path, Path], dir: Path) -> Iterator[Path]:
    for h, p in headers.items():
        if p.is_relative_to(dir):
            try:
                yield p.relative_to(dir).parents[len(h.parts) - 1]
            except IndexError:
                pass


def _compile_db(
    files: Sequence[Path], dir: Path, include_dirs: Sequence[Path], existing: CompilationDB | None
) -> CompilationDB:
    if existing:
        return CompilationDB(tuple(_transform_commands(existing)))
    else:
        return CompilationDB(tuple(_commands(files, dir, include_dirs)))


def _transform_commands(compile_db: CompilationDB) -> Iterator[Command]:
    for cmd in compile_db:
        if cmd.language == Language.CXX:
            compiler = "clang++"
        else:
            compiler = "clang"
        flags, files = cmd.gcc_options
        yield cmd.with_arguments(compiler, *flags.args, *files)


def _commands(files: Iterable[Path], dir: Path, include_dirs: Collection[Path]) -> Iterator[Command]:
    for p in files:
        suffix = p.suffix
        if suffix not in C_CXX_SOURCE_SUFFIXES:
            continue
        compiler = "clang++" if suffix in CXX_SOURCE_SUFFIXES else "clang"
        file = p.relative_to(dir)
        cmd = (compiler, *(f"-I{p}" for p in include_dirs), "-c", str(file))
        yield Command(cmd, directory=dir.resolve(), file=file)


def find_header(
    header: Path,
    dirs: Iterable[Path] | None = None,
    include_dirs: Collection[Path] | None = None,
    case_sensitive: bool = True,
) -> tuple[Path, ...]:
    include_dirs = include_dirs or []
    if p := next(find(header, dirs=include_dirs, case_sensitive=case_sensitive), None):
        return (p,)
    else:
        return tuple(find(header, dirs=dirs or [], recursive=True, case_sensitive=case_sensitive))
