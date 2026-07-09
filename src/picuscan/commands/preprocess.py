# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import sys
import typing as t
from contextlib import suppress
from pathlib import Path
from typing import Literal, Sequence

import attrs
import click
from tqdm import tqdm

from picuscan import logging
from picuscan.common.file import glob, rewrite
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.compdb import CompilationDB
from picuscan.constants import C_CXX_SUFFIXES
from picuscan.misc import git
from picuscan.misc import paramtypes as p
from picuscan.misc.cppcheck import check_config
from picuscan.misc.cppcheck.tqdm import update_tqdm
from picuscan.misc.decorators import collect_params, unasync

logger = logging.get_logger(__name__)

_DEFAULT_PATTERNS = sorted(f"*{ext}" for ext in C_CXX_SUFFIXES)

Conversion = Literal["enc", "line", "inc"]
_DEFAULT_CONVERSIONS: t.Collection[Conversion] = ["enc", "line", "inc"]

GIT_TEMPLATE = """Picuscan preprocess fixed some issues

The following converters were used: {}"""


@attrs.frozen(kw_only=True)
class _Params:
    dir: Path
    scope: t.Sequence[str]
    scope_file: Path | None
    pattern: t.Sequence[str]
    exclude: t.Sequence[str]
    encoding: str | None
    convert: t.Collection[Conversion]
    git: bool
    git_template: str
    output: t.IO[str] | None
    compile_db: CompilationDB | None
    include_list: Path | None


@click.command(help="Preprocess and normalize source files.")
@click.argument("dir", type=p.Path(file_okay=False), default=".")
@click.option("--scope", "-s", multiple=True, help="Specify paths in scope (whitelist) (dir is default)")
@click.option("--scope-file", "-f", type=p.Path(dir_okay=False), help="Read scope paths from file")
@click.option(
    "--pattern",
    "-p",
    multiple=True,
    default=_DEFAULT_PATTERNS,
    show_default=True,
    help="Process only the files that match this pattern.",
)
@click.option("--exclude", "-x", multiple=True, help="Exclude the files that match this pattern.")
@click.option("--encoding", help="The encoding used for the input files.")
@click.option(
    "--convert",
    "-c",
    type=p.Literal(Conversion, case_sensitive=False),
    multiple=True,
    default=_DEFAULT_CONVERSIONS,
    show_default=True,
    help="""The conversions that will be performed.

    enc: Convert the input files to UTF-8.

    line: Normalize the line endings (i.e., LF instead of CRLF).

    inc: Normalize the path separators (i.e., / instead of \\) used in include directives.""",
)
@click.option(
    "--git/--no-git",
    default=True,
    help="""Create a Git repository (if one doesn't already exist). Create snapshots of the input files, pre- and
    post-processing.""",
)
@click.option(
    "--git-template",
    default=GIT_TEMPLATE,
    help="""The template that will be used for the Git commit after the processing. If you include {} in the message
    string, it will be replaced with the list of conversions that were performed.""",
)
@click.option("--output", "-o", type=click.File("w"), help="Write the list of missing header files to this file.")
@click.option(
    "--compile-db", type=p.CompilationDB(), help="Compilation database. Used for the missing header file check."
)
@click.option(
    "--include-list",
    type=p.Path(exists=True, dir_okay=False),
    help="Read the list of include paths from this file. Used for the missing header file check.",
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

    scope: t.Sequence[str | Path] = params.scope
    if params.scope_file:
        scope = params.scope_file.read_text().strip().split("\n")
    if not scope:
        scope = [params.dir]
    files: list[Path] = []
    for path in scope:
        files += list(glob(Path(path), params.pattern, params.exclude))
    if not files:
        logger.warning("Nothing to process")
        sys.exit(2)
    logger.info(f"Found {len(files)} source files in scope")
    relative = tuple(p.relative_to(params.dir) for p in files)

    if repo:
        if await repo.is_dirty(relative):
            logger.error("There are uncommitted changes in the repository.")
            sys.exit(1)

    logger.info("Converting file encoding...")
    with tqdm(files, bar_format=fixed_width_desc()) as t:
        for path in t:
            t.set_description(f"{path.name}")
            _convert(path, set(params.convert), params.encoding)

    if repo:
        with suppress(Exception):
            await repo.add(relative, ignore_errors=True)
            await repo.commit(params.git_template.format(", ".join(params.convert)), relative)

    await _cppcheck(params, files)


def _convert(path: Path, conversions: set[Conversion], encoding: str | None = None) -> None:
    newline = None if "line" in conversions else ""
    try:
        with rewrite(path, "w", encoding="utf-8" if "enc" in conversions else encoding, newline=newline) as new:
            with open(path, mode="r", encoding=encoding, newline=newline) as f:
                for s in f:
                    if "inc" in conversions:
                        s = _convert_if_include(s)
                    new.write(s)
    except ValueError as e:
        logger.error(f"{path}: {e}")
        sys.exit(2)
    except LookupError as e:
        logger.error(f"Error: {e}")
        sys.exit(2)


INCLUDE_PATTERN = re.compile(r'^(\s*#include\s*)(<.*>|".*")(.*)', re.S)


def _convert_if_include(s: str) -> str:
    if match := re.match(INCLUDE_PATTERN, s):
        include, path, rest = match.groups()
        path = path.replace("\\", "/")
        return f"{include}{path}{rest}"
    return s


async def _cppcheck(params: _Params, files: Sequence[Path]) -> None:
    if not params.compile_db and not params.include_list:
        logger.warning("Please provide compilation database or includes file to find missing header files; done")
        return

    logger.info("Finding missing header files...")
    with tqdm(total=100, bar_format=fixed_width_desc()) as t:
        if compile_db := params.compile_db:
            missing = await check_config(f"--project={compile_db.path}", on_event=update_tqdm(t))
        elif params.include_list:
            missing = await check_config(f"--includes-file={params.include_list}", files=files, on_event=update_tqdm(t))
        else:
            raise RuntimeError

    if missing:
        if output := params.output:
            logger.info(f"Writing list of missing headers to {output.name}")
            output.writelines(f"{header}\n" for header in missing)
        else:
            logger.warning("Missing headers: {}".format(", ".join(missing)))
