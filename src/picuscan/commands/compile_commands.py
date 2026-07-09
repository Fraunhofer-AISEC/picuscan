# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import ast
import re
import gzip
import json
import subprocess
import sys
from functools import reduce
from pathlib import Path
from typing import IO, Any, AsyncIterable, Iterable, Iterator, Sequence

import attrs
import click

from picuscan import process, logging
from picuscan.common.file import glob
from picuscan.common.file import cloc as _cloc
from picuscan.compdb import Command, CompilationDB, dump
from picuscan.constants import C_CXX_SOURCE_SUFFIXES, CXX_SUFFIXES
from picuscan.misc import paramtypes
from picuscan.misc.asyncutils import adict
from picuscan.misc.decorators import collect_params, unasync
from picuscan.process import DEVNULL, PIPE

logger = logging.get_logger(__name__)


@click.group(help="Utilities to work with a compilation database")
def cli() -> None:
    pass


@attrs.frozen
class _GenParams:
    dir: Path
    pattern: Sequence[str]
    exclude: Sequence[str]
    compiler: str
    cxx_compiler: str
    includes_file: IO[str] | None
    config_file: Path | None
    output: IO[str]
    scope_file: Path | None


@cli.command(help="Generate a compilation database.")
@click.argument("dir", type=click.Path(exists=True, file_okay=False, path_type=Path), default=".")
@click.option(
    "--pattern",
    "-p",
    multiple=True,
    default=sorted(f"*{ext}" for ext in C_CXX_SOURCE_SUFFIXES),
    show_default=True,
    help="Include only the files that match this pattern in the compilation database.",
)
@click.option(
    "--exclude", "-x", multiple=True, help="Exclude the files that match this pattern from the compilation database."
)
@click.option(
    "--compiler",
    "--cc",
    default="clang",
    show_default=True,
    help="The compiler that will be used for the compile commands.",
)
@click.option(
    "--cxx-compiler",
    "--cxx",
    default="clang++",
    show_default=True,
    help="The C++ compiler that will be used for the compile commands.",
)
@click.option("--includes-file", type=click.File("r"), help="The include directories.")
@click.option(
    "--config-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Read this file to generate a list of macro definitions.",
)
@click.option("--output", "-o", type=click.File("w"), default="-", help="Write the compilation database to this file.")
@click.option("--scope-file", "-f", type=paramtypes.Path(dir_okay=False), help="Read scope paths from file")
@collect_params(_GenParams)
@unasync
async def gen(params: _GenParams) -> None:
    if params.scope_file:
        files: Iterable[Path] = list(map(Path, params.scope_file.read_text().strip().split("\n")))
    else:
        files = glob(params.dir, params.pattern, params.exclude, dir_ok=False)
    files = (p.relative_to(params.dir) for p in files)
    dir = params.dir.absolute()
    include_dirs = [] if params.includes_file is None else list(s.strip() for s in params.includes_file)

    try:
        if params.config_file is None:
            defines = {}
        else:
            defines = await adict(_defines(params.config_file, include_dirs))
    except Exception:
        logger.error("Failed to process the configuration file: {}", params.config_file)
        defines = {}

    cmds = [Command(_arguments(params, p, include_dirs, defines), directory=dir, file=p) for p in files]
    dump(CompilationDB(cmds), params.output)


_DEFINE_REGEX = re.compile(r"^#define\s+(\S+)(?:\s+(\S.*))?")


async def _defines(p: Path, include_dirs: Sequence[str]) -> AsyncIterable[tuple[str, str | None]]:
    include_flags = (f"-I{dir}" for dir in include_dirs)
    completed = await process.run("cpp", *include_flags, "-dM", p, stdout=PIPE, stderr=DEVNULL)
    for s in completed.stdout_text.splitlines():
        if match := re.match(_DEFINE_REGEX, s):
            name, value = match.groups()
            if not name.startswith("_"):
                yield name, value


def _arguments(params: _GenParams, p: Path, include_dirs: Sequence[str], defines: dict[str, str | None]) -> list[str]:
    compiler = params.cxx_compiler if p.suffix in CXX_SUFFIXES else params.compiler
    include_flags = (f"-I{dir}" for dir in include_dirs)
    define_flags = (f"-D{n}" if v is None else f"-D{n}={v}" for n, v in defines.items())
    output = p.with_suffix(f"{p.suffix}.o")
    return [compiler, *include_flags, *define_flags, "-c", "-o", str(output), str(p)]


_BUILTINS = (all, any, enumerate, len, list, range, reversed, set, sorted, str, tuple, zip)


@attrs.frozen
class _SelectParams:
    db: CompilationDB
    output: IO[str]
    where: str | None
    map: str | None
    reduce: tuple[str, str] | None


_SELECT_HELP = f"""Filter and transform compile commands.

This command works mostly with Python expressions. Unless specified otherwise, the following are accessible in all
expressions:

* dir [Path object]: The compile command directory

* file [Path object]: The file that the compile command operates on

* output [Path object]: The output file from the compile command

* args [str list]: The compile command arguments

* path [Path object]: The absolute path of the file that the compile command operates on

* cmd [Function]: A function that takes a directory, a file name/path and a list of arguments to generate a compile
command. Example: cmd(dir, file, args)

* The following Python functions: {", ".join(x.__name__ for x in _BUILTINS)}
"""


@cli.command(help=_SELECT_HELP)
@click.argument("db", type=paramtypes.CompilationDB(), default="-")
@click.option("--output", "-o", type=click.File("w"), default="-", help="Output file.")
@click.option(
    "--where", "--filter", metavar="EXPR", help="Filter out any commands for which this expression is not true."
)
@click.option("--map", metavar="EXPR", help="Evaluate this expression to transform the compile commands.")
@click.option(
    "--reduce",
    metavar="EXPR LITERAL",
    type=(str, str),
    help="""Reduce the compile commands. This options takes two expressions. The first expression is the reduce
    expression, whereas the second is the initial state for the reduce operation. The initial state must be a Python
    literal.""",
)
@click.option(
    "--count",
    "reduce",
    flag_value=("x + 1", "0"),
    help="Print the number of compile commands. Equivalent to --reduce 'x + 1' 0.",
)
@collect_params(_SelectParams)
def select(params: _SelectParams) -> None:
    cmds = iter(params.db)
    if params.where:
        cmds = _filter(cmds, params.where)
    if params.map:
        cmds = _map(cmds, params.map)
    if params.reduce is None:
        dump(CompilationDB(cmds), params.output)
    else:
        expr, initial = params.reduce
        print(_reduce(cmds, expr, initial))


def _filter(cmds: Iterable[Command], expr: str) -> Iterator[Command]:
    code = compile(expr, "<where>", "eval")
    for cmd in cmds:
        if eval(code, _globals(), _locals(cmd)):
            yield cmd


def _map(cmds: Iterable[Command], expr: str) -> Iterator[Command]:
    code = compile(expr, "<map>", "eval")
    for cmd in cmds:
        x = eval(code, _globals(), _locals(cmd))
        assert isinstance(x, Command)
        yield x


def _reduce(cmds: Iterable[Command], expr: str, initial: str) -> Any:
    code = compile(expr, "<reduce>", "eval")
    x = ast.literal_eval(initial)
    return reduce(lambda acc, cmd: eval(code, _globals(), {**_locals(cmd), "x": acc}), cmds, x)


def _globals() -> dict[str, Any]:
    return {"__builtins__": {**{x.__name__: x for x in _BUILTINS}, "cmd": _cmd}}


def _cmd(dir: Any, file: Any, args: Any) -> Command:
    return Command(map(str, args), directory=Path(dir), file=Path(file))


def _locals(cmd: Command) -> dict[str, Any]:
    return {"dir": cmd.directory, "file": cmd.file, "args": cmd.arguments, "path": cmd.path, "output": cmd.output}


@attrs.frozen
class _RunParams:
    db: CompilationDB
    ast: str | None
    ir: bool
    pp: bool
    path: str | None
    output: IO[str] | None


@cli.command(help="Run compile commands")
@click.argument("db", type=paramtypes.CompilationDB(), default="compile_commands.json")
@click.option(
    "--ast",
    default=None,
    help="dump clang AST of all translation units to specified json file (support for .gz)",
)
@click.option(
    "--ir/--no-ir",
    default=False,
    help="dump LLVM IR for every translation unit",
)
@click.option(
    "--pp/--no-pp",
    default=False,
    help="only run preprocessor",
)
@click.option(
    "--path",
    default=None,
    help="filter translation units based on path",
)
@click.option(
    "--output",
    "-o",
    type=click.File("w"),
    default=None,
    help="Write the compilation database with compilable TRs to this file",
)
@collect_params(_RunParams)
@unasync
async def run(params: _RunParams) -> None:
    failed = list()
    success = list()
    missing_header = set()
    ast_l = []
    for cmd in params.db.commands:
        directory = cmd.directory
        path = cmd.path
        if params.path and params.path not in str(path):
            continue
        compile_cmd = list(cmd.arguments)
        if params.ir:
            compile_cmd = _transform_cmd_ir(compile_cmd)
        if params.pp:
            compile_cmd = _transform_cmd_pp(compile_cmd)
        if params.ast:
            compile_cmd = _transform_cmd_ast(compile_cmd)
        print(" ".join(compile_cmd))

        stdout = None
        if params.ast or params.pp:
            stdout = subprocess.PIPE
        p = subprocess.run(compile_cmd, cwd=directory, stdout=stdout, stderr=subprocess.PIPE)
        sys.stderr.write(p.stderr.decode())
        if p.returncode == 0:
            success.append(path)
            if params.ast:
                ast = json.loads(p.stdout)
                ast["file"] = str(path)
                ast_l.append(ast)
            if params.pp:
                (Path(path.parent) / (path.stem + ".pp" + path.suffix)).write_bytes(p.stdout)
        else:
            try:
                err = p.stderr.decode().split("\n")
                missing = set(filter(lambda x: "file not found" in x, err))
                missing.update(set(filter(lambda x: "non-portable path" in x, err)))
                missing = set(map(lambda x: x.split("'")[1], missing))
                missing_header.update(missing)
            except Exception:
                pass

            failed.append(path)

    if params.ast:
        if params.ast.endswith(".gz"):
            f = gzip.open(params.ast, "wt")
        else:
            f = open(params.ast, "wt")
        json.dump(ast_l, f)
        f.close()

    ret = 0
    if failed:
        print(f"The following {len(failed)} files could NOT be compiled")
        for path in failed:
            print(f"* {path}")
        ret = 1
    else:
        print(f"All {len(success)} file(s) compiled successfully")

    if success:
        print(f"The following {len(success)} files could be compiled successfully")
        for path in success:
            print(f"* {path}")

    if missing_header:
        print(f"Found {len(missing_header)} missing header files (via compiler errors)")
        for header in sorted(missing_header):
            print(f"* {header}")

    if params.output:
        cc = CompilationDB(list(filter(lambda x: x.path in success, params.db.commands)))
        dump(cc, params.output)

    sys.exit(ret)


@attrs.frozen
class _ClocParams:
    db: CompilationDB


@cli.command(help="Show lines of code for sources files in compilation database")
@click.argument("db", type=paramtypes.CompilationDB(), default="compile_commands.json")
@collect_params(_ClocParams)
@unasync
async def cloc(params: _ClocParams) -> None:
    counts = {"C/C++ Header": 0, "C++": 0, "C": 0}
    for cmd in params.db.commands:
        d = _cloc(cmd.path)
        counts["C/C++ Header"] += d["C/C++ Header"]
        counts["C"] += d["C"]
        counts["C++"] += d["C++"]
    for key, value in counts.items():
        print(f"{key.ljust(15)}: {value}")


def _transform_cmd_ir(cmd: list[str]) -> list[str]:
    new_cmd = []
    for arg in cmd:
        if arg.endswith(".o"):
            arg = arg[:-1] + "bc"
        if arg.startswith("-O"):
            continue
        new_cmd.append(arg)

    new_cmd.insert(1, "-emit-llvm")
    new_cmd.insert(1, "-disable-O0-optnone")
    new_cmd.insert(1, "-Xclang")
    new_cmd.insert(1, "-O0")
    return new_cmd


def _transform_cmd_ast(cmd: list[str]) -> list[str]:
    new_cmd = cmd[::]
    new_cmd.insert(1, "-ast-dump=json")
    new_cmd.insert(1, "-Xclang")
    new_cmd.insert(1, "-fsyntax-only")
    return new_cmd


def _transform_cmd_pp(cmd: list[str]) -> list[str]:
    new_cmd = []
    skip = False
    for arg in cmd:
        if arg == "-o":
            skip = True
            continue
        if not skip:
            new_cmd.append(arg)
        skip = False

    new_cmd.insert(1, "-E")
    return new_cmd
