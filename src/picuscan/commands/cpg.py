# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Sequence, TypeVar
from urllib.parse import urlparse

import attrs
import click

from picuscan import process, sarif, logging
from picuscan.common.cpg import CPG
from picuscan.common.file import glob
from picuscan.constants import C_CXX_SUFFIXES
from picuscan.misc.decorators import collect_params, unasync
from picuscan.sarif.models import Run, Tool, ToolComponent


logger = logging.get_logger(__name__)

COMMON_PARAMS = [
    click.option(
        "--uri",
        default="bolt://localhost:7687",
        envvar="PICUSCAN_CPG_URI",
        show_default=True,
        help="The Neo4j instance URI.",
    ),
    click.option("--user", default="neo4j", show_default=True, help="The Neo4j database user."),
    click.option("--password", default="password", show_default=True, help="The Neo4j database password."),
]

R = TypeVar("R")


def add_common_params(cmd: Callable[..., R]) -> Callable[..., R]:
    for param in reversed(COMMON_PARAMS):
        cmd = param(cmd)
    return cmd


@attrs.frozen
class CommonParams:
    uri: str
    user: str
    password: str


@click.group(help="Run some checks on the CPG database.")
def cli() -> None:
    pass


_PATTERNS = sorted(f"*{ext}" for ext in C_CXX_SUFFIXES)


@attrs.frozen
class LoadParams(CommonParams):
    dir: Path
    pattern: Sequence[str]
    exclude: Sequence[str]
    compilation_db: Path | None
    includes_file: Path | None
    save_depth: int


@cli.command(help="Transform the source code into a CPG and load the graph into Neo4j.")
@add_common_params
@click.argument("dir", default=".", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--pattern", "-p", default=_PATTERNS, show_default=True, help="Process only the files that match this pattern."
)
@click.option("--exclude", "-x", default=[], help="Exclude the files that match this pattern.")
@click.option(
    "--compilation-db",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Compilation database. This option overrides --pattern, --exclude and --includes-file.",
)
@click.option(
    "--includes-file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Read the include directories from this file.",
)
@click.option("--save-depth", type=int, default=4, show_default=True, help="Limit the recursion depth for the graph.")
@collect_params(LoadParams)
@unasync
async def load(params: LoadParams) -> None:
    uri = urlparse(params.uri)
    host = f"--host={uri.hostname}", f"--port={uri.port}"
    creds = f"--user={params.user}", f"--password={params.password}"
    args: list[str | Path] = [*host, *creds, f"--save-depth={params.save_depth}"]
    if params.compilation_db:
        args.append(f"--json-compilation-database={params.compilation_db}")
    else:
        if params.includes_file:
            args.append(f"--includes-file={params.includes_file}")
        args.extend(glob(params.dir, params.pattern, params.exclude))
    await process.run("cpg-neo4j", *args, discard_output=True)


@attrs.frozen
class FuncsLikeParams(CommonParams):
    name: str


@cli.command(help="Find similarly named functions.")
@add_common_params
@click.option("--name", required=True, help="The function name.")
@collect_params(FuncsLikeParams)
def funcs_like(params: FuncsLikeParams) -> None:
    with connect(params) as cpg:
        results = frozenset(cpg.find_funcs_like(params.name))
        run = Run(tool=Tool(driver=ToolComponent(name="Picuscan")), results=results)
        log = sarif.log([run])
        print(sarif.dumps(log))


@cli.command(help="Locate array access operations.")
@add_common_params
@collect_params(CommonParams)
def array_accesses(params: CommonParams) -> None:
    with connect(params) as cpg:
        results = frozenset(x.sarif for x in cpg.find_array_accesses())
        run = Run(tool=Tool(driver=ToolComponent(name="Picuscan")), results=results)
        log = sarif.log([run])
        print(sarif.dumps(log))


@cli.command(help="Locate function calls where the return value is not checked.")
@add_common_params
@collect_params(CommonParams)
def missing_ret_checks(params: CommonParams) -> None:
    with connect(params) as cpg:
        results = frozenset(cpg.find_missing_return_checks())
        run = Run(tool=Tool(driver=ToolComponent(name="Picuscan")), results=results)
        log = sarif.log([run])
        print(sarif.dumps(log))


@contextmanager
def connect(params: CommonParams) -> Iterator[CPG]:
    try:
        with CPG(params.uri, (params.user, params.password)) as cpg:
            yield cpg
    except Exception as exc:
        logger.error(exc)
        sys.exit(1)
