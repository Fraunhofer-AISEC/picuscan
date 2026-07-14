# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
import typing as t

import attrs
import click

from picuscan.compdb import Command, CompilationDB
from picuscan.llvm import unity
from picuscan.llvm.config import get_llvm_config
from picuscan.logging import get_logger
from picuscan.misc import paramtypes as p
from picuscan.misc.decorators import collect_params, unasync

logger = get_logger(__name__)


@attrs.frozen
class _Options:
    compile_db: CompilationDB
    output: t.IO[bytes]
    llvm: str
    fail_on_error: bool
    rename_symbols: bool


@click.command(help="Combine C/C++ files into a LLVM bitcode bundle.")
@click.argument("compile_db", type=p.CompilationDB(), default="compile_commands.json")
@click.option("--output", "-o", type=click.File("wb"), required=True, help="Output file.")
@click.option("--llvm", help="LLVM version or path to the llvm-config executable.", default="llvm-config")
@click.option(
    "--fail-on-error/--no-fail-on-error", show_default=True, help="Stop the build on the first compilation error."
)
@click.option(
    "--rename-symbols/--no-rename-symbols",
    show_default=True,
    help="Avoid symbol conflicts during linking by automatically renaming the main functions.",
)
@unasync
@collect_params(_Options)
async def cli(opts: _Options) -> None:
    await build(opts)


async def build(opts: _Options) -> None:
    try:
        try:
            llvm: int | str = int(opts.llvm)
        except ValueError:
            llvm = opts.llvm
        llvm_config = await get_llvm_config(llvm)
        logger.info("Using LLVM: %s", llvm_config.prefix)
    except Exception:
        logger.error("Failed to locate LLVM installation.")
        sys.exit(1)

    if opts.rename_symbols:
        try:
            in_memory = unity.InMemoryBuilder(opts.compile_db, fail_on_error=opts.fail_on_error, rename_symbols=True)
        except Exception:
            logger.error("Failed to initialize InMemoryBuilder.", exc_info=True)
            sys.exit(1)
        in_memory.register_renamed_symbol_callback(
            lambda name, renamed: logger.info("Renamed %r from %s to %r", renamed.name, renamed.file, name)
        )
        builder: unity.InMemoryBuilder | unity.GenericBuilder = in_memory
    else:
        builder = unity.GenericBuilder(opts.compile_db, llvm_config, fail_on_error=opts.fail_on_error)
    builder.register_compile_callback(lambda cmd: logger.info("Compiling %s", cmd.file))
    builder.register_compile_done_callback(_log_compile_done)

    try:
        await builder(opts.output)
    except Exception:
        logger.error("Build failed.", exc_info=True)
        sys.exit(1)


def _log_compile_done(cmd: Command, exc: BaseException | None) -> None:
    if exc is not None:
        logger.error(exc)
