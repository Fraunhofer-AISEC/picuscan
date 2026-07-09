# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import pkgutil
from asyncio import Semaphore
from typing import Any

import click

from . import commands, logging
from .config import Config
from .misc import sysutils

logging.install()
logger = logging.get_logger(__name__)


class Loader(click.Group):
    def list_commands(self, ctx: click.Context) -> list[str]:
        return [name.replace("_", "-") for _, name, _ in pkgutil.iter_modules(commands.__path__)]

    def get_command(self, ctx: click.Context, cmd_name: str) -> click.Command | None:
        cmd_name = cmd_name.replace("-", "_")
        try:
            # When a user runs 'picuscan some-command', look for the
            # command definition in 'picuscan.commands.some_command'
            module = importlib.import_module(f"{commands.__name__}.{cmd_name}")
            cmd = getattr(module, "cli")
            if isinstance(cmd, click.Command):
                return cmd
        except (ModuleNotFoundError, AttributeError):
            pass
        return None


LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


@click.command(cls=Loader, help="Picuscan")
@click.option(
    "--log", type=click.Choice(LEVELS, case_sensitive=False), default="INFO", show_default=True, help="Log level."
)
@click.option(
    "--max-jobs", "-j", type=click.IntRange(1), default=sysutils.cpu_count(), help="Maximum number of processes."
)
@click.option("--keep-tmps", is_flag=True, help="Don't delete temporary files.")
@click.version_option()
@click.pass_context
def main(ctx: click.Context, /, log: str, max_jobs: int, **kwds: Any) -> None:
    logger.setLevel(log)
    semaphore = Semaphore(max_jobs)
    # Make the configuration available in all subcommand contexts
    ctx.obj = Config(job_semaphore=semaphore, **kwds)
