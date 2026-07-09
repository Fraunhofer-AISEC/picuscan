# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from asyncio import Semaphore
from contextlib import asynccontextmanager

import attrs
import click


@attrs.frozen(kw_only=True)
class Config:
    job_semaphore: Semaphore = attrs.field(factory=Semaphore)
    """Use this semaphore to limit the number of expensive tasks that run concurrently."""

    keep_tmps: bool = False


@t.overload
def get_current_config(silent: t.Literal[False] = ...) -> Config: ...


@t.overload
def get_current_config(silent: bool) -> Config | None: ...


def get_current_config(silent: bool = False) -> Config | None:
    ctx = click.get_current_context(silent)
    if ctx is None:
        return None
    conf = ctx.find_object(Config)
    if not silent and conf is None:
        raise RuntimeError("There is no active configuration.")
    return conf


@asynccontextmanager
async def acquire_job_semaphore() -> t.AsyncIterator[None]:
    """Use this context manager to limit the number of expensive tasks
    that run concurrently."""
    if config := get_current_config(silent=True):
        async with config.job_semaphore:
            yield
    else:
        yield
