# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shutil
import typing as t
from abc import ABC, abstractmethod
from inspect import isabstract
from pathlib import Path

import attrs

from picuscan.analyzer.transforms._results import update_results
from picuscan.config import get_current_config
from picuscan.sarif.models import Level, Log, Invocation

from .options import Options
from .tools.data import load_rules
from .transforms import (
    Transform,
    fingerprint,
    inject_cwe_mappings,
    mark_open,
    normalize_locations,
    update_results_with_json,
    down_rate_failed_sources,
)

REGISTRY: dict[str, type[Tool]] = {}


class Tool(ABC):
    """
    This is the base class of all tool definitions. Inheriting from it
    will automatically register the subclass as a tool in the registry.

    That being said, you still need to ensure that the module containing
    the subclass definition is loaded somehow. Normally, this is handled
    by `load_tools()` from `picuscan.analyzer.tools`.
    """

    name: t.ClassVar[str]
    """Name of the tool. This defaults to `__name__`."""
    override_program: t.ClassVar[str | None] = None
    """Name of the program that will be executed. This defaults to `name.lower()`."""
    enabled: t.ClassVar[bool] = True
    """Whether this tool is enabled by default."""
    supports_threading: bool = False
    """Whether this tool uses parallel computing"""
    uses_tqdm: bool = False
    """Whether this tool uses tqdm process bar"""

    invocations: list[Invocation] = []
    """Tool process invocations to be added to the SARIF file"""

    # Transforms
    rebase_locations: t.ClassVar[bool] = True
    inject_cwe_mappings: t.ClassVar[bool] = True
    inject_fingerprints: t.ClassVar[bool] = True
    mark_all_open: t.ClassVar[bool] = True
    down_rate_failed_sources: t.ClassVar[bool] = True

    def __init_subclass__(cls) -> None:
        super().__init_subclass__()
        if not hasattr(cls, "name"):
            cls.name = cls.__name__
        if not isabstract(cls):
            name = cls.name.casefold()
            tool = REGISTRY.setdefault(name, cls)
            if tool is not cls:
                raise RuntimeError(f"{cls} conflicts with {tool}, as both have the name {name!r}.")

    def __init__(
        self,
        opts: Options,
        *,
        picuscan_dir: Path,
        tool_dir: Path,
        sink: t.IO[bytes],
        jobs: int = 0,
        bar_position: int = 0,
    ):
        super().__init__()
        self.opts = opts
        self.picuscan_dir = picuscan_dir
        self.tool_dir = tool_dir
        self.sink = sink
        self.config = get_current_config()
        self.jobs = jobs
        self.failed_sources: set[str] = set()
        """list of source files, which could not be analyzed by the tool"""
        self.bar_position = bar_position
        """progress bar position"""

    def should_run(self) -> bool:
        """Whether the tool should be executed."""
        return bool(shutil.which(self.program))

    @abstractmethod
    async def run(self) -> Log:
        """Run the tool and produce a SARIF log."""
        ...

    @property
    def program(self) -> str:
        return self.name.lower() if self.override_program is None else self.override_program

    @property
    def transforms(self) -> list[Transform]:
        transforms: list[Transform] = []
        transforms.append(
            update_results(
                [
                    (lambda r: r.level == Level.ERROR, lambda r: attrs.evolve(r, rank=100)),
                    (lambda r: r.level == Level.WARNING, lambda r: attrs.evolve(r, rank=80)),
                    (None, lambda r: attrs.evolve(r, rank=40)),
                ]
            )
        )
        if self.rebase_locations:
            transforms.append(normalize_locations())
        if self.inject_cwe_mappings:
            transforms.append(inject_cwe_mappings())
        if self.inject_fingerprints:
            transforms.append(fingerprint())
        if self.mark_all_open:
            transforms.append(mark_open())
        if self.opts.sarif_transform:
            transforms.append(update_results_with_json(load_rules(self.name)))
        if self.down_rate_failed_sources:
            transforms.append(down_rate_failed_sources(self.failed_sources))
        return transforms
