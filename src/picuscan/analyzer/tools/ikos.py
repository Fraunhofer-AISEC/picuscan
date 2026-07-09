# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import typing as t
import shutil
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from collections.abc import AsyncIterator, Iterator

import attrs

from picuscan import fs, logging, process, sarif
from picuscan.analyzer.options import Options
from picuscan.analyzer.tool import Tool
from picuscan.analyzer.transforms import Transform, truncate_stacks, update_results
from picuscan.llvm import unity
from picuscan.llvm.callgraph import CallGraph
from picuscan.llvm.config import LLVMConfig, get_llvm_config
from picuscan.process import PIPE, TransformSarifAddInvocations
from picuscan.sarif.models import Level, Log, Result, Stack, StackFrame
from picuscan.sarif.visitor import Visitor
from picuscan.typing import StrBytesPath, StrPath

logger = logging.get_logger(__name__)


class IKOS(Tool):
    enabled = False

    async def run(self) -> Log:
        logger.info("Running %s", self.name)

        if self.opts.ikos_llvm is None:
            version = await self.__version()
            if version and version < (3, 1):
                llvm_version = 9
            else:
                llvm_version = 14
            llvm = await get_llvm_config(llvm_version)
        else:
            try:
                llvm_version = int(self.opts.ikos_llvm)
                llvm = await get_llvm_config(llvm_version)
            except ValueError:
                llvm = await get_llvm_config(self.opts.ikos_llvm)

        if self.opts.ikos_llvm_ir is None:
            async with self.__build(llvm) as (ir_bundle, renamed):
                if self.config.keep_tmps:
                    shutil.copyfile(ir_bundle, self.tool_dir / ir_bundle.name)
                completed = await self.__analyze(ir_bundle, renamed, llvm)
        else:
            completed = await self.__analyze(self.opts.ikos_llvm_ir, [], llvm)
        doc = sarif.loads(completed.stdout)
        self.invocations = completed.get_sarif_invocation()
        return doc

    async def __analyze(
        self, llvm_ir_file: StrPath, entry_points: t.Iterable[str], llvm: LLVMConfig
    ) -> process.CompletedProcess:
        output_db = self.tool_dir / "output.db"
        args: list[StrBytesPath] = [self.program, "--format=sarif", "-q", "-o", output_db]
        if self.opts.ikos_find_entrypoints:
            callgraph = await CallGraph.from_llvm_ir(llvm_ir_file, llvm=llvm)
            entry_points = callgraph.global_root_functions
            logger.info("Found the entry points: %s", entry_points)
            args += ["-e", ",".join(entry_points)]
        elif self.opts.ikos_entrypoints_file:
            entry_points = self.opts.ikos_entrypoints_file.read_text().strip().split("\n")
            args += ["-e", ",".join(entry_points)]
        elif entry_points:
            args += ["-e", ",".join(entry_points)]
        return await process.run(*args, *self.opts.ikos_args, llvm_ir_file, stdout=PIPE, stderr=self.sink)

    @asynccontextmanager
    async def __build(self, llvm: LLVMConfig) -> AsyncIterator[tuple[Path, frozenset[str]]]:
        builder = unity.InMemoryBuilder(
            self.opts.compile_db, llvm, fail_on_error=False, rename_symbols=self.opts.ikos_rename_symbols
        )
        with fs.temp_file(suffix=".bc") as file:
            logger.info("Preparing LLVM IR bundle for %s", self.name)
            await builder(t.cast(t.IO[bytes], file))
            yield Path(file.name), builder.renamed_entry_points

    async def __version(self) -> tuple[int, ...] | None:
        result = await process.run("ikos", "--version", capture_output=True)
        if match := re.match(r"^ikos (\S+)", result.stdout_text):
            version_str = match.group(1)
            components = version_str.split(".")
            try:
                return tuple(map(int, components))
            except ValueError:
                pass
        return None

    @property
    def transforms(self) -> list[Transform]:
        return [
            truncate_stacks(self.opts.ikos_truncate_stacks),
            update_results(
                [
                    (lambda r: r.level == Level.ERROR, lambda r: attrs.evolve(r, rank=100)),
                    (None, lambda r: attrs.evolve(r, rank=40)),
                ]
            ),
            *super().transforms,
            _PrependResultLocationToStacks(),
            TransformSarifAddInvocations(self.name, self.invocations),
        ]


class _PrependResultLocationToStacks(Visitor[Options]):
    def __init__(self) -> None:
        self._top_frame: StackFrame | None = None
        self._result: Result | None = None

    def visit_Result(self, node: Result, opts: Options) -> Result:
        with self._enter_result(node):
            return self.generic_visit(node, opts)

    @contextmanager
    def _enter_result(self, result: Result) -> Iterator[None]:
        try:
            (location,) = result.locations
        except ValueError:
            pass
        else:
            if not location.message:
                location = attrs.evolve(location, message=result.message)
            self._top_frame = StackFrame(location=location)
        yield
        self._top_frame = None

    def visit_Stack(self, node: Stack, opts: Options) -> Stack:
        if not self._top_frame:
            return node
        frames = (self._top_frame, *node.frames)
        return attrs.evolve(node, frames=frames)
