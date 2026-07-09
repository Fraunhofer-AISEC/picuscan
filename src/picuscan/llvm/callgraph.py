# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import re
from collections.abc import AsyncIterator, Set
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import networkx as nx

from picuscan import process
from picuscan.process import DEVNULL, PIPE
from picuscan.typing import StrPath

from .config import LLVMConfig, get_llvm_config


@dataclass(frozen=True, slots=True)
class CallGraph:
    graph: nx.DiGraph[str]
    symbols: Set[str]

    @classmethod
    async def from_llvm_ir(cls, path: StrPath, llvm: LLVMConfig | None = None) -> CallGraph:
        path = Path(path)
        if llvm is None:
            llvm = await get_llvm_config()

        # llvm-nm only works with bitcode files.
        async with _as_bitcode(path, llvm) as bitcode:
            graph, symbols = await asyncio.gather(_callgraph(bitcode, llvm), _symbols(bitcode, llvm))

        return cls(graph, symbols)

    @property
    def root_functions(self) -> set[str]:
        return {f for f, d in self.graph.in_degree if d == 0}

    @property
    def global_root_functions(self) -> set[str]:
        return {f for f in self.root_functions if f in self.symbols}


@asynccontextmanager
async def _as_bitcode(path: Path, llvm: LLVMConfig) -> AsyncIterator[Path]:
    if path.suffix == ".ll":
        with NamedTemporaryFile(suffix=".bc") as bitcode:
            await process.run(llvm.assembler, "-o", "-", path, stdout=bitcode, stderr=DEVNULL)
            bitcode.flush()
            yield Path(bitcode.name)
    else:
        # Hopefully, the file is already in bitcode format.
        yield path


_NODE_PATTERN = re.compile(rb"^Call graph node for function: '(.*)'<<")
_CALL_PATTERN = re.compile(rb"^\s*CS<[^>]+> calls function '(.*)'$")


async def _callgraph(path: Path, llvm: LLVMConfig) -> nx.DiGraph[str]:
    completed = await process.run(llvm.optimizer, "-print-callgraph", path, stdout=DEVNULL, stderr=PIPE)
    graph: nx.DiGraph[str] = nx.DiGraph()
    caller = None
    for line in completed.stderr.splitlines():
        if match := re.match(_NODE_PATTERN, line):
            caller = match.group(1).decode()
            graph.add_node(caller)
        elif caller:
            if match := re.match(_CALL_PATTERN, line):
                callee = match.group(1)
                graph.add_edge(caller, callee.decode())
    return graph


async def _symbols(path: Path, llvm: LLVMConfig) -> frozenset[str]:
    completed = await process.run(llvm.nm, path, capture_output=True)
    symbols: list[str] = []
    for record in completed.stdout.splitlines():
        fields = record.split()
        if fields[-2] == b"T":
            symbols.append(fields[-1].decode())
    return frozenset(symbols)
