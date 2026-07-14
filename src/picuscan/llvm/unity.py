# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
import shutil
import subprocess
import typing as t
from abc import ABC, abstractmethod
from pathlib import Path

import attrs
from typing_extensions import Unpack

from picuscan import fs, process
from picuscan.compdb import Command, CompilationDB
from picuscan.constants import Language
from picuscan.gcc import diagnostics
from picuscan.misc import asyncutils
from picuscan.typing import StrBytesPath

from .config import LLVMConfig, LLVMVersion


class _BuilderKwds(t.TypedDict, total=False):
    fail_on_error: bool


class AbstractBuilder(ABC):
    _compile_callbacks: list[t.Callable[[Command], None]]
    _compile_done_callbacks: list[t.Callable[[Command, BaseException | None], None]]

    def __init__(self, compdb: CompilationDB, config: LLVMConfig, **kwds: Unpack[_BuilderKwds]):
        self.compdb = compdb
        self.config = config
        self.fail_on_error = kwds.get("fail_on_error", True)

        self._compile_callbacks = []
        self._compile_done_callbacks = []

    @abstractmethod
    def __call__(self, output: t.IO[bytes]) -> t.Awaitable[None]:
        raise NotImplementedError

    def register_compile_callback(self, func: t.Callable[[Command], None]) -> None:
        self._compile_callbacks.append(func)

    def register_compile_done_callback(self, func: t.Callable[[Command, BaseException | None], None]) -> None:
        self._compile_done_callbacks.append(func)

    def _run_compile_callbacks(self, cmd: Command) -> None:
        for func in self._compile_callbacks:
            try:
                func(cmd)
            except Exception:
                pass

    def _run_compile_done_callbacks(self, cmd: Command, exc: BaseException | None = None) -> None:
        for func in self._compile_done_callbacks:
            try:
                func(cmd, exc)
            except Exception:
                pass

    def _get_compiler(self, cmd: Command) -> Path:
        match cmd.language:
            case Language.CXX:
                return self.config.cxx_compiler
            case _:
                return self.config.compiler


_COMPILER_OPTIONS = ["-g", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone"]


class GenericBuilder(AbstractBuilder):
    """This builder supports any version of LLVM."""

    async def __call__(self, output: t.IO[bytes]) -> None:
        with fs.temp_dir() as dir:
            compile_tasks = [self.compile(cmd, dir / self.__mangle_path(cmd.file)) for cmd in self.compdb]
            if self.fail_on_error:
                modules = await asyncutils.gather(compile_tasks)
            else:
                modules_and_exceptions = await asyncutils.gather(compile_tasks, return_exceptions=True)
                modules = [o for o in modules_and_exceptions if not isinstance(o, BaseException)]
            await self.link(modules, output)

    def __mangle_path(self, path: Path) -> str:
        bitcode_file = path.with_suffix(".bc")
        s = os.fspath(bitcode_file)
        return s.replace(os.sep, "%")

    async def compile(self, cmd: Command, output: StrBytesPath) -> StrBytesPath:
        self._run_compile_callbacks(cmd)
        try:
            result = await self._compile(cmd, output)
        except Exception as err:
            self._run_compile_done_callbacks(cmd, err)
            raise
        self._run_compile_done_callbacks(cmd)
        return result

    async def _compile(self, cmd: Command, output: StrBytesPath) -> StrBytesPath:
        cmd.directory.mkdir(parents=True, exist_ok=True)
        compiler = self._get_compiler(cmd)
        args = [*cmd.arguments[1:], *_COMPILER_OPTIONS, "-o", output]
        try:
            await process.run(compiler, *args, stdout=process.DEVNULL, stderr=process.PIPE, cwd=cmd.directory)
        except process.CalledProcessError as err:
            diags = diagnostics.parse_output(err.stderr_text)
            errors = [d for d in diags if d.is_error]
            raise CompileError(cmd, errors) from err
        return output

    async def link(self, files: t.Sequence[StrBytesPath], output: t.IO[bytes]) -> None:
        if not files:
            raise UnityError("Nothing to link")
        try:
            await process.run(self.config.linker, "-S", *files, stdout=output, stderr=process.PIPE)
        except process.CalledProcessError as err:
            msg = err.stderr_text.strip()
            if msg.startswith("error: "):
                msg = msg[7:]
            raise UnityError(msg) from err


_T = t.TypeVar("_T")


def _resolve_llvm14_config() -> LLVMConfig:
    """Locate LLVM 14 via ``llvm-config-14``.

    Multiple LLVM versions can be installed simultaneously, where any version
    can be the default ``llvm-config``.  Using ``llvm-config-14`` ensures that
    LLVM 14 is used regardless of the default.  If ``llvm-config-14`` is not
    available, a ``RuntimeError`` is raised."""
    llvm_config = shutil.which("llvm-config-14")
    if llvm_config is None:
        raise RuntimeError("LLVM 14 is required but llvm-config-14 was not found on PATH.")
    try:
        prefix = subprocess.check_output([llvm_config, "--prefix"], text=True).strip()
        version = subprocess.check_output([llvm_config, "--version"], text=True).strip()
    except (subprocess.CalledProcessError, OSError) as err:
        raise RuntimeError(f"LLVM 14 is required but llvm-config-14 failed: {err}") from err
    return LLVMConfig(version=LLVMVersion(*map(int, version.split(".", 3))), prefix=Path(prefix))


class InMemoryBuilder(GenericBuilder):
    """This builder uses clang tools directly to compile and link LLVM bitcode.
    Unlike `GenericBuilder`, it can rename `main` functions to avoid symbol
    conflicts during linking. LLVM 14 is required and is located via
    ``llvm-config-14``, so it works regardless of the default ``llvm-config``."""

    renamed_symbols: dict[str, _RenamedSymbol]

    _renamed_symbol_callbacks: list[t.Callable[[str, _RenamedSymbol], None]]

    def __init__(
        self,
        compdb: CompilationDB,
        config: LLVMConfig | None = None,
        *,
        rename_symbols: bool = False,
        **kwds: Unpack[_BuilderKwds],
    ):
        # The InMemoryBuilder requires LLVM 14. Multiple LLVM versions can be
        # installed simultaneously, where any version can be the default
        # ``llvm-config``. We use ``llvm-config-14`` to locate LLVM 14
        # specifically; if it is not available, a RuntimeError is raised.
        resolved = _resolve_llvm14_config()
        super().__init__(compdb, resolved, **kwds)

        self.rename_symbols = rename_symbols
        self.renamed_symbols = {}
        self._renamed_symbol_callbacks = []

    async def _compile(self, cmd: Command, output: StrBytesPath) -> StrBytesPath:
        await super()._compile(cmd, output)
        if self.rename_symbols:
            try:
                await self._rename_main(cmd, output)
            except Exception as err:
                raise UnityError(f"Failed to process the LLVM bitcode generated for {cmd.file}.") from err
        return output

    async def _rename_main(self, cmd: Command, output: StrBytesPath) -> None:
        completed = await process.run(self.config.disassembler, output, capture_output=True)
        content = completed.stdout_text
        if not re.search(r"@main\b", content):
            return
        n = len(self.renamed_symbols)
        new_name = f"main#{n}"
        renamed = _RenamedSymbol(name="main", file=cmd.file)
        self.renamed_symbols[new_name] = renamed
        self._run_renamed_symbol_callbacks(new_name, renamed)
        try:
            content = re.sub(r"@main\b", f'@"{new_name}"', content)
            with fs.temp_file(mode="w", suffix=".ll") as ll_file:
                ll_file.write(content)
                ll_file.flush()
                await process.run(
                    self.config.assembler,
                    ll_file.path,
                    "-o",
                    output,
                    stdout=process.DEVNULL,
                    stderr=process.PIPE,
                )
        except Exception:
            self.renamed_symbols.pop(new_name, None)
            raise

    async def link(self, files: t.Sequence[StrBytesPath], output: t.IO[bytes]) -> None:
        if not files:
            raise UnityError("Nothing to link")
        try:
            await process.run(self.config.linker, *files, stdout=output, stderr=process.PIPE)
        except process.CalledProcessError as err:
            msg = err.stderr_text.strip()
            if msg.startswith("error: "):
                msg = msg[7:]
            raise UnityError(msg) from err

    @property
    def renamed_entry_points(self) -> frozenset[str]:
        return frozenset(sym for (sym, renamed) in self.renamed_symbols.items() if renamed.name == "main")

    def register_renamed_symbol_callback(self, func: t.Callable[[str, _RenamedSymbol], None]) -> None:
        self._renamed_symbol_callbacks.append(func)

    def _run_renamed_symbol_callbacks(self, name: str, renamed: _RenamedSymbol) -> None:
        for func in self._renamed_symbol_callbacks:
            try:
                func(name, renamed)
            except Exception:
                pass


@attrs.frozen
class _RenamedSymbol:
    name: str
    """The original name of the symbol."""
    file: Path | None


class UnityError(Exception):
    pass


class LLVMVersionError(UnityError):
    pass


class CompileError(UnityError):
    def __init__(self, cmd: Command, errors: t.Sequence[diagnostics.Diagnostic]):
        details = "\n".join([f" {err.msg} @ line {err.location.line}" for err in errors])
        super().__init__(f"Failed to compile {cmd.file}:\n{details}")
        self.cmd = cmd
        self.diagnostics = errors
