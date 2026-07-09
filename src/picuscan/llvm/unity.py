# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import typing as t
from abc import ABC, abstractmethod
from pathlib import Path

import attrs
from llvmlite import binding as llvm
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


class InMemoryBuilder(AbstractBuilder):
    """This builder can manipulate the LLVM IR, but it only supports whichever
    LLVM versions that the `llvmlite` package supports."""

    renamed_symbols: dict[str, _RenamedSymbol]

    _renamed_symbol_callbacks: list[t.Callable[[str, _RenamedSymbol], None]]

    def __init__(
        self, compdb: CompilationDB, config: LLVMConfig, *, rename_symbols: bool = False, **kwds: Unpack[_BuilderKwds]
    ):
        super().__init__(compdb, config, **kwds)

        if not self.__is_llvm_compatible(config.version):
            raise LLVMVersionError(f"The requested LLVM version ({config.version_str}) is not supported.")

        self.rename_symbols = rename_symbols
        self.renamed_symbols = {}
        self._renamed_symbol_callbacks = []

    def __is_llvm_compatible(self, version: LLVMVersion) -> bool:
        major, _, _ = llvm.llvm_version_info
        return bool(major == version.major)

    async def __call__(self, output: t.IO[bytes]) -> None:
        compile_tasks = map(self.compile, self.compdb)
        if self.fail_on_error:
            modules = await asyncutils.gather(compile_tasks)
        else:
            modules_and_exceptions = await asyncutils.gather(compile_tasks, return_exceptions=True)
            modules = [x for x in modules_and_exceptions if isinstance(x, llvm.ModuleRef)]
        try:
            combined = self.link(modules)
        except Exception as err:
            raise UnityError(str(err)) from err
        output.write(combined.as_bitcode())
        output.flush()

    def link(self, modules: t.Sequence[llvm.ModuleRef]) -> llvm.ModuleRef:
        combined = llvm.parse_assembly("")
        for n, module in enumerate(modules):
            if self.rename_symbols:
                file = Path(module.source_file) if module.source_file != "<string>" else None
                # Only rename the main functions for now
                try:
                    function = module.get_function("main")
                    name = f"main#{n}"
                    renamed = _RenamedSymbol(function.name, file)
                    function.name = name
                    self.renamed_symbols[name] = renamed
                    self._run_renamed_symbol_callbacks(name, renamed)
                except NameError:
                    pass
            combined.link_in(module)
        return combined

    async def compile(self, cmd: Command) -> llvm.ModuleRef:
        self._run_compile_callbacks(cmd)
        try:
            result = await self._compile(cmd)
        except Exception as err:
            self._run_compile_done_callbacks(cmd, err)
            raise
        self._run_compile_done_callbacks(cmd)
        return result

    async def _compile(self, cmd: Command) -> llvm.ModuleRef:
        cmd.directory.mkdir(parents=True, exist_ok=True)
        compiler = self._get_compiler(cmd)
        args = [*cmd.arguments[1:], *_COMPILER_OPTIONS, "-o", "-"]
        try:
            completed = await process.run(compiler, *args, capture_output=True, cwd=cmd.directory)
            return llvm.parse_bitcode(completed.stdout)
        except process.CalledProcessError as err:
            diags = diagnostics.parse_output(err.stderr_text)
            errors = [d for d in diags if d.is_error]
            raise CompileError(cmd, errors) from err
        except Exception as err:
            raise UnityError(f"Failed to process the LLVM bitcode generated for {cmd.file}.") from err

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
