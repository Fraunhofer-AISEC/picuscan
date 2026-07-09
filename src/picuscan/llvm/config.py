# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from functools import cached_property
from pathlib import Path

import attrs

from picuscan import process
from picuscan.typing import StrBytesPath


@attrs.frozen(kw_only=True, slots=False)
class LLVMConfig:
    """Information about the LLVM installation."""

    version: LLVMVersion
    prefix: Path

    @cached_property
    def bin_dir(self) -> Path:
        """Return `$(llvm-config --prefix)/bin`."""
        return self.prefix / "bin"

    def get_executable(self, name: str) -> Path:
        """Return `$(llvm-config --prefix)/bin/$name`."""
        return self.bin_dir / name

    @cached_property
    def compiler(self) -> Path:
        """Equivalent to `get_executable("clang")`."""
        return self.get_executable("clang")

    @cached_property
    def cxx_compiler(self) -> Path:
        """Equivalent to `get_executable("clang++")`."""
        return self.get_executable("clang++")

    @cached_property
    def assembler(self) -> Path:
        """Equivalent to `get_executable("llvm-as")`."""
        return self.get_executable("llvm-as")

    @cached_property
    def linker(self) -> Path:
        """Equivalent to `get_executable("llvm-link")`."""
        return self.get_executable("llvm-link")

    @cached_property
    def optimizer(self) -> Path:
        """Equivalent to `get_executable("opt")`."""
        return self.get_executable("opt")

    @cached_property
    def nm(self) -> Path:
        """Equivalent to `get_executable("llvm-nm")`."""
        return self.get_executable("llvm-nm")

    @property
    def version_str(self) -> str:
        return ".".join(map(str, self.version))


class LLVMVersion(t.NamedTuple):
    major: int
    minor: int
    patch: int


async def get_llvm_config(path: StrBytesPath | int = "llvm-config") -> LLVMConfig:
    if isinstance(path, int):  # path is a version number.
        path = f"llvm-config-{path}"
    prefix = await _get_prefix(path)
    version = await _get_version(path)
    return LLVMConfig(version=version, prefix=prefix)


async def _get_prefix(path: StrBytesPath) -> Path:
    completed = await process.run(path, "--prefix", stdout=process.PIPE, stderr=process.DEVNULL)
    return Path(completed.stdout_text.strip())


async def _get_version(path: StrBytesPath) -> LLVMVersion:
    completed = await process.run(path, "--version", stdout=process.PIPE, stderr=process.DEVNULL)
    stdout = completed.stdout_text.strip()
    return LLVMVersion(*map(int, stdout.split(".", 3)))
