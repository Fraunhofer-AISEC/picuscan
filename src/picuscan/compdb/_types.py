# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shlex
import typing as t
from pathlib import Path

import attrs

from picuscan import gcc
from picuscan.constants import LANGUAGES, Language


# commands is inferred as Iterable[Unknown] in CompilationDB.__init__() without this
def _commands_converter(iterable: t.Iterable[Command]) -> tuple[Command, ...]:
    return tuple(iterable)


@attrs.frozen
class CompilationDB:
    commands: t.Sequence[Command] = attrs.field(converter=_commands_converter)
    path: Path | None = None

    @property
    def files(self) -> t.Iterator[Path]:
        for cmd in self:
            yield cmd.path

    @property
    def include_dirs(self) -> t.Iterator[Path]:
        for cmd in self:
            yield from cmd.include_dirs

    def __iter__(self) -> t.Iterator[Command]:
        return iter(self.commands)

    def __len__(self) -> int:
        return len(self.commands)


@attrs.frozen(kw_only=True)
class _CommandMixin:
    directory: Path
    file: Path
    output: str | None = None

    @property
    def path(self) -> Path:
        """This returns `file` as an absolute path."""
        return self.directory / self.file


def _arguments_converter(iterable: t.Iterable[str]) -> tuple[str, ...]:
    return tuple(iterable)


@attrs.frozen
class Command(_CommandMixin):
    arguments: t.Sequence[str] = attrs.field(converter=_arguments_converter)

    @property
    def command(self) -> str:
        return shlex.join(self.arguments)

    @property
    def language(self) -> Language | None:
        return LANGUAGES.get(self.file.suffix)

    @property
    def gcc_options(self) -> tuple[gcc.Options, list[str]]:
        return gcc.parse(self.arguments[1:])

    @property
    def include_dirs(self) -> t.Iterator[Path]:
        flags, _ = self.gcc_options
        yield from flags.include_dirs

    def with_arguments(self, *args: str) -> Command:
        return attrs.evolve(self, arguments=args)


@attrs.frozen
class ShellCommand(_CommandMixin):
    command: str
