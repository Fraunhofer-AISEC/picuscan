# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import shlex
from pathlib import Path

import attrs
from cattrs import GenConverter
from cattrs.preconf import json

from ._types import Command, CompilationDB, ShellCommand


def make_converter() -> GenConverter:
    c = json.make_converter(omit_if_default=True)

    c.register_structure_hook(Path, lambda o, _: Path(o))
    c.register_unstructure_hook(Path, os.fspath)

    handler = _CompilationDBHandler(c)
    c.register_structure_hook(CompilationDB, handler.structure)
    c.register_unstructure_hook(CompilationDB, handler.unstructure)

    return c


_Command = Command | ShellCommand


@attrs.frozen
class _CompilationDBHandler:
    converter: GenConverter

    def structure(self, o: object, _: type[CompilationDB]) -> CompilationDB:
        cmds = self.converter.structure(o, tuple[_Command, ...])
        return CompilationDB(map(self._normalize, cmds))

    def _normalize(self, cmd: _Command) -> Command:
        if isinstance(cmd, Command):
            return cmd
        else:
            arguments = shlex.split(cmd.command)
            return Command(arguments, directory=cmd.directory, file=cmd.file, output=cmd.output)

    def unstructure(self, db: CompilationDB) -> object:
        return self.converter.unstructure(db.commands)
