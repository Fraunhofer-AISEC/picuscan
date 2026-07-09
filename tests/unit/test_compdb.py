# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import attr
import pytest
from cattrs.errors import BaseValidationError

from picuscan import compdb
from picuscan.compdb import Command
from picuscan.constants import Language

SHELL = {
    "command": "clang -std=c99 -O2 main.c -c -o main.c.o",
    "directory": "/tmp",
    "file": "main.c",
}

SIMPLE = {
    "arguments": ["clang", "-std=c99", "-O2", "main.c", "-c", "-o", "main.c.o"],
    "directory": "/tmp",
    "file": "main.c",
}


def test_shell_command():
    db = compdb.structure([SHELL])
    cmd = db.commands[0]
    assert cmd.directory == Path("/tmp")
    assert cmd.file == Path("main.c")
    assert cmd.output is None
    assert cmd.command == "clang -std=c99 -O2 main.c -c -o main.c.o"
    assert cmd.arguments == ("clang", "-std=c99", "-O2", "main.c", "-c", "-o", "main.c.o")


def test_simple_command():
    db = compdb.structure([SIMPLE])
    cmd = db.commands[0]
    assert cmd.directory == Path("/tmp")
    assert cmd.file == Path("main.c")
    assert cmd.output is None
    assert cmd.command == "clang -std=c99 -O2 main.c -c -o main.c.o"
    assert cmd.arguments == ("clang", "-std=c99", "-O2", "main.c", "-c", "-o", "main.c.o")


def test_multiple_commands():
    db = compdb.structure([SHELL, SIMPLE])
    (shell, simple) = db.commands
    assert shell.directory == simple.directory
    assert shell.file == simple.file
    assert shell.output == simple.output
    assert shell.command == simple.command
    assert shell.arguments == simple.arguments


def test_missing_fields():
    with pytest.raises(BaseValidationError):
        compdb.structure({"directory": "/tmp", "file": "main.c"})


def test_language():
    file = Path("main.c")
    cmd = Command(("gcc", "main.c"), directory=Path(), file=file)
    assert cmd.language == Language.C
    cmd = attr.evolve(cmd, file=file.with_suffix(".cpp"))
    assert cmd.language == Language.CXX
    cmd = attr.evolve(cmd, file=file.with_suffix(".py"))
    assert cmd.language is None


def test_include_dirs():
    arguments = ("gcc", "-I/usr/include", "-I", "/usr/local/include", "main.c")
    cmd = Command(arguments, directory=Path(), file=Path("main.c"))
    expected = ["/usr/include", "/usr/local/include"]
    assert list(cmd.include_dirs) == [Path(p) for p in expected]
