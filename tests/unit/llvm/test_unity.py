# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from picuscan.compdb import Command, CompilationDB
from picuscan.llvm import unity
from picuscan.llvm.config import get_llvm_config

LLVM_MIN = 7
LLVM_MAX = 16
LLVM_CONFIG_TRY = ["llvm-config"] + [f"llvm-config-{v}" for v in range(LLVM_MIN, LLVM_MAX + 1)]
LLVM_CONFIG = next((p for p in map(shutil.which, LLVM_CONFIG_TRY) if p), None)

GOOD = "int f() { return 0; }"
BAD = "int f() { return 0 }"
MAIN = "int f(void); int main() { return f(); }"


@pytest.mark.skipif(not LLVM_CONFIG, reason="LLVM is not installed")
@pytest.mark.asyncio
async def test_unity_build(mocker: MockerFixture, tmp_path: Path):
    assert LLVM_CONFIG
    llvm = await get_llvm_config(Path(LLVM_CONFIG))

    files = [["good.c", GOOD], ["bad.c", BAD], ["main.c", MAIN]]
    for name, content in files:
        p = tmp_path / name
        p.write_text(content)

    cmds = tuple(Command(("clang", "-c", "-g", "-std=c99", n), directory=tmp_path, file=Path(n)) for (n, _) in files)
    db = CompilationDB(cmds)

    spy = mocker.spy(unity.GenericBuilder, "compile")

    path = tmp_path / "foo.ll"
    with path.open("wb") as file:
        builder = unity.GenericBuilder(db, llvm, fail_on_error=False)
        await builder(file)

    assert path.exists()
    assert path.read_bytes()
    assert spy.call_count == 3


@pytest.mark.skipif(not LLVM_CONFIG, reason="LLVM is not installed")
@pytest.mark.asyncio
async def test_unity_build_fail(mocker: MockerFixture, tmp_path: Path):
    assert LLVM_CONFIG
    llvm = await get_llvm_config(Path(LLVM_CONFIG))

    file = tmp_path / "bad.c"
    file.write_text(BAD)

    cmd = Command(("clang", "-c", "-g", "-std=c99", "bad.c"), directory=tmp_path, file=Path("bad.c"))
    db = CompilationDB((cmd,))

    spy = mocker.spy(unity.GenericBuilder, "compile")

    path = tmp_path / "bad.ll"
    with path.open("wb") as file:
        builder = unity.GenericBuilder(db, llvm, fail_on_error=False)
        with pytest.raises(unity.UnityError):
            await builder(file)

    assert not path.read_bytes()
    assert spy.call_count == 1
