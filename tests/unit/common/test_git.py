# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from picuscan.misc.git import Repository, init, is_repository
from picuscan.misc.git.status import Flag, _Regular, _Untracked

skip = pytest.mark.skipif(not shutil.which("git"), reason="Git is not installed")


@skip
@pytest.mark.asyncio
async def test_is_repository(tmp_path: Path):
    subprocess.check_call(["git", "init"], cwd=tmp_path)
    assert await is_repository(tmp_path)


@skip
@pytest.mark.asyncio
async def test_is_repository_empty(tmp_path: Path):
    assert not await is_repository(tmp_path)


@skip
@pytest.mark.asyncio
async def test_is_repository_not(tmp_path: Path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    assert not await is_repository(tmp_path)


@skip
@pytest.mark.asyncio
async def test_init(tmp_path: Path):
    repo = await init(tmp_path)
    assert repo.cwd == tmp_path
    git_dir = tmp_path / ".git"
    assert git_dir.exists()


@pytest.fixture
async def repo(tmp_path: Path):
    return await init(tmp_path)


@skip
@pytest.mark.asyncio
async def test_status(repo: Repository):
    foo = repo.cwd / "foo"
    foo.touch()
    bar = repo.cwd / "bar"
    bar.touch()

    await repo.add([foo.name])

    st = await repo.status()
    assert len(st) == 2
    assert _Regular(Flag.ADDED, Flag.UNMODIFIED, Path(foo.name)) in st
    assert _Untracked(Flag.UNTRACKED, Flag.UNTRACKED, Path(bar.name)) in st


@skip
@pytest.mark.asyncio
async def test_status_empty(repo: Repository):
    st = await repo.status()
    assert not st


@skip
@pytest.mark.asyncio
async def test_status_rename(repo: Repository):
    foo = repo.cwd / "foo"
    foo.touch()

    await repo.add([foo.name])
    await repo.commit("foo", [foo.name])
    await repo._git("mv", foo.name, "bar")

    (ent,) = await repo.status()
    assert ent.index == Flag.RENAMED
    assert ent.work_tree == Flag.UNMODIFIED
    assert ent.path == Path("bar")
    assert ent.orig == Path(foo.name)


@skip
@pytest.mark.asyncio
async def test_add(repo: Repository):
    foo = repo.cwd / "foo"
    foo.touch()
    await repo.add([foo])
    (ent,) = await repo.status()
    assert ent.index == Flag.ADDED
    assert ent.work_tree == Flag.UNMODIFIED
    assert ent.path == Path(foo.name)


@skip
@pytest.mark.asyncio
async def test_add_all(repo: Repository):
    foo = repo.cwd / "foo"
    foo.touch()
    bar = repo.cwd / "bar"
    bar.touch()
    await repo.add([Path(".")])

    st = await repo.status()
    assert len(st) == 2
    assert _Regular(Flag.ADDED, Flag.UNMODIFIED, Path(foo.name)) in st
    assert _Regular(Flag.ADDED, Flag.UNMODIFIED, Path(bar.name)) in st


@skip
@pytest.mark.asyncio
async def test_commit(repo: Repository):
    foo = repo.cwd / "foo"
    foo.touch()
    await repo.add([foo])
    await repo.commit(message="foo")
    assert not await repo.status()
