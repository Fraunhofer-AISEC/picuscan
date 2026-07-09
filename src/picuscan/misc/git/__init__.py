# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This is a simple wrapper around Git."""

from __future__ import annotations

import typing as t
from pathlib import Path
from typing import Iterable

import attrs

from picuscan import fs, process
from picuscan.misc.strutils import join
from picuscan.typing import StrBytesPath, StrPath

from . import status

GIT_DIR = ".git"


@attrs.frozen
class Repository:
    cwd: Path

    async def add(self, pathspecs: t.Iterable[StrBytesPath] = (), ignore_errors: bool = False) -> None:
        args = ["--pathspec-from-file=-", "--pathspec-file-nul"]
        if ignore_errors:
            args.append("--ignore-errors")
        await self._git("add", *args, input=join(pathspecs, "\0"))

    async def commit(
        self, message: str, pathspecs: Iterable[StrBytesPath] = (), all: bool = False, allow_empty: bool = False
    ) -> None:
        with fs.temp_file("w") as f:
            f.write(message)
            f.flush()
            opts = ["-F", f.name, "--pathspec-from-file=-", "--pathspec-file-nul"]
            if all:
                opts.append("-a")
            if allow_empty:
                opts.append("--allow-empty")
            await self._git("commit", *opts, input=join(pathspecs, "\0"))

    async def status(self, paths: Iterable[Path] | None = None) -> status.Status:
        """
        Return the status of the repository.
        @paths: Filter the status to have only these paths.
        """
        completed = await self._git("status", "--porcelain", "-z", stdout=process.PIPE)
        return status.parse(completed.stdout_text, None if paths is None else set(paths))

    async def is_dirty(
        self, paths: Iterable[Path] | None = None, index: bool = True, work_tree: bool = True, untracked: bool = True
    ) -> bool:
        """
        Return whether the working tree and/or the index is dirty.
        @paths: Return true only if these files are dirty.
        @index: Whether to consider the index.
        @work_tree: Whether to consider the working tree.
        @untracked: Whether untracked files should be considered dirty.
        """
        st = await self.status(paths)
        return st.is_dirty(index, work_tree, untracked)

    def _git(
        self,
        cmd: str,
        *args: StrBytesPath,
        stdin: int | t.IO[t.Any] | None = None,
        stdout: int | t.IO[t.Any] | None = process.DEVNULL,
        stderr: int | t.IO[t.Any] | None = process.DEVNULL,
        input: str | bytes | None = None,
    ) -> t.Awaitable[process.CompletedProcess]:
        return process.run("git", cmd, *args, stdin=stdin, input=input, stdout=stdout, stderr=stderr, cwd=self.cwd)


async def init(dir: StrPath) -> Repository:
    """Initialize a repository in `dir` and return a `Repository` object for it."""
    await process.run("git", "init", discard_output=True, cwd=dir)
    return Repository(Path(dir))


async def is_repository(dir: StrBytesPath) -> bool:
    """Check if `dir` is a Git repository."""
    try:
        await process.run("git", "status", "--porcelain", discard_output=True, cwd=dir)
        return True
    except process.CalledProcessError:
        return False
