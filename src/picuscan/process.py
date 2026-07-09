# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""Our main module for spawning processes and running programs. This
wraps the `asyncio` module in the standard library and uses a semaphore
to ensure that we do not spawn too many processes simultaneously."""

from __future__ import annotations

import typing as t
from abc import ABC
from asyncio import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cached_property

import attrs
from typing_extensions import Unpack

from picuscan.config import acquire_job_semaphore
from picuscan.logging import Tracer, get_logger
from picuscan.misc.strutils import SHELL, join
from picuscan.typing import StrBytesPath
from picuscan.sarif.models import Invocation, Run
from picuscan.analyzer.options import Options
from picuscan.sarif.visitor import Visitor

_FD = int | t.IO[t.Any] | None

PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT
DEVNULL = subprocess.DEVNULL

logger = get_logger(__name__)
tracer = Tracer(logger)


class _SpawnKwds(t.TypedDict, total=False):
    stdin: _FD
    stdout: _FD
    stderr: _FD
    cwd: StrBytesPath | None
    limit: int


@tracer.trace_async
async def spawn(program: StrBytesPath, /, *args: StrBytesPath, **kwds: Unpack[_SpawnKwds]) -> subprocess.Process:
    async with acquire_job_semaphore():
        return await subprocess.create_subprocess_exec(program, *args, **kwds)


@tracer.trace_async
async def run(
    program: StrBytesPath,
    /,
    *args: StrBytesPath,
    input: str | bytes | None = None,
    capture_output: bool = False,
    discard_output: bool = False,
    check: bool | int | t.Container[int] = True,
    **kwds: Unpack[_SpawnKwds],
) -> CompletedProcess:
    """Run a program.
    @input: Write the value to the stdin of the program. This implies `stdin=PIPE`.
    @capture_output: Set `stdout` and `stderr` to `PIPE`.
    @discard_output: Set `stdout` and `stderr` to `DEVNULL`.
    @check: Depending on the value of this parameter and the return code
    of the process, raise a `CalledProcessError`. See `CompletedProcess.check_returncode()`
    for more details."""
    if input is not None:
        if kwds.get("stdin") is not None:
            raise ValueError("stdin and input arguments cannot be used in combination.")
        kwds["stdin"] = PIPE
        if isinstance(input, str):
            input = input.encode()

    if capture_output or discard_output:
        if capture_output and discard_output:
            raise ValueError("capture_output and discard_output arguments cannot be used in combination.")
        if capture_output:
            kwds.setdefault("stdout", PIPE)
            kwds.setdefault("stderr", PIPE)
            kwds.setdefault("limit", 128 * 1024)  # Line buffer limit 128k
        else:
            kwds.setdefault("stdout", DEVNULL)
            kwds.setdefault("stderr", DEVNULL)

    t_start = datetime.now(timezone.utc).isoformat()
    proc = await spawn(program, *args, **kwds)
    out, err = await proc.communicate(input)
    assert proc.returncode is not None
    t_end = datetime.now(timezone.utc).isoformat()

    cmd = program, *args
    completed = CompletedProcess(cmd, proc.returncode, out, err, t_start, t_end)

    if check is not False:
        completed.check_returncode(None if check is True else check)

    return completed


class _CompletedProcessBase(ABC):
    _stdout: bytes | None
    _stderr: bytes | None

    @cached_property
    def stdout(self) -> bytes:
        """The captured stdout output. Return an empty byte string if
        nothing was captured."""
        return b"" if self._stdout is None else self._stdout

    def has_stdout(self) -> bool:
        return self._stdout is not None

    @cached_property
    def stdout_text(self) -> str:
        """Shortcut for `stdout.decode()`."""
        return "" if self._stdout is None else self._stdout.decode()

    @cached_property
    def stderr(self) -> bytes:
        """The captured stderr output. Return an empty byte string if
        nothing was captured."""
        return b"" if self._stderr is None else self._stderr

    def has_stderr(self) -> bool:
        return self._stderr is not None

    @cached_property
    def stderr_text(self) -> str:
        """Shortcut for `stderr.decode()`."""
        return "" if self._stderr is None else self._stderr.decode()


@attrs.frozen
class CompletedProcess(_CompletedProcessBase):
    args: t.Sequence[StrBytesPath]
    returncode: int
    _stdout: bytes | None
    _stderr: bytes | None
    t_start: str
    t_end: str

    def check_returncode(self, code: int | t.Container[int] | None = None) -> None:
        """Raise a `CalledProcessError` if:
        * `code` is `None` (the default) and `returncode` is not 0.
        * `code` is an `int` and `returncode` is not equal to `code`.
        * `code` is a container and `returncode` is not a member."""
        if code is None:
            if self.returncode != 0:
                raise CalledProcessError(self.args, self.returncode, self._stdout, self._stderr)
        elif isinstance(code, int):
            if self.returncode != code:
                raise CalledProcessError(self.args, self.returncode, self._stdout, self._stderr)
        elif self.returncode not in code:
            raise CalledProcessError(self.args, self.returncode, self._stdout, self._stderr)

    def get_sarif_invocation(self) -> list[Invocation]:
        return [
            Invocation(
                # execute will raise if exit code != 0
                executionSuccessful=True,
                arguments=list(map(str, self.args)),
                exitCode=self.returncode,
                startTimeUtc=self.t_start,
                endTimeUtc=self.t_end,
            )
        ]


@attrs.frozen
class CalledProcessError(_CompletedProcessBase, Exception):
    cmd: t.Sequence[StrBytesPath]
    returncode: int
    _stdout: bytes | None
    _stderr: bytes | None

    def __str__(self) -> str:
        return f"{join(self.cmd, SHELL)!r} returned exit status {self.returncode}."


@dataclass
class TransformSarifAddInvocations(Visitor[Options]):
    """Set the invocations attribute of the Run, after loading the SARIF result"""

    tool: str
    invocations: list[Invocation]

    def visit_Run(self, run: Run, opts: Options) -> Run:
        if run.tool.driver.name == self.tool:
            return attrs.evolve(run, invocations=self.invocations)
        return run
