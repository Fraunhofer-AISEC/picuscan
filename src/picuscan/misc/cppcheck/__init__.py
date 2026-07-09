# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This module simplifies the usage of Cppcheck."""

from __future__ import annotations

import asyncio
import os
import re
import typing as t
from asyncio import StreamReader, StreamWriter
from datetime import datetime, timezone
from pathlib import Path

import xmltodict

from picuscan import process
from picuscan.misc import asyncutils
from picuscan.process import DEVNULL, PIPE
from picuscan.typing import StrBytesPath

from ._stdlib import all_headers
from .error import CppcheckError
from .event import Checked, Checking, Event
from .output import Output
from ...sarif import Invocation

_Files = t.Iterable[StrBytesPath]
_OnEvent = t.Callable[[Event], None]


async def execute(
    *args: StrBytesPath,
    files: _Files | None = None,
    stdout: t.IO[bytes] | None = None,
    on_event: _OnEvent | None = None,
) -> tuple[Output, list[Invocation]]:
    """
    Execute Cppcheck, parse the XML output and return an `Output` object.
    @args: These arguments are directly passed to the program.
    @files: A list of files to be processed by Cppcheck. This uses stdin
    to pass the list of files to Cppcheck, which is more efficient than
    passing them as arguments.
    @stdout: Write the output to this file.
    """
    t_start = datetime.now(timezone.utc).isoformat()
    cmd: list[StrBytesPath] = ["cppcheck", "--xml", "--xml-version=2"]
    if files is not None:
        cmd.append("--file-list=-")
    cmd.extend(args)

    spawn_stdin = DEVNULL if files is None else PIPE

    if on_event is None:
        spawn_stdout = DEVNULL if stdout is None else stdout
    else:
        spawn_stdout = PIPE

    proc = await process.spawn(*cmd, stdin=spawn_stdin, stdout=spawn_stdout, stderr=PIPE)

    if files is not None:
        assert proc.stdin
        stdin_handler = _stdin_handler(proc.stdin, files)
    else:
        stdin_handler = asyncutils.noop()

    if on_event is not None:
        assert proc.stdout
        stdout_handler = _stdout_handler(proc.stdout, on_event, stdout)
    else:
        stdout_handler = asyncutils.noop()

    assert proc.stderr

    _, err, _ = await asyncio.gather(stdout_handler, proc.stderr.read(), stdin_handler)

    code = await proc.wait()
    if code != 0:
        raise CppcheckError("cppcheck exited with a non-zero status code.")

    t_end = datetime.now(timezone.utc).isoformat()
    invocations = [
        Invocation(
            # execute will raise if exit code != 0
            executionSuccessful=True,
            arguments=list(map(str, cmd)),
            exitCode=0,
            startTimeUtc=t_start,
            endTimeUtc=t_end,
        )
    ]

    return parse(err), invocations


async def _stdin_handler(writer: StreamWriter, files: _Files) -> None:
    linesep = os.linesep.encode()
    for s in map(os.fsencode, files):
        writer.write(s)
        writer.write(linesep)
    writer.write_eof()
    await writer.drain()


_FILE_PATTERN = re.compile(rb"^Checking (.*) ...")
_PROGRESS_PATTERN = re.compile(rb"(\d+)/(\d+) files checked (\d+)% done")


async def _stdout_handler(reader: StreamReader, on_event: _OnEvent, stdout: t.IO[bytes] | None) -> None:
    async for s in reader:
        if stdout:
            stdout.write(s)
        if match := re.match(_FILE_PATTERN, s):
            (path,) = match.groups()
            on_event(Checking(Path(path.decode())))
        elif match := re.match(_PROGRESS_PATTERN, s):
            count, total, _ = match.groups()
            count, total = int(count), int(total)
            percent = int(count / total * 100)
            on_event(Checked(count, total, percent))


_INCLUDE_PATTERN = re.compile(r"^Include file: (<.*>|\".*\") not found.")


async def check_config(
    *args: StrBytesPath,
    files: _Files | None = None,
    stdout: t.IO[bytes] | None = None,
    on_event: _OnEvent | None = None,
) -> set[str]:
    """This is like `execute()`, but it also sets the `--check-config`
    flag of Cppcheck and returns a set of missing headers."""
    out, _ = await execute("--check-config", "--enable=all", *args, files=files, stdout=stdout, on_event=on_event)

    results = out["results"]
    if errors := results["errors"]:
        error = errors["error"]
        error_list = error if isinstance(error, list) else [error]
    else:
        error_list = []

    missing: set[str] = set()
    for err in error_list:
        if err["@id"] in {"missingInclude", "missingIncludeSystem"}:
            msg = err["@msg"]
            if match := re.match(_INCLUDE_PATTERN, msg):
                header = match.group(1)[1:-1]
                missing.add(header)

    return missing - all_headers


def parse(input: str | bytes | t.IO[bytes]) -> Output:
    return t.cast(Output, xmltodict.parse(input, dict_constructor=dict))
