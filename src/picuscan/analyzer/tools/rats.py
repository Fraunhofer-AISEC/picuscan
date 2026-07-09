# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import subprocess
import re
from collections.abc import Iterator
from typing import IO, TypedDict, cast

import xmltodict

from picuscan import logging, process, sarif
from picuscan.analyzer.tool import Tool as AnalysisTool
from picuscan.analyzer.transforms import Transform, centuple_rank
from picuscan.process import TransformSarifAddInvocations
from picuscan.sarif.models import ColumnKind, Level, Location, Log, Result, Run, Tool, ToolComponent
from picuscan.typing import StrBytesPath

logger = logging.get_logger(__name__)

LEVELS = {"High": Level.WARNING, "Medium": Level.WARNING}


class Rats(TypedDict):
    rats_output: Output | None


class Output(TypedDict):
    vulnerability: Vulnerability | list[Vulnerability]


class Vulnerability(TypedDict):
    severity: str
    type: str
    message: str
    file: File | list[File]


class File(TypedDict):
    name: str
    line: str | list[str]


class RATS(AnalysisTool):
    async def run(self) -> Log:
        if from_ := self.opts.rats_from:
            logger.info("Reading %s findings from %s", self.name, from_.name)
            return self.__to_sarif(_parse(from_))

        logger.info("Running %s", self.name)
        args: list[StrBytesPath] = [
            "--xml",
            "--resultsonly",
            "--warning",
            "3",
            *self.opts.rats_args,
            *self.opts.compile_db.files,
            *self.opts.in_scope,
        ]
        completed = await process.run(self.program, *args, stdout=process.PIPE, stderr=process.DEVNULL)
        self.invocations = completed.get_sarif_invocation()
        return self.__to_sarif(_parse(completed.stdout))

    def __to_sarif(self, doc: Rats) -> Log:
        results: list[Result] = []

        output = doc["rats_output"] or {"vulnerability": []}
        vulnerability = output["vulnerability"]
        vulnerabilities = vulnerability if isinstance(vulnerability, list) else [vulnerability]

        for v in vulnerabilities:
            level = LEVELS.get(v["severity"], sarif.Level.NOTE)
            type = v.get("type", "unknown")
            message = _strip(v["message"])

            file = v["file"]
            files = file if isinstance(file, list) else [file]
            for location in _locations(files):
                results.append(Result(ruleId=type, level=level, message=sarif.message(message), locations=(location,)))

        full_name = _get_version()
        res = re.search(r"\d+\.\d+", full_name)
        assert res
        version = res.group(0)
        run = Run(
            tool=Tool(driver=ToolComponent(name=self.name, fullName=full_name, version=version)),
            results=frozenset(results),
            columnKind=ColumnKind.UNICODE_CODE_POINTS,
        )
        return sarif.log([run])

    @property
    def transforms(self) -> list[Transform]:
        return [
            centuple_rank(),
            *super().transforms,
            TransformSarifAddInvocations(self.name, self.invocations),
        ]


def _parse(input: bytes | IO[bytes]) -> Rats:
    return cast(Rats, xmltodict.parse(input, dict_constructor=dict))


def _strip(s: str) -> str:
    lines = s.split("\n")
    return " ".join(map(str.strip, lines))


def _locations(files: list[File]) -> Iterator[Location]:
    for f in files:
        line = f["line"]
        lines = line if isinstance(line, list) else [line]
        yield from [sarif.location(f["name"], line) for line in lines]


def _get_version() -> str:
    return subprocess.run(["rats", "--help"], stdout=subprocess.PIPE).stdout.decode().split("\n")[0]
