# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm

from picuscan import logging, process, sarif
from picuscan.analyzer.tool import Tool as AnalysisTool
from picuscan.analyzer.transforms import Transform
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.misc.collections import GlobSet
from picuscan.process import DEVNULL, PIPE, STDOUT
from picuscan.sarif.models import (
    CodeFlow,
    Level,
    Log,
    PropertyBag,
    Result,
    Run,
    ThreadFlow,
    ThreadFlowLocation,
    Tool,
    ToolComponent,
    Invocation,
)

logger = logging.get_logger(__name__)

PROGRESS_PATTERN = re.compile(rb".*\[(\d+)/(\d+)] \S+ analyzed")

LEVELS = {"CRITICAL": Level.ERROR, "HIGH": Level.ERROR, "MEDIUM": Level.WARNING, "STYLE": Level.NOTE}

NOTES = GlobSet(["clang-diagnostic-unused-*"])


def _get_failed_sources(out_dir: Path) -> set[str]:
    meta = json.loads((out_dir / "metadata.json").read_text())
    failed_sources: set[str] = set()
    for tool in meta["tools"]:
        for _, opts in tool["analyzers"].items():
            failed_sources.update(opts["analyzer_statistics"]["failed_sources"])
    return failed_sources


class CodeChecker(AnalysisTool):
    override_program = "CodeChecker"
    supports_threading = True

    def split_result_per_tool(self, results: list[Result], invocations: list[Invocation]) -> list[Run]:
        meta = json.load(open(self.tool_dir / "output" / "metadata.json"))
        runs: list[Run] = []
        for tool in meta["tools"]:
            tool_name = tool["name"]
            full_version = tool["version"].strip()
            res = re.search(r"\d+\.\d+(\.\d+)?", full_version)
            assert res
            version = res.group(0)
            run = sarif.Run(
                tool=Tool(
                    driver=ToolComponent(name=tool_name, fullName=f"{tool_name}, {full_version}", version=version),
                ),
                invocations=invocations,
                results=frozenset([]),
            )
            runs.append(run)
            for analyzer_name, analyzer in tool["analyzers"].items():
                analyzer_results = list(filter(lambda x: x.ruleId in analyzer["checkers"], results))
                full_version = analyzer["analyzer_statistics"]["version"].strip().replace("\n", ",")
                res = re.search(r"\d+\.\d+(\.\d+)?", full_version)
                assert res
                version = res.group(0)
                run = sarif.Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name=analyzer_name, fullName=f"{analyzer_name}, {full_version}", version=version
                        ),
                    ),
                    invocations=invocations,
                    results=frozenset(analyzer_results),
                )
                runs.append(run)
        return runs

    async def run(self) -> Log:
        version_str = await self.__version_str()
        version = tuple(map(int, version_str.split(".", 2)))
        if version < (6, 18, 0):
            raise RuntimeError("A more recent version of CodeChecker (>=6.18) is required")

        doc, invocations = await self.__run()
        assert doc["version"] == 1

        results: list[Result] = []

        reports = doc["reports"]

        for report in reports:
            path = report["file"]["path"]
            line = report["line"]
            column = report["column"]
            location = sarif.location(path, line, column)

            message = report["message"]
            checker_name = report["checker_name"]
            if checker_name in NOTES:
                level = Level.NOTE
            else:
                level = LEVELS.get(report["severity"], Level.WARNING)

            bug_path_events = report["bug_path_events"]
            code_flow = _code_flow(bug_path_events)

            results.append(
                Result(
                    properties=PropertyBag(severity=report["severity"]),
                    ruleId=checker_name,
                    level=level,
                    message=sarif.message(message),
                    locations=(location,),
                    codeFlows=(code_flow,),
                )
            )

        runs = self.split_result_per_tool(results, invocations)
        return sarif.log(runs)

    async def __version_str(self) -> str:
        result = await process.run(self.program, "analyzer-version", "-o", "json", stdout=PIPE, stderr=DEVNULL)
        doc = json.loads(result.stdout)
        try:
            version = doc["base_package_version"]
        except KeyError:
            version = doc["Base package version"]
        return str(version)

    async def __run(self) -> tuple[Any, list[Invocation]]:
        logger.info("Running %s", self.name)

        assert self.opts.compile_db.path
        out_dir = self.tool_dir / "output"

        args: list[str] = []
        if self.opts.codechecker_analyzers:
            args.append("--analyzers")
            args.extend(self.opts.codechecker_analyzers)
        if self.opts.codechecker_ctu:
            args.append("--ctu")
        if self.opts.codechecker_enable_all:
            args.append("--enable-all")
        if self.opts.codechecker_enable_alpha:
            args.append("--enable=alpha")
        if self.jobs:
            args.append(f"--jobs={self.jobs}")

        args = [
            self.program,
            "analyze",
            "-o",
            str(out_dir),
            *args,
            *self.opts.codechecker_args,
            str(self.opts.compile_db.path),
        ]
        t_start = datetime.now(timezone.utc).isoformat()
        proc = await process.spawn(
            *args,
            stdout=PIPE,
            stderr=STDOUT,
        )
        assert proc.stdout

        with tqdm(desc=self.name, total=100, bar_format=fixed_width_desc(), position=0) as progress:
            last = 0
            async for line in proc.stdout:
                self.sink.write(line)
                if match := re.match(PROGRESS_PATTERN, line):
                    current, total = match.groups()
                    percent = int(int(current) / int(total) * 100)
                    progress.update(percent - last)
                    last = percent
            if last < 100:
                progress.update(100 - last)

        status = await proc.wait()
        t_end = datetime.now(timezone.utc).isoformat()
        assert status in {0, 3}
        if status == 3:
            self.failed_sources = _get_failed_sources(out_dir)

        result = await process.run(
            self.program, "parse", "-e", "json", out_dir, stdout=PIPE, stderr=DEVNULL, check=(0, 2)
        )

        invocations = [
            Invocation(
                executionSuccessful=True, arguments=args, exitCode=status, startTimeUtc=t_start, endTimeUtc=t_end
            )
        ]

        return json.loads(result.stdout), invocations

    @property
    def transforms(self) -> list[Transform]:
        return [*super().transforms]


def _code_flow(bug_path_events: Any) -> CodeFlow:
    locations: list[ThreadFlowLocation] = []
    for ev in bug_path_events:
        path = ev["file"]["path"]
        message = ev["message"]

        range = ev["range"]
        start_line = range["start_line"]
        start_col = range["start_col"]
        end_line = range["end_line"]
        end_col = range["end_col"]

        location = sarif.location(path, start_line, start_col, last_line=end_line, last_col=end_col, msg=message)
        locations.append(ThreadFlowLocation(location=location))
    return CodeFlow(threadFlows=(ThreadFlow(locations=tuple(locations)),))
