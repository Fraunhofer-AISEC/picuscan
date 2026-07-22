# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t
from os.path import abspath

import attrs
from tqdm import tqdm

from picuscan import logging, sarif
from picuscan.analyzer.options import Options
from picuscan.analyzer.tool import Tool as AnalysisTool
from picuscan.analyzer.transforms import Transform, inject_cwe_taxonomy, update_results
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.misc.cppcheck import check_config, execute, parse
from picuscan.misc.cppcheck.output import Location, Output
from picuscan.misc.cppcheck.tqdm import update_tqdm
from picuscan.sarif.models import (
    CodeFlow,
    ColumnKind,
    Invocation,
    Level,
    Location as SarifLocation,
    Log,
    ReportingDescriptorReference,
    Result,
    Run,
    ThreadFlow,
    ThreadFlowLocation,
    Tool,
    ToolComponent,
)

logger = logging.get_logger(__name__)

LEVELS = {"error": Level.ERROR, "warning": Level.WARNING}


class Cppcheck(AnalysisTool):
    rebase_locations = False  # --relative-paths already handles this.
    inject_cwe_mappings = False
    supports_threading = True
    uses_tqdm = True

    def __init__(self, opts: Options, **kwds: t.Any):
        super().__init__(opts, **kwds)
        self.inject_cwe = False

    async def run(self) -> Log:
        if from_ := self.opts.cppcheck_from:
            logger.info("Reading %s findings from %s", self.name, from_.name)
            doc = parse(from_)
            invocations: list[Invocation] = []
        else:
            doc, invocations = await self.__run()

        results = doc["results"]

        version = results["cppcheck"]["@version"]

        errors = results["errors"]
        error = [] if errors is None else errors["error"]
        error_list = error if isinstance(error, list) else [error]

        sarif_results: list[Result] = []

        for err in error_list:
            id = err["@id"]
            level = LEVELS.get(err["@severity"], Level.NOTE)
            msg = err["@verbose"]

            taxa = None
            if cwe := err.get("@cwe"):
                taxa = (ReportingDescriptorReference(id=f"CWE-{cwe}"),)
                self.inject_cwe = True

            location = err.get("location", [])
            code_flows: tuple[CodeFlow, ...] = ()
            if isinstance(location, list):
                if len(location) == 0:
                    locations = []
                else:
                    locations = [location[0]]
                if len(location) > 1:
                    # TODO: what is the correct order of the "analysis steps"?
                    thread_locations = tuple([ThreadFlowLocation(location=self.__location(loc)) for loc in location])
                    thread_flows = tuple([ThreadFlow(message=None, locations=thread_locations)])
                    code_flows = tuple([CodeFlow(threadFlows=thread_flows)])
            else:
                locations = [location]
            sarif_locations = tuple(self.__location(loc) for loc in locations)

            sarif_results.append(
                Result(
                    ruleId=id,
                    taxa=taxa or (),
                    level=level,
                    message=sarif.message(msg),
                    locations=sarif_locations,
                    codeFlows=code_flows,
                )
            )

        run = Run(
            tool=Tool(driver=ToolComponent(name=self.name, version=version)),
            invocations=invocations,
            results=frozenset(sarif_results),
            columnKind=ColumnKind.UNICODE_CODE_POINTS,
        )
        return sarif.log([run])

    async def __run(self) -> tuple[Output, list[Invocation]]:
        args = self.__args()

        logger.info("Checking configuration before running %s", self.name)
        if missing := await check_config(*args, stdout=self.sink):
            logger.warning("Missing headers: %s", ", ".join(missing))

        logger.info("Running %s", self.name)
        with tqdm(
            desc=self.name, total=100, bar_format=fixed_width_desc(), position=self.bar_position, leave=False
        ) as progress:
            doc, invocations = await execute(*args, stdout=self.sink, on_event=update_tqdm(progress))
            return doc, invocations

    def __args(self) -> list[str]:
        args: list[str] = [
            f"--project={self.opts.compile_db.path}",
            "--force",
            "--inconclusive",
            "--library=boost,openssl,posix",
        ]
        if self.opts.base:
            args.append(f"--relative-paths={self.opts.base.resolve()}")
        if not self.opts.warnings:
            args.append("--enable=warning")
        else:
            args.append("--enable=all")
        if self.jobs:
            args.append(f"-j{self.jobs}")
        return [*args, *self.opts.cppcheck_args]

    def __location(self, loc: Location) -> SarifLocation:
        return sarif.location(
            abspath(loc["@file"]) if not self.opts.base else loc["@file"],
            max(int(loc["@line"]), 1),
            loc.get("@column"),
            base="BASE_DIR" if self.opts.base else None,
            msg=loc.get("@info"),
        )

    @property
    def transforms(self) -> list[Transform]:
        transforms = super().transforms
        if self.inject_cwe:
            transforms.insert(0, inject_cwe_taxonomy())
        transforms.append(
            update_results(
                [
                    (lambda r: r.level == Level.ERROR, lambda r: attrs.evolve(r, rank=100)),
                    (lambda r: r.level == Level.WARNING, lambda r: attrs.evolve(r, rank=80)),
                    (None, lambda r: attrs.evolve(r, rank=40)),
                ]
            )
        )
        return transforms
