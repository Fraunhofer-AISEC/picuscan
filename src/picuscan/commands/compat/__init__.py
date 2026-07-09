# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import IO, Literal

import attrs
import click

from picuscan.misc import paramtypes
from picuscan.misc.decorators import collect_params
from picuscan.sarif.models import Log

from .project import Finding, dump, load


@click.group(help="Tools for compatibility with the old project format")
def cli() -> None:
    pass


FindingType = Literal["verified", "new", "need-review"]


@attrs.frozen
class CommonParams:
    project: IO[bytes]
    select: FindingType


def _common_params() -> list[click.Parameter]:
    return [
        click.Argument(["project"], type=click.File("rb")),
        click.Option(
            ["--select", "-s"],
            type=paramtypes.Literal(FindingType, case_sensitive=False),
            default="verified",
            show_default=True,
        ),
    ]


@attrs.frozen
class GccParams(CommonParams):
    output: IO[str]


@cli.command(help="Display the selected findings in GCC's output format.", params=_common_params())
@click.option("--output", "-o", type=click.File("w"), default="-")
@collect_params(GccParams)
def gcc(params: GccParams) -> None:
    findings = get_findings(params)
    for f in findings:
        id = f"[{f.id:03d}]"
        if params.select == "verified":
            msg = f"{f.file}:{f.line}:1: error: {id} {f.comment}"
        elif params.select == "new":
            msg = f"{f.file}:{f.line}:1: warning: {id} {f.message}"
        else:
            assert params.select == "need-review"
            msg = f"{f.file}:{f.line}:1: note: {id} {f.comment}"
        print(msg, file=params.output)


@attrs.frozen
class ExportParams(CommonParams):
    output: IO[str]


@cli.command(help="Export the selected findings as a new project.", params=_common_params())
@click.option("--output", "-o", type=click.File("w"), default="-")
@collect_params(ExportParams)
def export(params: ExportParams) -> None:
    dump(get_findings(params), params.output)


def get_findings(params: CommonParams) -> tuple[Finding, ...]:
    project = load(params.project)
    if params.select == "verified":
        findings = filter(lambda f: not (f.comment is None or f.skippable), project)
    elif params.select == "new":
        findings = filter(lambda f: f.comment is None and not f.skippable, project)
    else:
        assert params.select == "need-review"
        findings = filter(lambda f: f.need_review, project)
    return tuple(findings)


@cli.command(help="Convert SARIF logs to the project format.")
@click.argument("log", type=paramtypes.SarifLog())
@click.option("--output", "-o", type=click.File("w"), default="-")
def from_sarif(log: Log, output: IO[str]) -> None:
    findings: set[Finding] = set()
    counter = 1
    for run in log:
        tool = run.tool.driver.name
        results = run.results or frozenset()
        for result in results:
            try:
                (location,) = result.locations
                physical = location.physicalLocation
                if physical is None:
                    continue
                artifact = physical.artifactLocation
                if artifact is None:
                    continue
                file = artifact.uri
                if file is None:
                    continue
                region = physical.region
                if region is None:
                    continue
                line = region.startLine
                if line is None:
                    continue
            except ValueError:
                continue

            message = result.message.text
            if message is None:
                continue

            id = counter
            counter = counter + 1

            finding = Finding(id, file, line, tool, message)
            findings.add(finding)

    dump(findings, output)
