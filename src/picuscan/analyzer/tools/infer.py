# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from subprocess import PIPE

import attrs
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from picuscan import logging, process, sarif
from picuscan.analyzer.options import Options
from picuscan.analyzer.tool import Tool
from picuscan.analyzer.transforms import Transform
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.sarif.models import ArtifactLocation, Location, Log, Result, ThreadFlowLocation, Invocation
from picuscan.sarif.visitor import Visitor
from picuscan.process import TransformSarifAddInvocations

logger = logging.get_logger(__name__)

ERROR_PATTERN = re.compile(rb"^In file included from (\S*):\d+:")
PROGRESS_PATTERN = re.compile(rb"(.*) DONE\s*$")


class Infer(Tool):
    supports_threading = True

    @logging_redirect_tqdm()
    async def run(self) -> Log:
        assert self.opts.compile_db.path
        output_dir = self.tool_dir / "output"

        logger.info("Running %s", self.name)
        args = [
            self.program,
            "--compilation-database",
            str(self.opts.compile_db.path),
            "-o",
            str(output_dir),
            "--progress-bar-style=plain",
            "--keep-going",
            "--sarif",
            "--no-filtering",
            "--default-checkers",
            "--bufferoverrun",
            "--pulse",
            *self.opts.infer_args,
        ]
        if self.jobs:
            args.append(f"--jobs={self.jobs}")
        t_start = datetime.now(timezone.utc).isoformat()
        proc = await process.spawn(
            *args,
            stdout=PIPE,
            stderr=PIPE,
        )
        assert proc.stdout
        assert proc.stderr
        files = set()
        with tqdm(
            desc=self.name, total=len(self.opts.compile_db), bar_format=fixed_width_desc(), position=2, leave=False
        ) as progress:
            async for line in proc.stderr:
                self.sink.write(line)
                if match := re.match(PROGRESS_PATTERN, line):
                    path = match.groups()[0].decode()
                    if path not in files:
                        files.add(path)
                        progress.update(1)
                if match := re.match(ERROR_PATTERN, line):
                    path = match.groups()[0].decode()
                    assert isinstance(path, str)
                    if not Path(path).suffix.startswith(".h"):
                        self.failed_sources.add(path)

        status = await proc.wait()
        t_end = datetime.now(timezone.utc).isoformat()
        stderr = await proc.stderr.read()
        self.sink.write(stderr)

        report_path = output_dir / "report.sarif"
        with open(report_path, "rb") as f:
            doc = sarif.load(f)

        self.invocations = [
            Invocation(
                executionSuccessful=True, arguments=args, exitCode=status, startTimeUtc=t_start, endTimeUtc=t_end
            )
        ]
        return doc

    @property
    def transforms(self) -> list[Transform]:
        return [
            _fix_artifact_location_uris(),
            _fix_result_location(),
            *super().transforms,
            TransformSarifAddInvocations(self.name, self.invocations),
        ]


class _fix_artifact_location_uris(Visitor[Options]):
    """Infer incorrectly uses the uriBaseId field to store the absolute path. This transform fixes the issue."""

    def visit_ArtifactLocation(self, node: ArtifactLocation, opts: Options) -> ArtifactLocation:
        if node.uri is not None:
            uri = node.uri
            if uri.startswith("file:"):
                uri = uri[5:]
            if Path(uri).is_absolute():
                return attrs.evolve(node, uri=os.fspath(uri), uriBaseId=None)
        if node.uriBaseId is None:
            return node
        path = Path(node.uriBaseId)
        if not path.is_absolute():
            return node
        return attrs.evolve(node, uri=os.fspath(path), uriBaseId=None)


class _fix_result_location(Visitor[Options]):
    """For errors that occur indirectly in another function, Infer sometimes uses the call site as the result location
    instead of where the error actually happens. This might be a confusing, so we extract the actual error location
    from the code flows property."""

    def visit_Result(self, node: Result, opts: Options) -> Result:
        try:
            codeFlow = node.codeFlows[0]
            threadFlow = codeFlow.threadFlows[0]
            threadFlowLocation = threadFlow.locations[-1]
            match threadFlowLocation:
                case ThreadFlowLocation(location=Location(physicalLocation=physicalLocation)) if physicalLocation:
                    location = Location(physicalLocation=physicalLocation)
                    return attrs.evolve(node, locations=(location,))
                case _:
                    return node
        except IndexError:
            return node
