# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Mapping
import json
import attrs
from dataclasses import dataclass
from itertools import chain

from tqdm import tqdm

from picuscan import logging, process, sarif
from picuscan.analyzer.tool import Tool
from picuscan.analyzer.transforms import Transform, centuple_rank
from picuscan.common.tqdm_support import fixed_width_desc
from picuscan.process import TransformSarifAddInvocations, CalledProcessError
from picuscan.sarif.models import ArtifactLocation, Log, ReportingDescriptorReference, ToolComponent
from picuscan.sarif.version import Version
from picuscan.analyzer.options import Options
from picuscan.sarif.visitor import Visitor

logger = logging.get_logger(__name__)


@dataclass
class TransformSarifUriBaseIds(Visitor[Options]):
    """Resolve the UriBaseId to full file path"""

    # TODO: Support UriBaseId in picuscan and sarif-editor

    originalUriBaseIds: Mapping[str, ArtifactLocation]

    def visit_ArtifactLocation(self, artifact: ArtifactLocation, opts: Options) -> ArtifactLocation:
        if artifact.uriBaseId and artifact.uri:
            base_uri = self.originalUriBaseIds[artifact.uriBaseId].uri
            assert base_uri
            return attrs.evolve(
                artifact,
                uri=base_uri.replace("file://", "") + artifact.uri,
                uriBaseId=None,
            )
        return artifact


@dataclass
class TransformSarifName(Visitor[Options]):
    """Overwrite the tool name"""

    name: str

    def visit_ToolComponent(self, tool: ToolComponent, opts: Options) -> ToolComponent:
        return attrs.evolve(tool, name=self.name)


@dataclass
class TransformSarifTaxa(Visitor[Options]):
    """Convert taxa format to picuscan format"""

    def visit_ReportingDescriptorReference(
        self, taxa: ReportingDescriptorReference, opts: Options
    ) -> ReportingDescriptorReference:
        if taxa.toolComponent and taxa.toolComponent.name and taxa.toolComponent.name.lower() == "cwe":
            return ReportingDescriptorReference(id=f"CWE-{taxa.id}")
        return taxa


class GCC(Tool):
    enabled = False

    async def run(self) -> Log:
        logger.info("Running %s", self.name)

        results = []
        res = Log(version=Version.V2_1_0, runs=None)
        for tr in tqdm(
            self.opts.compile_db,
            desc=self.name,
            total=len(self.opts.compile_db),
            bar_format=fixed_width_desc(),
            position=3,
        ):
            args = tr.arguments[1:]
            if not tr.directory.exists():
                logger.warning(f"Could not find directory given in compilation database: {tr.directory}")
                self.failed_sources.add(str(tr.file))
                continue
            result = await process.run(
                self.program,
                "-fanalyzer",
                "-fdiagnostics-format=sarif-stderr",
                *self.opts.gcc_args,
                *args,
                capture_output=True,
                cwd=tr.directory,
                check=False,  # gcc returns sarif file also in case of error
            )
            try:
                result.check_returncode()
            except CalledProcessError:
                logger.debug(f"Exit code != 0 when analyzing tr: {tr.file}")
                self.failed_sources.add(str(tr.file))
                # TODO: Invocation executionSuccessful will be true at the moment

            out = result.stderr.strip().decode()
            try:
                res = sarif.loads(out)
            except json.decoder.JSONDecodeError:
                logger.debug(f"Json decode error when analyzing tr: {tr.file}")
                logger.debug(out)
                self.failed_sources.add(str(tr.file))
                continue
            assert res.runs
            assert len(res.runs) == 1
            res = TransformSarifUriBaseIds(res.runs[0].originalUriBaseIds)(res, self.opts)
            assert res.runs
            invocations = result.get_sarif_invocation()
            res = TransformSarifAddInvocations(res.runs[0].tool.driver.name, invocations)(res, self.opts)
            res = TransformSarifName(self.name)(res, self.opts)
            results.append(res)

        if results:
            res = results[0]
            runs = tuple(chain.from_iterable(x.runs or () for x in results))
            res = attrs.evolve(res, runs=runs)

        return res

    @property
    def transforms(self) -> list[Transform]:
        return [
            centuple_rank(),
            TransformSarifTaxa(),
            *super().transforms,
        ]
