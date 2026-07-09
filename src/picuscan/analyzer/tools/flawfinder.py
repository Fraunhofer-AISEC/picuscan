# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from picuscan import logging, process, sarif
from picuscan.analyzer.tool import Tool
from picuscan.analyzer.transforms import Transform, centuple_rank
from picuscan.process import TransformSarifAddInvocations
from picuscan.sarif.models import Log

logger = logging.get_logger(__name__)


class Flawfinder(Tool):
    async def run(self) -> Log:
        if from_ := self.opts.flawfinder_from:
            logger.info("Reading %s findings from %s", self.name, from_.name)
            return sarif.load(from_)
        logger.info("Running %s", self.name)
        result = await process.run(
            self.program,
            "--neverignore",
            "--sarif",
            *self.opts.flawfinder_args,
            *self.opts.compile_db.files,
            *self.opts.in_scope,
            capture_output=True,
        )
        self.invocations = result.get_sarif_invocation()
        return sarif.loads(result.stdout)

    @property
    def transforms(self) -> list[Transform]:
        return [
            centuple_rank(),
            *super().transforms,
            TransformSarifAddInvocations(self.name, self.invocations),
        ]
