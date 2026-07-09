# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t

import attrs

from picuscan.analyzer.options import Options
from picuscan.sarif.models import Result
from picuscan.sarif.visitor import Visitor


def centuple_rank() -> _CentupleRankVisitor:
    return _CentupleRankVisitor()


class _CentupleRankVisitor(Visitor[Options]):
    """Some tools think the rank is only supposed to between 0 and 1, so multiply it by 100."""

    def visit_Result(self, node: Result, *args: t.Any, **kwds: t.Any) -> Result:
        if not (node.rank and 0 < node.rank <= 1):
            return attrs.evolve(node, rank=int(node.rank))
        return attrs.evolve(node, rank=int(node.rank * 100))
