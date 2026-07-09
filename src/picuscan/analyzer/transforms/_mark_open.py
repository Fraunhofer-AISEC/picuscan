# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import attrs

from picuscan.analyzer.options import Options
from picuscan.sarif.models import Result
from picuscan.sarif.visitor import Visitor


def mark_open() -> _MarkOpenVisitor:
    return _MarkOpenVisitor()


class _MarkOpenVisitor(Visitor[Options]):
    def visit_Result(self, node: Result, opts: Options) -> Result:
        if node.kind and node.kind != "fail":
            return node
        return attrs.evolve(node, kind="open")
