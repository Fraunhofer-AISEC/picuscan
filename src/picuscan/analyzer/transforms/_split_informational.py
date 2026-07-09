# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t

import attrs

from picuscan.analyzer.options import Options
from picuscan.misc.iterutils import partition
from picuscan.sarif.models import Log, Run
from picuscan.sarif.visitor import Visitor


def split_informational() -> _SplitInformationalVisitor:
    return _SplitInformationalVisitor()


class _SplitInformationalVisitor(Visitor[Options]):
    _runs: list[Run]

    def __init__(self) -> None:
        self._runs = []

    def visit_Run(self, node: Run, *args: t.Any, **kwds: t.Any) -> Run:
        if not node.results:
            return node
        results, informational = partition(lambda r: r.kind != "informational", node.results)
        self._runs.append(attrs.evolve(node, results=frozenset(informational)))
        return attrs.evolve(node, results=frozenset(results))

    def get_informational_log(self, log: Log) -> Log:
        return attrs.evolve(log, runs=tuple(self._runs))
