# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Hashable
from typing import Generic, TypeVar

from .classes.reportviews import InDegreeView

_T = TypeVar("_T", bound=Hashable)

class Graph(Generic[_T]):
    def add_node(self, node_for_adding: _T, **attr: object) -> None: ...
    def add_edge(self, u_of_edge: _T, v_of_edge: _T, **attr: object) -> None: ...

class DiGraph(Graph[_T]):
    @property
    def in_degree(self) -> InDegreeView[_T]: ...
