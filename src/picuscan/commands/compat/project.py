# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from collections.abc import Collection
from typing import IO, Any, Optional

import attrs
from cattrs import GenConverter
from cattrs.preconf.json import make_converter

from picuscan.common.cattrs import configure_converter


@attrs.frozen
class Finding:
    id: int = attrs.field(metadata={"override": {"rename": "ID"}})
    file: str
    line: int
    tool: str
    message: str
    function: Optional[str] = None
    type: Optional[str] = None
    severity: Optional[str] = None
    comment: Optional[str] = None
    is_false_positive: bool = False
    skip: bool = False
    need_review: bool = False
    is_duplicate: bool = False

    @property
    def skippable(self) -> bool:
        return self.is_false_positive or self.skip or self.is_duplicate


_Project = frozenset[Finding]


def load(input: IO[Any]) -> _Project:
    return structure(json.load(input))


def structure(o: Any) -> _Project:
    return _converter.structure(o, _Project)


def dump(findings: Collection[Finding], fp: IO[str]) -> None:
    json.dump(unstructure(findings), fp, indent=2)


def unstructure(findings: Collection[Finding]) -> Any:
    return _converter.unstructure(findings, _Project)


def _make_converter() -> GenConverter:
    c = make_converter()
    configure_converter(c)
    project_handler = _ProjectHandler(c)
    c.register_structure_hook_func(lambda t: t == _Project, project_handler.structure)
    c.register_unstructure_hook_func(lambda t: t == _Project, project_handler.unstructure)
    return c


@attrs.frozen
class _ProjectHandler:
    converter: GenConverter

    def structure(self, o: Any, _: type[_Project], /) -> _Project:
        return frozenset(self.converter.structure(x, Finding) for x in o)

    def unstructure(self, project: _Project) -> list[Any]:
        return list(self.converter.unstructure(x, Finding) for x in project)


_converter = _make_converter()
