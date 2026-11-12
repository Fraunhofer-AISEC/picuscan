# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import attrs
import cattrs
from attrs import Attribute
from cattrs.gen._consts import AttributeOverride


@attrs.frozen
class Metadata:
    override: AttributeOverride = attrs.field(factory=AttributeOverride)
    additional_properties: bool = False

    def resolve_name(self, field: Attribute[Any]) -> str:
        rename = self.override.rename
        return field.name if rename is None else rename


def from_attribute(field: Attribute[Any]) -> Metadata:
    return cattrs.structure(field.metadata, Metadata)


def fields(cls: type) -> Iterator[tuple[Attribute[Any], Metadata]]:
    for field in attrs.fields(cls):
        yield field, from_attribute(field)


def overrides(cls: type) -> dict[str, AttributeOverride]:
    return {f.name: md.override for f, md in fields(cls)}


def additional_field(cls: type) -> Attribute[Any] | None:
    for field, metadata in fields(cls):
        if metadata.additional_properties:
            return field
    return None
