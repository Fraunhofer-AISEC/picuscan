# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Callable, Mapping

import attrs
from attrs import Attribute
from cattrs import GenConverter
from cattrs.gen._consts import AttributeOverride
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn


def configure_converter(c: GenConverter) -> None:
    c.register_structure_hook_factory(attrs.has, _StructureFactory(c))
    c.register_unstructure_hook_factory(attrs.has, _UnstructureFactory(c))


@attrs.frozen
class _Base:
    converter: GenConverter

    def _overrides(self, cls: type) -> dict[str, AttributeOverride]:
        overrides = ((f.name, self._override(f)) for f in attrs.fields(cls))
        return {name: override for name, override in overrides if override is not None}

    def _override(self, field: Attribute[object]) -> AttributeOverride | None:
        metadata = field.metadata
        try:
            return AttributeOverride(**metadata["override"])
        except KeyError:
            return None


@attrs.frozen
class _StructureFactory(_Base):
    def __call__(self, cls: type) -> Callable[[Mapping[str, Any], type[Any]], Any]:
        return make_dict_structure_fn(
            cls,
            self.converter,
            _cattrs_forbid_extra_keys=self.converter.forbid_extra_keys,
            **self._overrides(cls),  # type: ignore[arg-type]
        )


@attrs.frozen
class _UnstructureFactory(_Base):
    def __call__(self, cls: type) -> Callable[[Any], dict[str, Any]]:
        return make_dict_unstructure_fn(
            cls,
            self.converter,
            _cattrs_omit_if_default=self.converter.omit_if_default,
            **self._overrides(cls),  # type: ignore[arg-type]
        )
