# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Container, Generic, Mapping, TypeVar

import attrs
from attrs import Attribute
from cattrs import GenConverter
from cattrs.gen import make_dict_structure_fn, make_dict_unstructure_fn

from .metadata import additional_field, fields, overrides


def configure_converter(c: GenConverter) -> None:
    c.register_structure_hook(Path, lambda o, _: Path(o))
    c.register_unstructure_hook(Path, str)
    c.register_structure_hook_factory(attrs.has, _StructureFactory(c))
    c.register_unstructure_hook_factory(attrs.has, _UnstructureFactory(c))


@attrs.frozen
class _StructureFactory:
    converter: GenConverter

    def __call__(self, cls: type) -> _StructureHook[Any]:
        structure_fn: Callable[[Mapping[str, Any], type[Any]], Any] = make_dict_structure_fn(
            cls,
            self.converter,
            _cattrs_forbid_extra_keys=self.converter.forbid_extra_keys,
            **overrides(cls),  # type: ignore[arg-type]
        )
        additional = additional_field(cls)
        defined_fields = frozenset(md.resolve_name(f) for f, md in fields(cls) if f != additional)
        return _StructureHook(cls, structure_fn, defined_fields, additional)


_T = TypeVar("_T")


@attrs.frozen
class _StructureHook(Generic[_T]):
    cls: type[_T]
    structure_fn: Callable[[Mapping[str, Any], type[_T]], _T]
    field_names: Container[str]
    additional_field: Attribute[Any] | None = None

    def __call__(self, unstructured: Mapping[str, Any], _: type[_T] | None = None, /) -> _T:
        if self.additional_field:
            items = tuple((k, v, k not in self.field_names) for k, v in unstructured.items())
            unstructured = {
                **{k: v for k, v, additional in items if not additional},
                self.additional_field.name: {k: v for k, v, additional in items if additional},
            }
        return self.structure_fn(unstructured, self.cls)


@attrs.frozen
class _UnstructureFactory:
    converter: GenConverter

    def __call__(self, cls: type[_T]) -> Callable[[_T], dict[str, Any]]:
        return _UnstructureHook(
            make_dict_unstructure_fn(
                cls,
                self.converter,
                _cattrs_omit_if_default=self.converter.omit_if_default,
                **overrides(cls),  # type: ignore[arg-type]
            ),
            additional_field(cls),
        )


@attrs.frozen
class _UnstructureHook(Generic[_T]):
    unstructure_fn: Callable[[_T], dict[str, Any]]
    additional_field: Attribute[Any] | None = None

    def __call__(self, o: _T, /) -> dict[str, Any]:
        unstructured = self.unstructure_fn(o)
        if self.additional_field:
            additional_properties = unstructured.pop(self.additional_field.name)
            unstructured.update(additional_properties)
        return unstructured
