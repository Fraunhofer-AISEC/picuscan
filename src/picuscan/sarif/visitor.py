# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Generic, TypeVar

import attr

from picuscan.sarif.models import Object

_Ctx = TypeVar("_Ctx")
_T = TypeVar("_T", bound=Object)


class Visitor(Generic[_Ctx]):
    """
    This class recursively visits all attributes of a SARIF object. It
    is mainly used for transforming a SARIF log.

    To define a new visitor method, subclass `Visitor` and simply prefix
    the name of the SARIF class with `visit_` like this:
    ```python
    class RunVisitor(Visitor[dict]):
        def visit_Run(self, node: Run, context: dict) -> Run:
            raise NotImplementedError
    visitor = RunVisitor()
    visitor(log, {"x": "Use the context to pass additional data to the visitor."})
    ```

    If you *do not* modify a node in a visitor method, make sure that
    you return the exact same instance (and *not* a copy). The visitor
    can detect this and avoid unnecessary copy operations.
    """

    def generic_visit(self, obj: _T, ctx: _Ctx) -> _T:
        changes: dict[str, Any] = {}
        for field in attr.fields(type(obj)):
            value = getattr(obj, field.name)
            if isinstance(value, dict):
                new_dict: dict[Any, Any] = {}
                changed = False
                for k, v in value.items():
                    if not isinstance(v, Object):
                        new_dict[k] = v
                        continue
                    new_value = self(v, ctx)
                    new_dict[k] = new_value
                    if new_value is not v:
                        changed = True
                if changed:
                    changes[field.name] = new_dict
            elif isinstance(value, tuple):
                new_list: list[Any] = []
                changed = False
                for v in value:
                    if not isinstance(v, Object):
                        new_list.append(v)
                        continue
                    new_value = self(v, ctx)
                    new_list.append(new_value)
                    if new_value is not v:
                        changed = True
                if changed:
                    changes[field.name] = tuple(new_list)
            elif isinstance(value, frozenset):
                new_set: set[Any] = set()
                changed = False
                for v in value:
                    if not isinstance(v, Object):
                        new_set.add(v)
                        continue
                    new_value = self(v, ctx)
                    new_set.add(new_value)
                    if new_value is not v:
                        changed = True
                if changed:
                    changes[field.name] = frozenset(new_set)
            elif isinstance(value, Object):
                new_value = self(value, ctx)
                if new_value is not value:
                    changes[field.name] = new_value

        if changes:
            return attr.evolve(obj, **changes)
        else:
            return obj

    def __call__(self, obj: _T, ctx: _Ctx) -> _T:
        method = f"visit_{type(obj).__name__}"
        visit = getattr(self, method, self.generic_visit)
        new = visit(obj, ctx)
        assert isinstance(new, type(obj))
        return new
