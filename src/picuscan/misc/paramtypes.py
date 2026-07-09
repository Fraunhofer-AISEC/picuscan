# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""
This module contains some useful subclasses of `click.ParamType`.
"""

from __future__ import annotations

import enum
import pathlib as p
import typing as t
from json import JSONDecodeError

import click
from click import Context, Parameter, ParamType
from typing_extensions import Unpack

from picuscan import compdb, sarif
from picuscan.sarif.models import Log
from picuscan.typing import is_str, is_tuple_with


class Literal(click.Choice[str]):
    """
    This is just a wrapper around `click.Choice` with some special handling for `typing.Literal`.

    Example usage:
    ```python
    _FooBar = typing.Literal["foo", "bar"]

    @click.command
    @click.argument("foobar", type=Literal(_FooBar))
    def cli(foobar: _FooBar):
        assert foobar in {"foo", "bar"}
    ```
    """

    def __init__(self, tp: t.Any, case_sensitive: bool = True) -> None:
        if t.get_origin(tp) != t.Literal:
            raise ValueError(f"Expected a literal type but received {tp}.")
        args = t.get_args(tp)
        if not is_tuple_with(args, is_str):
            raise TypeError(f"All values in {tp} must be strings.")
        super().__init__(args, case_sensitive)


class Enum(ParamType[enum.Enum]):
    """Like `click.Choice`, but for subclasses of `enum.Enum`."""

    name = "enum"

    def __init__(self, type: type[enum.Enum]):
        super().__init__()
        self._type = type

    def convert(self, value: t.Any, param: Parameter | None, ctx: Context | None) -> enum.Enum:
        if isinstance(value, self._type):
            return value

        if isinstance(value, str):
            for member in self._type:
                if member.name.casefold() == value.casefold():
                    return member

        try:
            if issubclass(self._type, enum.IntEnum):
                value = int(value)
            return self._type(value)
        except ValueError:
            pass

        members_str = ", ".join(f"{m.name} ({m.value})" for m in self._type)
        self.fail(f"{value!r} is not one of {members_str}.", param, ctx)


class Sequence(ParamType[tuple[t.Any, ...]]):
    """Accept a (by default) comma-separated list of strings as the
    value of the parameter."""

    name = "sequence"

    def __init__(self, type: ParamType[t.Any] | None = None, *, sep: str = ","):
        """
        @type: Use this to convert the individual sequence items.
        @sep: The separator used for splitting.
        """
        super().__init__()
        self._type = type
        self._sep = sep

    def convert(self, value: t.Any, param: Parameter | None, ctx: Context | None) -> tuple[t.Any, ...]:
        if isinstance(value, str):
            items = value.split(self._sep) if value else []
        else:
            try:
                items = iter(value)
            except TypeError:
                self.fail(f"{value!r} is not iterable.", param, ctx)

        if self._type:
            return tuple(self._type.convert(x, param, ctx) for x in items)
        else:
            return tuple(items)


class _PathKwds(t.TypedDict, total=False):
    exists: bool
    file_okay: bool
    dir_okay: bool
    writable: bool
    readable: bool
    executable: bool
    resolve_path: bool
    allow_dash: bool


def Path(**kwds: Unpack[_PathKwds]) -> click.Path:
    """This is just a wrapper around `click.Path` that sets `path_type`
    to `pathlib.Path`."""
    return click.Path(**kwds, path_type=p.Path)


class CompilationDB(click.File):
    """Read a compilation database from the file."""

    def __init__(self) -> None:
        super().__init__("rb")

    def convert(self, value: t.Any, param: Parameter | None, ctx: Context | None):  # type: ignore
        if isinstance(value, compdb.CompilationDB):
            return value
        file = super().convert(value, param, ctx)
        try:
            return compdb.load(file)
        except (JSONDecodeError, KeyError, TypeError) as err:
            self.fail(f"{file.name}: {err}", param, ctx)


class SarifLog(click.File):
    """Read a SARIF log from the file."""

    name = "SARIF_LOG"

    def __init__(self) -> None:
        super().__init__("rb")

    def convert(self, value: t.Any, param: Parameter | None, ctx: Context | None):  # type: ignore
        if isinstance(value, Log):
            return value
        file = super().convert(value, param, ctx)
        try:
            return sarif.load(file)
        except Exception as err:
            self.fail(f"{value}: {err}", param, ctx)
