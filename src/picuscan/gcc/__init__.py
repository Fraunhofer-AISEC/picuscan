# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""GCC-related stuff."""

from __future__ import annotations

import os
from argparse import ArgumentError, ArgumentParser
from collections.abc import Iterator
from pathlib import Path
from typing import Sequence

import attrs
from typing_extensions import Self


@attrs.frozen(kw_only=True)
class Options:
    """A (useful) subset of the options understood by `gcc`."""

    # Overall options
    link: bool = True
    assemble: bool = True
    output: Path | None = None
    language: str | None = None

    # C language options
    ansi: bool = False
    standard: str | None = None

    # Debugging options
    debug: bool = False

    # Optimization options
    optimize: str | bool = False

    # Preprocessor options
    preprocessor_defines: Sequence[str] = attrs.field(default=(), converter=tuple)
    preprocessor_undefines: Sequence[str] = attrs.field(default=(), converter=tuple)

    # Directory options
    include_dirs: Sequence[Path] = attrs.field(default=(), converter=tuple)

    @classmethod
    def from_args(cls, args: Sequence[str]) -> tuple[Self, list[str]]:
        """Create instance from a sequence of arguments meant for `gcc`."""
        try:
            known, _ = _parser.parse_known_args(args)
        except ArgumentError as exc:
            raise ParseError(exc) from exc
        except SystemExit as exc:
            # We pass `exit_on_error=False` to `ArgumentParser()`, but this still happens sometimes.
            raise RuntimeError(f"The argument parser tried to exit unexpectedly: {exc}") from exc
        kwargs = vars(known)
        files = kwargs.pop("files")
        return cls(**kwargs), files

    @property
    def args(self) -> Iterator[str]:
        """Transform instance into a sequence of arguments that can be passed to `gcc`."""
        if not self.link:
            yield "-c"
        if not self.assemble:
            yield "-S"
        if self.output:
            yield from ["-o", os.fspath(self.output)]
        if self.language is not None:
            yield from ["-x", self.language]
        if self.ansi:
            yield "-ansi"
        if self.standard is not None:
            yield f"-std={self.standard}"
        if self.debug:
            yield "-g"
        if self.optimize is True:
            yield "-O"
        elif self.optimize is not False:
            yield f"-O{self.optimize}"
        yield from [f"-D{s}" for s in self.preprocessor_defines]
        yield from [f"-U{s}" for s in self.preprocessor_undefines]
        yield from [f"-I{p}" for p in self.include_dirs]


class ParseError(Exception):
    """An error that might occur when parsing `gcc` arguments."""


def parse(args: Sequence[str]) -> tuple[Options, list[str]]:
    """Shorthand for `Options.from_args(args)`."""
    return Options.from_args(args)


def _get_parser() -> ArgumentParser:
    parser = ArgumentParser(add_help=False, allow_abbrev=False, exit_on_error=False)

    parser.add_argument("-c", dest="link", action="store_false")
    parser.add_argument("-S", dest="assemble", action="store_false")
    parser.add_argument("-o", dest="output", type=Path)
    parser.add_argument("-x", dest="language")

    parser.add_argument("-ansi", action="store_true")
    parser.add_argument("-std", dest="standard")

    parser.add_argument("-g", dest="debug", action="store_true")

    parser.add_argument("-O", dest="optimize", action="store_true")
    for suffix in ["0", "1", "2", "3", "s", "fast", "g"]:
        parser.add_argument(f"-O{suffix}", dest="optimize", action="store_const", const=suffix)

    parser.add_argument("-D", dest="preprocessor_defines", action="append", default=[])
    parser.add_argument("-U", dest="preprocessor_undefines", action="append", default=[])

    parser.add_argument("-I", dest="include_dirs", action="append", type=Path, default=[])

    parser.add_argument("files", nargs="*")

    return parser


_parser = _get_parser()
