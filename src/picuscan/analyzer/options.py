# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This module holds the parameter definitions for the `picuscan analyze` command."""

from __future__ import annotations

from pathlib import Path
from typing import IO, Literal, Sequence

import attrs
import click

from picuscan.compdb import CompilationDB
from picuscan.misc import paramtypes


@attrs.frozen(kw_only=True, slots=False)
class _MainOptions:
    compile_db: CompilationDB
    in_scope: Sequence[str]
    exclude: Sequence[str]
    project: str | None
    output: Path
    run_dir: Path | None
    base: Path | None
    warnings: bool
    tools: Sequence[str]
    enable: Sequence[str]
    disable: Sequence[str]
    split: _SplitValue | None
    sarif_transform: bool
    jobs: int


_SplitValue = Literal["informational"]

_MAIN_OPTIONS = (
    click.Argument(["compile_db"], type=paramtypes.CompilationDB(), default="compile_commands.json"),
    click.Option(
        ["--in-scope", "-i"], multiple=True, help="Additional source paths not included in the compilation database."
    ),
    click.Option(["--exclude", "-x"], multiple=True, help="Exclude these paths from analysis results."),
    click.Option(["--project", "-p"], help="Project name."),
    click.Option(["--output", "-o"], type=paramtypes.Path(), default=".", help="Output file."),
    click.Option(
        ["--run-dir"],
        type=paramtypes.Path(),
        help="""Store the tool logs in this directory. By default, this is set
        to $COMPILATION_DB_PARENT/.picuscan/runs/$TIMESTAMP.""",
    ),
    click.Option(
        ["--base", "-b"], help="If specified, make source paths relative to this directory.", type=paramtypes.Path()
    ),
    click.Option(["--warnings/--no-warnings"], help="Whether to ignore warnings.", default=True),
    click.Option(
        ["--tool", "-t", "tools"], show_default=True, multiple=True, help="Enable these tools (and only these tools)."
    ),
    click.Option(["--enable", "-e"], multiple=True, help="Enable these tools in addition to the default ones."),
    click.Option(["--disable", "-d"], multiple=True, help="Disable these tools."),
    click.Option(
        ["--split"],
        type=paramtypes.Literal(_SplitValue),
        help="""Split the analysis results into separate files. With --split=informational, the results are grouped by
        their 'kind' property.""",
    ),
    click.Option(["--sarif-transform/--no-sarif-transform"], default=True, help="Apply SARIF transformation (default)"),
    click.Option(["--jobs", "-j"], help="Limit number auf parallel jobs (0 means no limit).", type=int, default=0),
)


@attrs.frozen(kw_only=True, slots=False)
class _CodeCheckerOptions:
    codechecker_args: Sequence[str]
    codechecker_analyzers: Sequence[str]
    codechecker_ctu: bool
    codechecker_enable_all: bool
    codechecker_enable_alpha: bool


_CODECHECKER_OPTIONS = (
    click.Option(["--codechecker-args"], multiple=True, help="Pass the following argument directly to CodeChecker."),
    click.Option(
        ["--codechecker-analyzers"],
        type=paramtypes.Sequence(),
        default=("clangsa", "clang-tidy"),
        show_default=True,
        help="The list of analyzers to use. Comma-separated.",
    ),
    click.Option(
        ["--codechecker-ctu/--no-codechecker-ctu"],
        default=True,
        show_default=True,
        help="Enable cross-translation-unit analysis.",
    ),
    click.Option(
        ["--codechecker-enable-all/--no-codechecker-enable-all"],
        default=True,
        show_default=True,
        help="Enable all checkers.",
    ),
    click.Option(
        ["--codechecker-enable-alpha/--no-codechecker-enable-alpha"],
        default=True,
        show_default=True,
        help="Enable experimental checkers.",
    ),
)


@attrs.frozen(kw_only=True, slots=False)
class _CppcheckOptions:
    cppcheck_args: Sequence[str]
    cppcheck_from: IO[bytes]


_CPPCHECK_OPTIONS = (
    click.Option(["--cppcheck-args"], multiple=True, help="Pass the following argument directly to Cppcheck."),
    click.Option(["--cppcheck-from"], help="Read Cppcheck findings from file.", type=click.File("rb")),
)


@attrs.frozen(kw_only=True, slots=False)
class _FlawfinderOptions:
    flawfinder_args: Sequence[str]
    flawfinder_from: IO[str]


_FLAWFINDER_OPTIONS = (
    click.Option(["--flawfinder-args"], multiple=True, help="Pass the following argument directly to flawfinder."),
    click.Option(["--flawfinder-from"], help="Read flawfinder findings from file.", type=click.File()),
)


@attrs.frozen(kw_only=True, slots=False)
class _IkosOptions:
    ikos_args: Sequence[str]
    ikos_llvm: str | None
    ikos_rename_symbols: bool
    ikos_llvm_ir: str | None
    ikos_find_entrypoints: bool
    ikos_truncate_stacks: int
    ikos_entrypoints_file: Path | None


_IKOS_OPTIONS = (
    click.Option(["--ikos-args"], multiple=True, help="Pass the following argument directly to IKOS."),
    click.Option(["--ikos-llvm"], show_default=True, help="LLVM version."),
    click.Option(
        ["--ikos-rename-symbols/--no-ikos-rename-symbols"],
        default=False,
        show_default=True,
        help="""When preparing the LLVM IR bundle for the analysis, try to avoid symbol conflicts by automatically
        renaming the main functions.""",
    ),
    click.Option(
        ["--ikos-llvm-ir"],
        type=click.Path(exists=True, dir_okay=False, readable=True),
        help="Use this LLVM IR file instead of building it automatically.",
    ),
    click.Option(["--ikos-find-entrypoints"], is_flag=True, default=False, help="Automatically find entry points."),
    click.Option(["--ikos-truncate-stacks"], show_default=True, type=int, default=10),
    click.Option(
        ["--ikos-entrypoints-file"],
        default=None,
        help="Read entrypoints from file (line based).",
        type=paramtypes.Path(),
    ),
)


@attrs.frozen(kw_only=True, slots=False)
class _RatsOptions:
    rats_args: Sequence[str]
    rats_from: IO[bytes]


_RATS_OPTIONS = (
    click.Option(["--rats-args"], multiple=True, help="Pass the following argument directly to RATS."),
    click.Option(["--rats-from"], help="Read RATS findings from file.", type=click.File("rb")),
)


@attrs.frozen(kw_only=True, slots=False)
class _InferOptions:
    infer_args: Sequence[str]


_INFER_OPTIONS = (click.Option(["--infer-args"], multiple=True, help="Pass the following argument directly to Infer."),)


@attrs.frozen(kw_only=True, slots=False)
class _GccOptions:
    gcc_args: Sequence[str]


_GCC_OPTIONS = (click.Option(["--gcc-args"], multiple=True, help="Pass the following argument directly to gcc."),)


@attrs.frozen
class Options(
    _RatsOptions,
    _IkosOptions,
    _FlawfinderOptions,
    _CppcheckOptions,
    _CodeCheckerOptions,
    _InferOptions,
    _GccOptions,
    _MainOptions,
):
    pass


OPTIONS: Sequence[click.Parameter] = (
    *_MAIN_OPTIONS,
    *_CODECHECKER_OPTIONS,
    *_CPPCHECK_OPTIONS,
    *_FLAWFINDER_OPTIONS,
    *_IKOS_OPTIONS,
    *_RATS_OPTIONS,
    *_INFER_OPTIONS,
    *_GCC_OPTIONS,
)
