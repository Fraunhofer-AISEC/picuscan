# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
from typing import Any

import attrs
import click
import pandas as pd

from picuscan.logging import get_logger
from picuscan.misc.decorators import collect_params, unasync
from picuscan.common.file import tokei

logger = get_logger(__name__)


@click.group(help="Tools useful for code audits.")
def cli() -> None:
    pass


@attrs.frozen
class _ModuleClocParams:
    paths: list[Path]
    sort_by_loc: bool
    exclude_module: list[str]
    exclude_src: list[str]
    export_files: Path | None


@cli.command(help="Show loc per module")
@click.argument(
    "paths",
    nargs=-1,
    type=click.Path(exists=True, file_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "--sort-by-loc/--no-sort-by-loc",
    default=False,
    help="Sort result table by loc (default sort by name)",
)
@click.option(
    "--exclude-module",
    multiple=True,
    help="Exclude modules",
)
@click.option(
    "--exclude-src",
    multiple=True,
    help="Exclude source folder",
)
@click.option(
    "--export-files",
    type=click.Path(writable=True, path_type=Path),
    help="Export list of source files as newline-separated text file",
)
@collect_params(_ModuleClocParams)
@unasync
async def module_cloc(params: _ModuleClocParams) -> None:
    counts = []
    all_files: list[str] = []
    for path in params.paths:
        if path.name in params.exclude_module:
            continue
        d: dict[str, Any]
        files: list[str]
        d, files = tokei(path, params.exclude_src)
        d["Module"] = path.name
        d["is_file"] = path.is_file()
        counts.append(d)
        all_files.extend(files)
    df = pd.DataFrame(counts)
    df = df.rename(columns={"C/C++ Header": "Header"})
    df = df.sort_values(["is_file", "Module"]).reset_index(drop=True)
    df = df.drop(columns=["is_file"])
    df.loc[df.shape[0]] = {
        "Module": "Total",
        "Header": df["Header"].sum(),
        "C++": df["C++"].sum(),
        "C": df["C"].sum(),
    }
    df = df.set_index("Module")
    df["Sum"] = df.apply(lambda x: sum(x), axis=1)
    df = df[df["Sum"] > 0]
    if params.sort_by_loc:
        df = df.sort_values(["Sum"])
    print(df.to_markdown())
    if params.export_files:
        params.export_files.write_text("\n".join(sorted(all_files)) + "\n" if all_files else "")
