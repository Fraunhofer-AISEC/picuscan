# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from importlib.resources import files
import json
import hashlib
import fnmatch
from functools import lru_cache
from itertools import groupby
from pathlib import Path
from typing import Callable, Sequence, TypeVar, Any

import attrs
import click
import numpy as np
import pandas as pd
from tabulate import tabulate

from picuscan import logging
from picuscan.misc.decorators import collect_params, unasync
from picuscan.sarif.models import Result
from picuscan.sarif import structure

logger = logging.get_logger(__name__)

pd.set_option("display.max_rows", 500)
pd.set_option("display.max_columns", 500)
pd.set_option("display.width", 1000)

COMMON_PARAMS = [
    click.option(
        "--ignore-stacks/--no-ignore-stacks",
        default=False,
        help="Ignore findings, which only differ by different code flows",
    )
]

R = TypeVar("R")


def add_common_params(cmd: Callable[..., R]) -> Callable[..., R]:
    for param in reversed(COMMON_PARAMS):
        cmd = param(cmd)
    return cmd


def expand_json_column(df: pd.DataFrame, column: str, rename: None | dict[str, str] = None) -> pd.DataFrame:
    if column not in df.columns:
        return df
    col = df[column]
    df = df.drop(columns=[column])
    tmp = pd.json_normalize(col)
    tmp = tmp.set_index(df.index)
    if rename:
        tmp = tmp.rename(columns=rename)
    df = pd.concat([tmp, df], axis=1)
    return df


def load_sarif_as_df(path: Path, ignore_stacks: bool = False) -> pd.DataFrame:
    sarif = json.load(open(path))
    return _sarif_to_df(sarif, path.name, ignore_stacks)


def _sarif_to_df(sarif: dict[str, Any], name: str, ignore_stacks: bool = False) -> pd.DataFrame:
    results = []
    for run in sarif["runs"]:
        tool = run["tool"]["driver"]
        tool_name = tool["name"]
        tool_version = None
        if "version" in tool:
            tool_version = tool["version"]
        result = pd.DataFrame(run["results"])
        result["tool"] = tool_name
        result["tool_version"] = tool_version
        results.append(result)
    df = pd.DataFrame()
    if results:
        df = pd.concat(results).reset_index(drop=True)
    if df.empty:
        logger.warning(f"SARIF has no findings: {name}")
        return df
    if "taxa" in df.columns:
        df = df.explode("taxa")
    if "locations" not in df.columns:
        df["locations"] = None
    df = df.explode("locations")
    df = expand_json_column(
        df, "locations", {"physicalLocation.artifactLocation.uri": "path", "physicalLocation.region.startLine": "line"}
    )
    df = expand_json_column(df, "properties")
    df = expand_json_column(df, "message", {"text": "message"})
    df = expand_json_column(df, "taxa", {"id": "CWE"})
    df = df[~df["path"].isna()]
    df["line"] = df["line"].astype(int)
    df["location"] = df["path"] + ":" + df["line"].astype(str)
    df["file-type"] = df["path"].str.split(".").str[-1]
    if "codeFlows" not in df.columns:
        df["codeFlows"] = np.nan
    if "stacks" not in df.columns:
        df["stacks"] = np.nan
    if ignore_stacks:
        df = df.drop_duplicates(["location", "tool", "ruleId", "message"])
        df["codeFlows_h"] = np.nan
        df["stacks_h"] = np.nan
    else:
        df["codeFlows_h"] = df["codeFlows"].map(
            lambda x: hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest() if x else x
        )
        df["stacks_h"] = df["stacks"].map(
            lambda x: hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest() if x else x
        )
    df = df.reset_index(drop=True)
    df.attrs["name"] = name
    return df


@lru_cache(maxsize=1)
def load_cwe_names() -> dict[str, str]:
    cwe_path = files("picuscan.res").joinpath("cwe.json")
    names: dict[str, str] = {}
    try:
        data = json.loads(cwe_path.read_text("utf-8"))
        for entry in data:
            name = entry.get("name", "")
            if ":" in name:
                cwe_id, desc = name.split(":", 1)
                names[cwe_id.strip()] = desc.strip()
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return names


@attrs.frozen
class CommonParams:
    ignore_stacks: bool


@click.group(help="Utilities to work with sarif files")
def cli() -> None:
    pass


@attrs.frozen
class CompareParams(CommonParams):
    path: Sequence[Path]
    detail: bool


@cli.command(help="Compare multiple sarif files")
@add_common_params
@click.argument(
    "path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), nargs=-1, required=True
)
@click.option(
    "--detail/--no-detail",
    default=False,
    help="Show findings which are only present in one of the supplied sarif files",
)
@collect_params(CompareParams)
@unasync
async def compare(params: CompareParams) -> None:
    def compare_by_group(l_df: list[pd.DataFrame], group: str) -> None:
        l_df_count = []
        for df in l_df:
            df_rule_count = df.groupby([group]).agg({"location": "count"}).rename(columns={"location": "count"})
            df_rule_count["name"] = df.attrs["name"]
            l_df_count.append(df_rule_count)

        df_concat = pd.concat(l_df_count)
        df_cmp_rule_count = df_concat.pivot(columns="name", values="count")
        df_cmp_rule_count = df_cmp_rule_count[~df_cmp_rule_count.eq(df_cmp_rule_count.iloc[:, 0], axis=0).all(axis=1)]
        print(f"[+] Compare number of findings by aggregate on {group}")
        if df_cmp_rule_count.empty:
            print("* No difference")
            return
        print(df_cmp_rule_count)

    l_df = list(map(lambda x: load_sarif_as_df(x, params.ignore_stacks), params.path))
    l_df = list(filter(lambda x: not x.empty, l_df))
    if not l_df:
        logger.warning("No data loaded")
        return

    compare_by_group(l_df, "tool")
    print()
    compare_by_group(l_df, "level")
    print()
    compare_by_group(l_df, "ruleId")

    if params.detail:
        for df in l_df:
            print()
            print(f"[+] Unique findings in SARIF file: {df.attrs['name']}")
            df_u = _get_unique_findings(df, list(filter(lambda x: x.attrs["name"] != df.attrs["name"], l_df)))
            if df_u.shape[0] > 0:
                df_u = df_u.sort_values(["path", "line", "message"], ascending=True)
                df_u.apply(lambda x: print(x["location"], x["message"]), axis=1)  # type: ignore
            else:
                print("* no unique findings")


def _get_unique_findings(df_ref: pd.DataFrame, df_l: list[pd.DataFrame]) -> pd.DataFrame:
    for df in df_l:
        df_m = df_ref.merge(df, how="left", on=["location", "tool", "ruleId", "message", "codeFlows_h", "stacks_h"])
        df_ref = df_ref[df_m["path_y"].isna()].reset_index(drop=True)
    return df_ref


@attrs.frozen
class InfoParams(CommonParams):
    path: Path
    head: int


@cli.command(help="Show statistics about findings in SARIF file")
@add_common_params
@click.argument("path", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option("--head", "-h", type=int, default=10, help="Limit number of listed rule IDs (use -1 to list all)")
@collect_params(InfoParams)
@unasync
async def info(params: InfoParams) -> None:
    def print_group(df_print: pd.DataFrame, group: str, head: int = -1) -> None:
        df_print = (
            df_print.groupby([group])
            .agg({"path": "count"})
            .reset_index()
            .rename(columns={"path": "findings"})
            .sort_values(["findings"], ascending=False)
        )
        if head > 0:
            df_print = df_print.head(head)
        print(df_print.to_string(index=False))

    df = load_sarif_as_df(params.path, params.ignore_stacks)
    if df.empty:
        logger.warning("Sarif file is empty")
        return

    print("[+] Number of findings per tool:")
    print_group(df, "tool")

    print("\n[+] Number of findings per kind:")
    print_group(df, "kind")

    print("\n[+] Number of findings per level:")
    print_group(df, "level")

    print("\n[+] Number of findings per file type:")
    print_group(df, "file-type")

    print(f"\n[+] Top {params.head} rule IDs:")
    print_group(df, "ruleId", params.head)

    if "CWE" in df.columns:
        print(f"\n[+] Top {params.head} CWE categories:")
        cwe_names = load_cwe_names()
        df_cwe = (
            df.fillna({"CWE": "N/A"})
            .groupby(["CWE"])
            .agg({"path": "count"})
            .reset_index()
            .rename(columns={"path": "findings"})
            .sort_values(["findings"], ascending=False)
        )
        if params.head > 0:
            df_cwe = df_cwe.head(params.head)
        df_cwe["name"] = df_cwe["CWE"].map(lambda x: cwe_names.get(x, ""))
        print(df_cwe[["CWE", "name", "findings"]].to_string(index=False))


@attrs.frozen
class FilterParams(CommonParams):
    tool: list[str]
    level: list[str]
    kind: list[str]
    rank: int
    scope: list[str]
    not_scope: list[str]
    not_message: list[str]
    cwe: list[str]
    not_cwe: list[str]
    exclude_rules: Path | None
    path_in: Path
    scope_file: Path
    merge: bool
    path_filter: list[str]
    rule_id: list[str]
    guid: list[str]
    line: str | None
    out: Path | None = None
    max_rows: int = 20
    json_output: bool = False


def _result_matches_cwe(result: dict[str, Any], patterns: list[str], cwe_names: dict[str, str]) -> bool:
    return any(
        any(
            fnmatch.fnmatch(t.get("id", ""), p)
            or fnmatch.fnmatch(cwe_names.get(t.get("id", ""), "").lower(), p.lower())
            for p in patterns
        )
        for t in result.get("taxa", [])
    )


def _parse_line_range(spec: str) -> tuple[int | None, int | None]:
    """Parse a line range specification like '10', '10-20', '10-', '-20'."""
    spec = spec.strip()
    if "-" in spec:
        parts = spec.split("-", 1)
        start = int(parts[0]) if parts[0].strip() else None
        end = int(parts[1]) if parts[1].strip() else None
    else:
        start = end = int(spec)
    if start is not None and start < 1:
        raise ValueError("line range start must be >= 1")
    if end is not None and end < 1:
        raise ValueError("line range end must be >= 1")
    if start is not None and end is not None and start > end:
        raise ValueError("line range start must be <= end")
    return start, end


FILTER_OPTIONS = [
    click.option("--tool", "-t", multiple=True, help="Tool(s) which should be included (multiple)"),
    click.option("--level", "-l", multiple=True, help="Level(s) which should be included (multiple)"),
    click.option("--kind", "-k", multiple=True, help="Kind(s) which should be included (multiple)"),
    click.option("--rank", "-r", type=int, help="Minimum rank which should be included"),
    click.option(
        "--scope", "-s", multiple=True, help="Finding must be in specified scope(s) (multiple) (case sensitive)"
    ),
    click.option(
        "--not-scope", "-n", multiple=True, help="Exclude findings from specified scope(s) (multiple) (case sensitive)"
    ),
    click.option(
        "--not-message",
        "-m",
        multiple=True,
        help="Exclude finding with specified message(s) (multiple) (case sensitive)",
    ),
    click.option(
        "--cwe",
        "-c",
        multiple=True,
        help="Include findings matching specified CWE ID(s) or name glob pattern(s) (multiple) (case insensitive)",
    ),
    click.option(
        "--not-cwe",
        "-C",
        multiple=True,
        help="Exclude findings matching specified CWE ID(s) or name glob pattern(s) (multiple) (case insensitive)",
    ),
    click.option(
        "--exclude-rules",
        "-e",
        type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
        help="Read rule IDs to exclude from file",
    ),
    click.option(
        "--scope-file",
        "-f",
        type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
        help="Load in-scope paths from specified file (case sensitive)",
    ),
    click.option(
        "--merge/--no-merge",
        "-g",
        default=False,
        help="Merge findings at same location but different call stack to single finding",
    ),
    click.option(
        "--path-filter",
        "-p",
        multiple=True,
        help="Filter findings by file path (fnmatch glob pattern, matches primary location) (multiple)",
    ),
    click.option(
        "--line",
        "-L",
        type=str,
        default=None,
        help="Filter findings by line range of primary location (e.g. '10', '10-20', '10-', '-20')",
    ),
    click.option(
        "--rule-id",
        "-R",
        multiple=True,
        help="Include findings matching specified rule ID(s) (fnmatch glob pattern) (multiple)",
    ),
    click.option(
        "--guid",
        "-G",
        multiple=True,
        help="Include findings matching specified GUID(s) (fnmatch glob pattern) (multiple)",
    ),
]


def add_filter_options(cmd: Callable[..., R]) -> Callable[..., R]:
    for param in reversed(FILTER_OPTIONS):
        cmd = param(cmd)
    return cmd


def _result_is_in_scope(
    result: dict[str, Any],
    scope: list[str],
    ignore_stacks: bool,
    line_range: tuple[int | None, int | None] | None = None,
    fnmatch_paths: bool = False,
) -> bool:
    """Check whether a result is in scope, considering code flows, stacks, and primary location.

    If line_range is provided, locations must match both the path AND the line range.
    If line_range is None, only the path is checked.

    If fnmatch_paths is True, path matching uses fnmatch glob patterns. Otherwise,
    substring matching is used (current --scope behavior).
    """

    def uri_matches(uri: str) -> bool:
        if not scope:
            return True
        if fnmatch_paths:
            return any(fnmatch.fnmatch(uri, p) for p in scope)
        return any(p in uri for p in scope)

    def location_in_scope(uri: str, start_line: int | None = None) -> bool:
        if not uri_matches(uri):
            return False
        if line_range is not None:
            if start_line is None:
                return False
            ls, le = line_range
            if ls is not None and start_line < ls:
                return False
            if le is not None and start_line > le:
                return False
        return True

    locations = result.get("locations")
    if not locations:
        return False

    in_scope = False

    if "codeFlows" in result and not ignore_stacks:
        for flow in result["codeFlows"]:
            for thread in flow["threadFlows"]:
                for loc in thread["locations"]:
                    loc_data = loc.get("location", {})
                    phys = loc_data.get("physicalLocation", {})
                    if not phys:
                        continue
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    start = phys.get("region", {}).get("startLine")
                    if location_in_scope(uri, start):
                        in_scope = True

    if "stacks" in result:
        for stack in result["stacks"]:
            for frame in stack["frames"]:
                loc_data = frame.get("location", {})
                phys = loc_data.get("physicalLocation", {})
                if not phys:
                    continue
                uri = phys.get("artifactLocation", {}).get("uri", "")
                start = phys.get("region", {}).get("startLine")
                if location_in_scope(uri, start):
                    in_scope = True

    phys = locations[0].get("physicalLocation", {})
    if not phys:
        return in_scope
    uri = phys.get("artifactLocation", {}).get("uri", "")
    start = phys.get("region", {}).get("startLine")
    if location_in_scope(uri, start):
        in_scope = True

    return in_scope


def filter_scope(
    sarif_run: dict[str, Any],
    scope: list[str],
    invert: bool = False,
    ignore_stacks: bool = False,
    line_range: tuple[int | None, int | None] | None = None,
    fnmatch_paths: bool = False,
) -> None:
    """Filter results from a SARIF run in-place based on scope matching.

    Determines in-scope by checking code flows, stacks, and primary location.
    Results not matching scope criteria (or matching when inverted) are removed.
    """
    rm = []
    for idx, result in enumerate(sarif_run["results"]):
        if _result_is_in_scope(result, scope, ignore_stacks, line_range, fnmatch_paths) is invert:
            rm.append(idx)

    for idx in rm[::-1]:
        del sarif_run["results"][idx]


def _apply_filters(sarif: dict[str, Any], params: FilterParams) -> None:
    """Apply all filter steps to the SARIF dict in-place based on the given params."""

    if params.tool:
        logger.info(f"Filter based on tool: {params.tool}")
        sarif["runs"] = list(
            filter(lambda x: x["tool"]["driver"]["name"].lower() in list(map(str.lower, params.tool)), sarif["runs"])
        )

    if params.level:
        logger.info(f"Filter based on level: {params.level}")
        for run in sarif["runs"]:
            run["results"] = list(filter(lambda x: x["level"] in params.level, run["results"]))

    if params.kind:
        logger.info(f"Filter based on kind: {params.kind}")
        for run in sarif["runs"]:
            run["results"] = list(filter(lambda x: x["kind"] in params.kind, run["results"]))

    if params.rank:
        logger.info(f"Filter based on rank: {params.rank}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: ("rank" in x and (x["rank"] >= params.rank or x["rank"] == -1)) or "rank" not in x,
                    run["results"],
                )
            )

    if params.scope:
        logger.info(f"Filter based on scope: {params.scope}")
        for run in sarif["runs"]:
            filter_scope(run, list(params.scope), ignore_stacks=params.ignore_stacks)

    if params.not_scope:
        logger.info(f"Filter based on not in scope: {params.not_scope}")
        for run in sarif["runs"]:
            filter_scope(run, list(params.not_scope), invert=True, ignore_stacks=params.ignore_stacks)

    if params.not_message:
        logger.info(f"Exclude based on message: {params.not_message}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: not any(list(map(lambda msg: msg in x["message"]["text"], params.not_message))),
                    run["results"],
                )
            )

    if params.cwe:
        logger.info(f"Filter based on CWE: {params.cwe}")
        cwe_names = load_cwe_names()
        for run in sarif["runs"]:
            run["results"] = list(filter(lambda x: _result_matches_cwe(x, params.cwe, cwe_names), run["results"]))

    if params.not_cwe:
        logger.info(f"Exclude based on CWE: {params.not_cwe}")
        cwe_names = load_cwe_names()
        for run in sarif["runs"]:
            run["results"] = list(
                filter(lambda x: not _result_matches_cwe(x, params.not_cwe, cwe_names), run["results"])
            )

    if params.exclude_rules:
        logger.info(f"Filter based on exclude rule IDs: {params.exclude_rules}")
        exclude_rules = list(map(str.strip, open(params.exclude_rules).readlines()))
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: not any(list(map(lambda rule: fnmatch.fnmatch(x["ruleId"], rule), exclude_rules))),
                    run["results"],
                )
            )

    if params.rule_id:
        logger.info(f"Filter based on rule ID: {params.rule_id}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: any(fnmatch.fnmatch(x.get("ruleId", ""), p) for p in params.rule_id),
                    run["results"],
                )
            )

    if params.guid:
        logger.info(f"Filter based on GUID: {params.guid}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: any(fnmatch.fnmatch(x.get("guid", ""), p) for p in params.guid),
                    run["results"],
                )
            )

    if params.scope_file:
        files = params.scope_file.read_text().strip().split("\n")
        logger.info(f"Filter based on scope file: {params.scope_file}")
        for run in sarif["runs"]:
            filter_scope(run, files, ignore_stacks=params.ignore_stacks)

    if params.path_filter or params.line:
        line_range: tuple[int | None, int | None] = (None, None)
        if params.line:
            try:
                line_range = _parse_line_range(params.line)
            except ValueError as e:
                raise click.BadParameter(str(e), param_hint="--line")
        logger.info(f"Filter based on path: {params.path_filter}, line: {params.line}")
        for run in sarif["runs"]:
            filter_scope(
                run,
                list(params.path_filter),
                ignore_stacks=params.ignore_stacks,
                line_range=line_range,
                fnmatch_paths=True,
            )

    if params.merge:
        # merge runs with same tool
        sarif["runs"] = sorted(sarif["runs"], key=lambda x: x["tool"]["driver"]["name"])
        runs = []
        for _, g in groupby(sarif["runs"], key=lambda x: x["tool"]["driver"]["name"]):
            group = list(g)
            merged_run = group[0]
            for run in group[1:]:
                merged_run["results"] += run["results"]
            runs.append(merged_run)
        sarif["runs"] = runs

        def keyfunc(res: dict[str, Any]) -> tuple[Any, Any, Any, Any, Any, Any, Any]:
            loc = res["locations"][0]["physicalLocation"]
            key = (
                loc["artifactLocation"]["uri"],
                loc["region"]["startLine"],
                loc["region"].get("startColumn", 0),
                list(map(lambda x: x.get("id", "UNKNOWN-CWE"), res.get("taxa", []))),
                res["ruleId"],
                res["kind"],
                res["level"],
            )
            return key

        # merge findings at same location but different call stack
        for run in sarif["runs"]:
            res = sorted(run["results"], key=keyfunc)
            merged_res = []
            for _, g in groupby(res, keyfunc):
                group = list(g)
                merged_finding = group[0]
                for finding in group[1:]:
                    if "stacks" in finding:
                        merged_finding["stacks"] += finding["stacks"]
                    if "codeFlows" in finding:
                        merged_finding["codeFlows"] += finding["codeFlows"]
                # sort and filter stacks
                if "stacks" in merged_finding:
                    merged_finding["stacks"] = sorted(merged_finding["stacks"], key=lambda x: len(x["frames"]))
                    merged_finding["stacks"] = merged_finding["stacks"][:3]  # limit merged stacks
                if "codeFlows" in merged_finding:
                    merged_finding["codeFlows"] = sorted(
                        merged_finding["codeFlows"], key=lambda x: len(x["threadFlows"][0]["locations"])
                    )
                merged_res.append(merged_finding)

            run["results"] = merged_res

    # only include runs where we actually have results
    sarif["runs"] = list(filter(lambda x: len(x["results"]) > 0, sarif["runs"]))


@cli.command(help="Filter SARIF file", name="filter")
@add_common_params
@add_filter_options
@click.argument("path_in", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to store filtered SARIF file",
)
@collect_params(FilterParams)
@unasync
async def _filter(params: FilterParams) -> None:
    if params.out is None:
        raise click.UsageError("--out is required")

    with open(params.path_in) as f:
        sarif = json.load(f)

    _apply_filters(sarif, params)

    selected = sum(len(run["results"]) for run in sarif["runs"])
    logger.info(f"Export {selected} finding(s) to file: {params.out}")

    with open(params.out, "wt") as f:
        json.dump(sarif, f, indent=2)


@cli.command(help="Search and display findings from SARIF file as table", name="search")
@add_common_params
@add_filter_options
@click.argument("path_in", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option(
    "--max-rows",
    type=int,
    default=20,
    help="Maximum number of rows to display (use -1 for all)",
)
@click.option(
    "--json/--no-json",
    "json_output",
    default=False,
    help="Output results as JSON instead of a table",
)
@collect_params(FilterParams)
@unasync
async def _search(params: FilterParams) -> None:
    with open(params.path_in) as f:
        sarif = json.load(f)

    _apply_filters(sarif, params)

    selected = sum(len(run["results"]) for run in sarif["runs"])

    df = _sarif_to_df(sarif, params.path_in.name, params.ignore_stacks)
    if df.empty:
        logger.warning("No findings to display")
        return
    display_cols = ["guid", "tool", "ruleId", "level", "rank", "CWE", "location", "message"]
    for c in display_cols:
        if c not in df.columns:
            df[c] = pd.NA
    df_display = (
        df.sort_values(["path", "line"], ascending=True)[display_cols].fillna("").rename(columns={"ruleId": "ruleID"})
    )
    if params.max_rows >= 0:
        df_display = df_display.head(params.max_rows)

    if params.json_output:
        print(json.dumps(df_display.to_dict("records"), indent=2))
    else:
        logger.info(f"Found {selected} finding(s) limiting output to {params.max_rows}")
        print(tabulate(df_display.to_dict("list"), headers="keys", tablefmt="psql"))


@attrs.frozen
class ReportParams(FilterParams):
    pass


@cli.command(help="Generate a markdown report from results")
@add_common_params
@add_filter_options
@click.argument("path_in", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to store results in markdown file (if omitted, prints to stdout)",
)
@collect_params(ReportParams)
@unasync
async def report(params: ReportParams) -> None:
    def _format_location(loc: Any) -> str:
        parts: list[str] = []
        pl = loc.physicalLocation
        if pl:
            if pl.artifactLocation and pl.artifactLocation.uri:
                parts.append(pl.artifactLocation.uri)
            if pl.region and pl.region.startLine:
                parts.append(f":{pl.region.startLine}")
        msg = ""
        if loc.message and loc.message.text:
            msg = f" — {loc.message.text}"
        return "".join(parts) + msg

    def generate_report_entry(result: Result, tool_name: str) -> str:
        guid = result.guid or "unknown"
        entry = f"# {guid}\n"

        entry += "| Field | Value |\n"
        entry += "|-------|-------|\n"
        level_str = result.level.value if result.level else ""
        rank_str = str(result.rank) if result.rank >= 0 else ""
        entry += f"| Tool | {tool_name} |\n"
        entry += f"| Rule ID | {result.ruleId or ''} |\n"
        entry += f"| Level | {level_str} |\n"
        entry += f"| Rank | {rank_str} |\n\n"

        entry += "## Abstract\n"
        cwe_id = result.taxa[0].id if result.taxa and result.taxa[0].id else None
        if cwe_id:
            cwe_names = load_cwe_names()
            cwe_name = cwe_names.get(cwe_id)
            entry += f"{cwe_id}: {cwe_name}\n" if cwe_name else f"{cwe_id}\n"
        else:
            entry += "TODO\n"
        entry += "## Location\n"
        for loc in result.locations:
            entry += (
                loc.physicalLocation.artifactLocation.uri
                if loc.physicalLocation
                and loc.physicalLocation.artifactLocation
                and loc.physicalLocation.artifactLocation.uri
                else "TODO"
            )
            entry += (
                (":" + str(loc.physicalLocation.region.startLine))
                if loc.physicalLocation and loc.physicalLocation.region and loc.physicalLocation.region.startLine
                else ""
            ) + "\n"
        entry += "## Description\n"
        entry += (result.message.text if result.message.text else "") + "\n"

        if result.codeFlows:
            entry += "## Code Flows\n"
            for cf in result.codeFlows:
                for tf in cf.threadFlows:
                    for tfl in tf.locations:
                        if tfl.location:
                            entry += f"- {_format_location(tfl.location)}\n"
            entry += "\n"

        if result.stacks:
            entry += "## Stacks\n"
            for stack in result.stacks:
                if stack.message and stack.message.text:
                    entry += f"**{stack.message.text}**\n\n"
                for frame in stack.frames:
                    if frame.location:
                        entry += f"- {_format_location(frame.location)}\n"
            entry += "\n"

        _trans: dict[str, str | int | None] = {"_": r"\_"}
        entry = entry.translate(str.maketrans(_trans))
        entry += "## Code Snippet\n```c++\n"
        if (
            result.locations
            and result.locations[0].physicalLocation
            and result.locations[0].physicalLocation.artifactLocation
            and result.locations[0].physicalLocation.artifactLocation.uri
            and result.locations[0].physicalLocation.region
            and result.locations[0].physicalLocation.region.startLine
        ):
            code_loc = result.locations[0].physicalLocation.artifactLocation.uri
            code_line = result.locations[0].physicalLocation.region.startLine - 1

            with open(code_loc) as f:
                lines = f.readlines()
                if code_line > 0:
                    entry += lines[code_line - 1]
                if code_line < len(lines):
                    entry += lines[code_line]
                if code_line < len(lines) - 1:
                    entry += lines[code_line + 1]
        else:
            entry += "TODO\n"
        entry += "```\n"
        entry += "## Recommendation\nTODO\n"
        # TODO: create mapping for taxa to short description + pre-assessment of afl and impact

        entry += "\n---"

        return entry

    with open(params.path_in) as f:
        sarif_json = json.load(f)

    _apply_filters(sarif_json, params)

    sarif = structure(sarif_json)

    results: list[tuple[str, Result]] = []
    if sarif.runs:
        for run in sarif.runs:
            tool_name = run.tool.driver.name
            if run.results:
                for r in run.results:
                    results.append((tool_name, r))

    report = ""
    for tool_name, r in results:
        report += generate_report_entry(r, tool_name) + "\n\n"

    if params.out is not None:
        with open(params.out, "wt") as f:
            f.write(report)
    else:
        print(report, end="")
