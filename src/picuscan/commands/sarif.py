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

from picuscan.misc.decorators import collect_params, unasync
from picuscan.sarif.models import Result
from picuscan.sarif import load

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
        print(f"[#] Warning: SARIF file has no findings: {path}")
        return df
    if "taxa" in df.columns:
        df = df.explode("taxa")
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
    df.attrs["name"] = path.name
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
        print("[!] No data loaded")
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
        print("[!] Sarif file is empty")
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
    exclude_rules: Path | None
    path_in: Path
    scope_file: Path
    out: Path
    merge: bool


@cli.command(help="Filter SARIF file", name="filter")
@add_common_params
@click.argument("path_in", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option("--tool", "-t", multiple=True, help="Tool(s) which should be included (multiple)")
@click.option("--level", "-l", multiple=True, help="Level(s) which should be included (multiple)")
@click.option("--kind", "-k", multiple=True, help="Kind(s) which should be included (multiple)")
@click.option("--rank", "-r", type=int, help="Minimum rank which should be included")
@click.option("--scope", "-s", multiple=True, help="Finding must be in specified scope(s) (multiple) (case sensitive)")
@click.option(
    "--not-scope", "-n", multiple=True, help="Exclude findings from specified scope(s) (multiple) (case sensitive)"
)
@click.option(
    "--not-message", "-m", multiple=True, help="Exclude finding with specified message(s) (multiple) (case sensitive)"
)
@click.option(
    "--cwe",
    "-c",
    multiple=True,
    help="Include findings matching specified CWE ID(s) or name glob pattern(s) (multiple) (case insensitive)",
)
@click.option(
    "--exclude-rules",
    "-e",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Read rule IDs to exclude from file",
)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to store filtered SARIF file",
)
@click.option(
    "--scope-file",
    "-f",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Load in-scope paths from specified file (case sensitive)",
)
@click.option(
    "--merge/--no-merge",
    "-g",
    default=False,
    help="Merge findings at same location but different call stack to single finding",
)
@collect_params(FilterParams)
@unasync
async def _filter(params: FilterParams) -> None:
    def filter_scope(sarif_run: dict[str, Any], scope: list[str], invert: bool = False) -> None:
        rm = list()
        for idx, result in enumerate(sarif_run["results"]):
            if "locations" not in result:
                continue
            in_scope = False
            if "codeFlows" in result and not params.ignore_stacks:
                for flow in result["codeFlows"]:
                    for thread in flow["threadFlows"]:
                        for loc in thread["locations"]:
                            if "physicalLocation" not in loc["location"]:
                                continue
                            uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"]
                            if [path for path in scope if path in uri]:
                                in_scope = True
            if "stacks" in result:
                for stack in result["stacks"]:
                    for frame in stack["frames"]:
                        uri = frame["location"]["physicalLocation"]["artifactLocation"]["uri"]
                        if [path for path in scope if path in uri]:
                            in_scope = True
            if "physicalLocation" not in result["locations"][0]:
                continue
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            if [path for path in scope if path in uri]:
                in_scope = True
            if in_scope is invert:
                rm.append(idx)

        for idx in rm[::-1]:
            del sarif_run["results"][idx]

    with open(params.path_in) as f:
        sarif = json.load(f)

    if params.tool:
        print(f"Filter based on tool: {params.tool}")
        sarif["runs"] = list(
            filter(lambda x: x["tool"]["driver"]["name"].lower() in list(map(str.lower, params.tool)), sarif["runs"])
        )

    if params.level:
        print(f"Filter based on level: {params.level}")
        for run in sarif["runs"]:
            run["results"] = list(filter(lambda x: x["level"] in params.level, run["results"]))

    if params.kind:
        print(f"Filter based on kind: {params.kind}")
        for run in sarif["runs"]:
            run["results"] = list(filter(lambda x: x["kind"] in params.kind, run["results"]))

    if params.rank:
        print(f"Filter based on rank: {params.rank}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: ("rank" in x and (x["rank"] >= params.rank or x["rank"] == -1)) or "rank" not in x,
                    run["results"],
                )
            )

    if params.scope:
        print(f"Filter based on scope: {params.scope}")
        for run in sarif["runs"]:
            filter_scope(run, params.scope)

    if params.not_scope:
        print(f"Filter based on not in scope: {params.not_scope}")
        for run in sarif["runs"]:
            filter_scope(run, params.not_scope, True)

    if params.not_message:
        print(f"Exclude based on message: {params.not_message}")
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: not any(list(map(lambda msg: msg in x["message"]["text"], params.not_message))),
                    run["results"],
                )
            )

    if params.cwe:
        print(f"Filter based on CWE: {params.cwe}")
        cwe_names = load_cwe_names()
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: any(
                        any(
                            fnmatch.fnmatch(t.get("id", ""), p)
                            or fnmatch.fnmatch(cwe_names.get(t.get("id", ""), "").lower(), p.lower())
                            for p in params.cwe
                        )
                        for t in x.get("taxa", [])
                    ),
                    run["results"],
                )
            )

    if params.exclude_rules:
        print(f"Filter based on exclude rule IDs: {params.exclude_rules}")
        exclude_rules = list(map(str.strip, open(params.exclude_rules).readlines()))
        for run in sarif["runs"]:
            run["results"] = list(
                filter(
                    lambda x: not any(list(map(lambda rule: fnmatch.fnmatch(x["ruleId"], rule), exclude_rules))),
                    run["results"],
                )
            )

    if params.scope_file:
        files = params.scope_file.read_text().strip().split("\n")
        print(f"Filter based on scope file: {params.scope_file}")
        for run in sarif["runs"]:
            filter_scope(run, files, False)

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

    selected = sum(len(run["results"]) for run in sarif["runs"])
    print(f"Export {selected} finding(s) to file: {params.out}")

    with open(params.out, "wt") as f:
        json.dump(sarif, f, indent=2)


@attrs.frozen
class ReportParams:
    path_in: Path
    out: Path
    name: str
    cntstart: int


@cli.command(help="Generate a markdown report from results with kind 'fail'")
@click.argument("path_in", type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path), required=True)
@click.option(
    "--out",
    "-o",
    type=click.Path(file_okay=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to store results in markdown file",
)
@click.option("--name", "-n", help="Basic name for entry ids")
@click.option("--cntstart", "-c", type=int, help="Number to start counter for entry ids (default 1)")
@collect_params(ReportParams)
@unasync
async def report(params: ReportParams) -> None:
    def generate_report_entry(result: Result, id: int) -> str:
        entryname = (params.name if params.name else "Entry") + f"-{id:02d}"
        entry = "# " + entryname + "\n"
        entry += "## Rating\n"
        entry += "Info/Low/Medium/High\n"
        entry += "## Abstract\n"
        entry += (result.taxa[0].id if result.taxa and result.taxa[0].id else "TODO") + "\n"
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

        return entry

    with open(params.path_in) as f:
        sarif = load(f)

    results: list[Result] = []

    if sarif.runs:
        for run in sarif.runs:
            if run.results:
                for r in run.results:
                    if r.kind in ["fail"]:
                        results.append(r)
                    # TODO: error in SARIF editor: self created findings do not have a 'kind', add them as well
                    elif r.ruleId == "self" or r.ruleId == "Self":
                        results.append(r)

    report = ""
    cnt = params.cntstart if params.cntstart else 1
    for r in results:
        report += generate_report_entry(r, cnt) + "\n\n"
        cnt = cnt + 1

    with open(params.out, "wt") as f:
        f.write(report)
