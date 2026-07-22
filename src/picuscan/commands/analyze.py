# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any, Iterable

import click
from tqdm.contrib.logging import logging_redirect_tqdm

from picuscan import logging, sarif
from picuscan.analyzer.options import OPTIONS, Options
from picuscan.analyzer.tool import REGISTRY, Tool
from picuscan.analyzer.tools import load_tools
from picuscan.analyzer.transforms import filter_excludes, split_informational
from picuscan.misc.decorators import unasync, add_options
from picuscan.sarif.models import Log

logger = logging.get_logger(__name__)


@click.command(help="Static code analysis")
@unasync
@add_options(OPTIONS)
async def cli(**kwargs: Any) -> None:
    opts: Options = Options(**kwargs)
    await analyze(opts)


@logging_redirect_tqdm()
async def analyze(opts: Options) -> None:
    load_tools()
    logger.info(f"Loaded tools: {' '.join(sorted(cls.name for cls in REGISTRY.values()))}")

    if opts.tools:
        tool_names = set(s.casefold() for s in opts.tools)
    else:
        tool_names = set(n for n, tool in REGISTRY.items() if tool.enabled)
    tool_names = (tool_names | set(s.casefold() for s in opts.enable)) - set(s.casefold() for s in opts.disable)

    try:
        tools = list(map(lambda x: REGISTRY[x], tool_names))
    except KeyError as e:
        logger.warning("Error unknown tool %r.", e.args[0])
        sys.exit(1)

    jobs = 0
    tools_with_threading = len(list(filter(lambda x: x.supports_threading, tools)))
    if opts.jobs and tools_with_threading:
        jobs = max(1, opts.jobs // tools_with_threading)
        logger.info(f"Using {jobs} parallel jobs for each tool that supports threading")

    assert opts.compile_db.path
    picuscan_dir = opts.compile_db.path.parent / ".picuscan"
    start_time = time.strftime("%Y_%m_%d-%H_%M_%S")
    run_dir = opts.run_dir if opts.run_dir else picuscan_dir / "runs" / start_time
    run_dir.mkdir(parents=True, exist_ok=True)

    tool_instances: list[Tool] = []
    bar_position = 0
    for tool in tools:
        tool_dir = run_dir / tool.name
        tool_dir.mkdir(exist_ok=True)
        sink = open(tool_dir / "sink", "wb")
        instance = tool(opts, picuscan_dir=picuscan_dir, tool_dir=tool_dir, sink=sink, jobs=jobs)
        if instance.should_run():
            tool_instances.append(instance)
            if tool.uses_tqdm:
                instance.bar_position = bar_position
                bar_position += 1
        else:
            logger.warning("Tool %s is not available (program %r not found on PATH)", tool.name, instance.program)

    project = opts.project
    if not project:
        project = opts.compile_db.path.parent.absolute().name
        logger.info(f"Using '{project}' as project name")

    if tool_instances:
        logger.info("Running tools: {}".format(", ".join(sorted(t.name for t in tool_instances))))
    else:
        logger.error("No tools are available/enabled")
        sys.exit(2)

    logger.info(f"Saving tool outputs in {run_dir}")

    loop = asyncio.get_running_loop()
    completed, _ = await asyncio.wait([loop.create_task(_run(opts, t), name=t.name) for t in tool_instances])

    logs: list[Log] = []
    failed = 0
    for task in completed:
        try:
            logs.append(await task)
        except Exception as e:
            logger.error(f"Error when executing task: {task.get_name()}: {e}")
            failed += 1

    # reset cursor in case tqdm clean up was incomplete
    sys.stdout.write("\r")
    sys.stdout.flush()
    logger.info(f"Done: Executed {len(tool_instances)} tool(s) ({len(logs)} succeeded, {failed} failed)")
    for tool_instance in tool_instances:
        if failed_sources := tool_instance.failed_sources:
            logger.warning(
                f"{tool_instance.name} failed to analyze {len(failed_sources)} translation unit(s): {', '.join(sorted(failed_sources))}"
            )

    logger.info("Combining tool results...")
    combined = _combine(opts, logs)

    if opts.split == "informational":
        logger.info("Splitting informational results...")
        transform = split_informational()
        combined = transform(combined, opts)
        informational_log = transform.get_informational_log(combined)
    else:
        informational_log = None

    is_dir = opts.output.is_dir()
    if is_dir:
        name = f"{project}_{start_time}.sarif"
        path = opts.output / name
    else:
        path = opts.output

    with open(path, "w") as f:
        sarif.dump(combined, f)
        if is_dir:
            link = opts.output / "last_project.sarif"
            link.unlink(missing_ok=True)
            link.symlink_to(path.relative_to(link.parent))

    if informational_log:
        with open(path.with_stem(f"{path.stem}_informational"), "w", encoding="utf-8") as f:
            sarif.dump(informational_log, f)

    logger.info(f"Generated {sum(_count(run) for run in logs)} finding(s) and exported to {path}")


async def _run(opts: Options, tool: Tool) -> Log:
    try:
        with tool.sink:
            sarif_log = await tool.run()
    except Exception:
        logger.error(f"Failed to run {tool.name}.", exc_info=True)
        raise

    transforms = tool.transforms
    if transforms:
        logger.debug(f"Transforming {tool.name} log with {transforms}")

    try:
        for transform in transforms:
            logger.debug(f"Transforming {tool.name} log with {transform}")
            sarif_log = transform(sarif_log, opts)
    except Exception:
        logger.error(f"Failed to transform {tool.name} log, recovering.", exc_info=True)

    return sarif_log


def _count(log: Log) -> int:
    runs = () if log.runs is None else log.runs
    return sum(len(() if run.results is None else run.results) for run in runs)


def _combine(opts: Options, logs: Iterable[Log]) -> Log:
    log = sarif.log(run for log in logs for run in log)
    transform = filter_excludes()
    log = transform(log, opts)
    return log
