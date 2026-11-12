# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""SARIF object models. See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html."""

from __future__ import annotations

import enum
from collections.abc import Iterable, Iterator, Mapping
from typing import Any, Literal

import attrs

from picuscan.sarif.version import Version

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


@attrs.frozen(kw_only=True)
class PropertyBag:
    tags: tuple[str, ...] = ()
    severity: str | None = None


@attrs.frozen(kw_only=True)
class Object:
    """The base SARIF object."""

    properties: PropertyBag = PropertyBag()


@attrs.frozen(kw_only=True)
class ArtifactLocation(Object):
    uri: str | None = None
    uriBaseId: str | None = None


@attrs.frozen(kw_only=True)
class Message(Object):
    text: str | None = None
    id: str | None = None


@attrs.frozen(kw_only=True)
class MultiformatMessageString(Object):
    text: str


@attrs.frozen(kw_only=True)
class Log(Object):
    version: Literal[Version.V2_1_0]
    schema: str | None = None
    runs: tuple[Run, ...] | None

    def __iter__(self) -> Iterator[Run]:
        yield from self.runs or []


@attrs.frozen(kw_only=True)
class Run(Object):
    externalPropertyFileReferences: ExternalPropertyFileReferences | None = None
    tool: Tool
    invocations: list[Invocation] | None = None
    originalUriBaseIds: Mapping[str, ArtifactLocation] = attrs.field(factory=dict)
    results: frozenset[Result] | None = None
    columnKind: ColumnKind | None = None


class ColumnKind(enum.Enum):
    UTF16_CODE_UNITS = "utf16CodeUnits"
    UNICODE_CODE_POINTS = "unicodeCodePoints"


@attrs.frozen(kw_only=True)
class ExternalPropertyFileReferences(Object):
    taxonomies: tuple[ExternalPropertyFileReference, ...] = ()


@attrs.frozen(kw_only=True)
class ExternalPropertyFileReference(Object):
    location: ArtifactLocation | None = None
    guid: str | None = None


@attrs.frozen(kw_only=True)
class Tool(Object):
    driver: ToolComponent


@attrs.frozen(kw_only=True)
class ToolComponent(Object):
    name: str
    fullName: str | None = None
    version: str | None = None
    rules: tuple[ReportingDescriptor, ...] = ()


@attrs.frozen(kw_only=True)
class Invocation(Object):
    executionSuccessful: bool
    arguments: list[str] | None = None
    exitCode: int | None = None
    startTimeUtc: str | None = None
    endTimeUtc: str | None = None


@attrs.frozen(kw_only=True)
class Result(Object):
    ruleId: str | None = None
    taxa: tuple[ReportingDescriptorReference, ...] = ()
    kind: Literal["pass", "open", "informational", "notApplicable", "review", "fail"] | None = None
    level: Level | None = None
    message: Message
    locations: tuple[Location, ...] = ()
    fingerprints: Mapping[str, str] = attrs.field(factory=dict, hash=False)
    codeFlows: tuple[CodeFlow, ...] = ()
    stacks: tuple[Stack, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    rank: float = -1
    guid: str | None = None


class Level(enum.Enum):
    WARNING = "warning"
    ERROR = "error"
    NOTE = "note"
    NONE = "none"


@attrs.frozen(kw_only=True)
class Location(Object):
    physicalLocation: PhysicalLocation | None = None
    message: Message | None = None


@attrs.frozen(kw_only=True)
class PhysicalLocation(Object):
    artifactLocation: ArtifactLocation | None = None
    region: Region | None = None


@attrs.frozen(kw_only=True)
class Region(Object):
    startLine: int | None = None
    startColumn: int | None = None
    endLine: int | None = None
    endColumn: int | None = None


@attrs.frozen(kw_only=True)
class Suppression(Object):
    kind: Literal["inSource", "external"]
    status: Literal["accepted", "underReview", "rejected"] | None = None
    justification: str | None = None


@attrs.frozen(kw_only=True)
class CodeFlow(Object):
    threadFlows: tuple[ThreadFlow, ...]


@attrs.frozen(kw_only=True)
class ThreadFlow(Object):
    message: Message | None = None
    locations: tuple[ThreadFlowLocation, ...]


@attrs.frozen(kw_only=True)
class ThreadFlowLocation(Object):
    location: Location | None = None


@attrs.frozen(kw_only=True)
class Stack(Object):
    message: Message | None = None
    frames: tuple[StackFrame, ...]


@attrs.frozen(kw_only=True)
class StackFrame(Object):
    location: Location | None = None


@attrs.frozen(kw_only=True)
class ReportingDescriptor(Object):
    id: str
    name: str | None = None
    shortDescription: MultiformatMessageString | None = None
    fullDescription: MultiformatMessageString | None = None
    relationships: tuple[ReportingDescriptorRelationship, ...] = ()


@attrs.frozen(kw_only=True)
class ReportingDescriptorReference(Object):
    id: str | None = None
    toolComponent: ToolComponentReference | None = None


@attrs.frozen(kw_only=True)
class ReportingDescriptorRelationship(Object):
    target: ReportingDescriptorReference
    kinds: tuple[str, ...] = ("relevant",)


@attrs.frozen(kw_only=True)
class ToolComponentReference(Object):
    name: str | None = None
    guid: str | None = None


def message(text: Any, **kw: Any) -> Message:
    return Message(text=str(text), **kw)


def log(runs: Iterable[Run] | None = None) -> Log:
    return Log(version=Version.V2_1_0, schema=SCHEMA, runs=tuple(runs) if runs else None)


def location(
    path: Any | None = None,
    line: int | str | None = None,
    col: int | str | None = None,
    *,
    last_line: int | str | None = None,
    last_col: int | str | None = None,
    base: Any | None = None,
    msg: Any | None = None,
) -> Location:
    if path is None:
        artifact = None
    else:
        artifact = ArtifactLocation(uri=str(path), uriBaseId=None if base is None else str(base))
    if line is None:
        assert col is None
        assert last_line is None
        assert last_col is None
        region = None
    else:
        region = Region(
            startLine=int(line),
            startColumn=None if col is None else int(col) or None,
            endLine=None if last_line is None else int(last_line) or None,
            endColumn=None if last_col is None else int(last_col) or None,
        )
    if artifact is None:
        assert region is None
        physical = None
    else:
        physical = PhysicalLocation(artifactLocation=artifact, region=region)
    return Location(physicalLocation=physical, message=None if msg is None else message(msg))
