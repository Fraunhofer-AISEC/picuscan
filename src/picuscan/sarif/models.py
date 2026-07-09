# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""SARIF object models. See https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html."""

from __future__ import annotations

import enum
from typing import Any, Iterable, Iterator, Literal, Mapping, Optional

import attrs

from picuscan.sarif.version import Version

# Don't update this to a later version. Otherwise, SARIF Viewer for VS
# Code breaks.
# See https://github.com/microsoft/sarif-vscode-extension/blob/3.1.1/src/extension/loadLogs.ts#L56
SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"


@attrs.frozen(kw_only=True)
class PropertyBag:
    tags: tuple[str, ...] = ()
    severity: Optional[str] = None


@attrs.frozen(kw_only=True)
class Object:
    """The base SARIF object."""

    properties: PropertyBag = PropertyBag()


@attrs.frozen(kw_only=True)
class ArtifactLocation(Object):
    uri: Optional[str] = None
    uriBaseId: Optional[str] = None


@attrs.frozen(kw_only=True)
class Message(Object):
    text: Optional[str] = None
    id: Optional[str] = None


@attrs.frozen(kw_only=True)
class MultiformatMessageString(Object):
    text: str


@attrs.frozen(kw_only=True)
class Log(Object):
    version: Literal[Version.V2_1_0]
    schema: Optional[str] = None
    runs: Optional[tuple[Run, ...]]

    def __iter__(self) -> Iterator[Run]:
        yield from self.runs or []


@attrs.frozen(kw_only=True)
class Run(Object):
    externalPropertyFileReferences: Optional[ExternalPropertyFileReferences] = None
    tool: Tool
    invocations: Optional[list[Invocation]] = None
    originalUriBaseIds: Mapping[str, ArtifactLocation] = attrs.field(factory=dict)
    results: Optional[frozenset[Result]] = None
    columnKind: Optional[ColumnKind] = None


class ColumnKind(enum.Enum):
    UTF16_CODE_UNITS = "utf16CodeUnits"
    UNICODE_CODE_POINTS = "unicodeCodePoints"


@attrs.frozen(kw_only=True)
class ExternalPropertyFileReferences(Object):
    taxonomies: tuple[ExternalPropertyFileReference, ...] = ()


@attrs.frozen(kw_only=True)
class ExternalPropertyFileReference(Object):
    location: Optional[ArtifactLocation] = None
    guid: Optional[str] = None


@attrs.frozen(kw_only=True)
class Tool(Object):
    driver: ToolComponent


@attrs.frozen(kw_only=True)
class ToolComponent(Object):
    name: str
    fullName: Optional[str] = None
    version: Optional[str] = None
    rules: tuple[ReportingDescriptor, ...] = ()


@attrs.frozen(kw_only=True)
class Invocation(Object):
    executionSuccessful: bool
    arguments: Optional[list[str]] = None
    exitCode: Optional[int] = None
    startTimeUtc: Optional[str] = None
    endTimeUtc: Optional[str] = None


@attrs.frozen(kw_only=True)
class Result(Object):
    ruleId: Optional[str] = None
    taxa: tuple[ReportingDescriptorReference, ...] = ()
    kind: Optional[Literal["pass", "open", "informational", "notApplicable", "review", "fail"]] = None
    level: Optional[Level] = None
    message: Message
    locations: tuple[Location, ...] = ()
    fingerprints: Mapping[str, str] = attrs.field(factory=dict, hash=False)
    codeFlows: tuple[CodeFlow, ...] = ()
    stacks: tuple[Stack, ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    rank: float = -1


class Level(enum.Enum):
    WARNING = "warning"
    ERROR = "error"
    NOTE = "note"
    NONE = "none"


@attrs.frozen(kw_only=True)
class Location(Object):
    physicalLocation: Optional[PhysicalLocation] = None
    message: Optional[Message] = None


@attrs.frozen(kw_only=True)
class PhysicalLocation(Object):
    artifactLocation: Optional[ArtifactLocation] = None
    region: Optional[Region] = None


@attrs.frozen(kw_only=True)
class Region(Object):
    startLine: Optional[int] = None
    startColumn: Optional[int] = None
    endLine: Optional[int] = None
    endColumn: Optional[int] = None


@attrs.frozen(kw_only=True)
class Suppression(Object):
    kind: Literal["inSource", "external"]
    status: Optional[Literal["accepted", "underReview", "rejected"]] = None
    justification: Optional[str] = None


@attrs.frozen(kw_only=True)
class CodeFlow(Object):
    threadFlows: tuple[ThreadFlow, ...]


@attrs.frozen(kw_only=True)
class ThreadFlow(Object):
    message: Optional[Message] = None
    locations: tuple[ThreadFlowLocation, ...]


@attrs.frozen(kw_only=True)
class ThreadFlowLocation(Object):
    location: Optional[Location] = None


@attrs.frozen(kw_only=True)
class Stack(Object):
    message: Optional[Message] = None
    frames: tuple[StackFrame, ...]


@attrs.frozen(kw_only=True)
class StackFrame(Object):
    location: Optional[Location] = None


@attrs.frozen(kw_only=True)
class ReportingDescriptor(Object):
    id: str
    name: Optional[str] = None
    shortDescription: Optional[MultiformatMessageString] = None
    fullDescription: Optional[MultiformatMessageString] = None
    relationships: tuple[ReportingDescriptorRelationship, ...] = ()


@attrs.frozen(kw_only=True)
class ReportingDescriptorReference(Object):
    id: Optional[str] = None
    toolComponent: Optional[ToolComponentReference] = None


@attrs.frozen(kw_only=True)
class ReportingDescriptorRelationship(Object):
    target: ReportingDescriptorReference
    kinds: tuple[str, ...] = ("relevant",)


@attrs.frozen(kw_only=True)
class ToolComponentReference(Object):
    name: Optional[str] = None
    guid: Optional[str] = None


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
