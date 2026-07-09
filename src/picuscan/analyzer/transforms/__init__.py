# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""This package holds the transform definitions. A transform is just a
function (or some other callable object) that accepts a SARIF log and an
instance of `Options`."""

from __future__ import annotations

import hashlib
import fnmatch
from dataclasses import dataclass, field
from itertools import groupby
from os.path import normpath
from pathlib import Path
from typing import Callable, Sequence
from urllib.parse import urlparse

import attr

from picuscan.analyzer.options import Options
from picuscan.sarif.models import (
    ArtifactLocation,
    ExternalPropertyFileReference,
    ExternalPropertyFileReferences,
    Log,
    ReportingDescriptor,
    ReportingDescriptorReference,
    Result,
    Run,
)
from picuscan.sarif.visitor import Visitor

from ..cwe import mapping as cwe_mapping
from ._mark_open import mark_open
from ._rank import centuple_rank
from ._results import update_results, update_results_with_json
from ._split_informational import split_informational

__all__ = (
    "centuple_rank",
    "filter_excludes",
    "fingerprint",
    "inject_cwe_mappings",
    "inject_cwe_taxonomy",
    "mark_open",
    "normalize_locations",
    "split_informational",
    "Transform",
    "truncate_stacks",
    "update_results",
    "update_results_with_json",
    "down_rate_failed_sources",
)

Transform = Callable[[Log, Options], Log]

CWE_44 = "https://raw.githubusercontent.com/sarif-standard/taxonomies/main/CWE_v4.4.sarif"


@dataclass
class normalize_locations(Visitor[Options]):
    def visit_ArtifactLocation(self, node: ArtifactLocation, opts: Options) -> ArtifactLocation:
        if not node.uri:
            return node
        uri = urlparse(node.uri)
        if uri.scheme and uri.scheme != "file":
            return node
        path = Path(uri.path)
        if opts.base:
            base_dir = opts.base.absolute()
            if path.is_absolute() and base_dir in path.parents:
                uri_ = normpath(path.relative_to(base_dir))
                return ArtifactLocation(uri=uri_, uriBaseId="BASE_DIR")
            return node
        else:
            if not path.is_absolute():
                if node.uriBaseId:
                    raise NotImplementedError("We don't resolve artifact locations by base ID yet.")
                uri_ = normpath(path.absolute())
                return ArtifactLocation(uri=uri_)
            return node

    def visit_Run(self, node: Run, opts: Options) -> Run:
        run = self.generic_visit(node, opts)
        if run is node:
            return node
        if not opts.base:
            return run
        base_dir = opts.base.absolute()
        base_ids = {"BASE_DIR": ArtifactLocation(uri=normpath(base_dir))}
        return attr.evolve(run, originalUriBaseIds=base_ids)


@dataclass
class inject_cwe_mappings(Visitor[Options]):
    tool: str | None = None

    TAXONOMY = ExternalPropertyFileReference(location=ArtifactLocation(uri=CWE_44))

    def visit_Run(self, node: Run, opts: Options) -> Run:
        self.tool = node.tool.driver.name.lower()
        if self.tool not in cwe_mapping:
            return node
        run = self.generic_visit(node, opts)
        if run is node:
            return node
        references = run.externalPropertyFileReferences or ExternalPropertyFileReferences()
        taxonomies = (self.TAXONOMY, *references.taxonomies)
        references = attr.evolve(references, taxonomies=taxonomies)
        return attr.evolve(run, externalPropertyFileReferences=references)

    def visit_Result(self, node: Result, opts: Options) -> Result:
        if self.tool is None:
            return node
        if self.tool not in cwe_mapping:
            return node
        if node.ruleId is None:
            return node
        for rule in cwe_mapping[self.tool]:
            if fnmatch.fnmatch(node.ruleId, rule):
                cwe = cwe_mapping[self.tool][rule]
                taxa = (ReportingDescriptorReference(id=cwe),)
                return attr.evolve(node, taxa=taxa)
        return node


@dataclass
class inject_cwe_taxonomy(Visitor[Options]):
    TAXONOMY = ExternalPropertyFileReference(location=ArtifactLocation(uri=CWE_44))

    def visit_Run(self, node: Run, opts: Options) -> Run:
        references = node.externalPropertyFileReferences or ExternalPropertyFileReferences()
        taxonomies = (self.TAXONOMY, *references.taxonomies)
        references = attr.evolve(references, taxonomies=taxonomies)
        return attr.evolve(node, externalPropertyFileReferences=references)


@dataclass
class truncate_stacks(Visitor[Options]):
    max: int

    def visit_Result(self, node: Result, opts: Options) -> Result:
        if self.max < 0:
            return node
        if len(node.stacks) <= self.max:
            return node
        return attr.evolve(node, stacks=node.stacks[0 : self.max])  # noqa: E203


class filter_excludes(Visitor[Options]):
    def visit_Run(self, node: Run, opts: Options) -> Run:
        if not opts.exclude:
            return node
        if not node.results:
            return node
        remove: list[Result] = []
        for result in node.results:
            if self.__should_remove(result, opts.exclude):
                remove.append(result)
        if not remove:
            return node
        results = node.results.difference(remove)
        return attr.evolve(node, results=results)

    def __should_remove(self, result: Result, exclude: Sequence[str]) -> bool:
        if not result.locations:
            return False
        for location in result.locations:
            uri = (
                location.physicalLocation
                and location.physicalLocation.artifactLocation
                and location.physicalLocation.artifactLocation.uri
            )
            if not uri:
                return False
            path = Path(uri)
            if any(path.match(pat) for pat in exclude):
                return True
        return False


@dataclass
class _FingerprintVisitor(Visitor[Options]):
    current_rules: dict[str, Sequence[ReportingDescriptor]] = field(default_factory=dict, init=True)

    def visit_Run(self, node: Run, opts: Options) -> Run:
        self.current_rules.clear()
        rules = sorted(node.tool.driver.rules, key=lambda r: r.id)
        for k, group in groupby(rules, key=lambda r: r.id):
            self.current_rules[k] = tuple(group)
        return self.generic_visit(node, opts)

    def visit_Result(self, node: Result, opts: Options) -> Result:
        tags = {ref.id.casefold() for ref in node.taxa if ref.id}
        if node.ruleId is not None:
            try:
                rules = self.current_rules[node.ruleId]
                for rule in rules:
                    tags.update(rel.target.id.casefold() for rel in rule.relationships if rel.target.id)
            except KeyError:
                pass
        cwes = sorted(s for s in tags if s.startswith("cwe-"))

        if not cwes:
            return node

        sha = hashlib.sha1()
        for cwe in cwes:
            sha.update(cwe.encode())

        try:
            location = node.locations[0]
            if physical := location.physicalLocation:
                if artifact := physical.artifactLocation:
                    if artifact.uri:
                        uri = Path(artifact.uri)
                        sha.update(uri.name.encode())
                if region := physical.region:
                    if region.startLine:
                        sha.update(region.startLine.to_bytes(64, "big"))
        except IndexError:
            pass
        except OverflowError:
            pass

        fingerprints = dict(node.fingerprints)
        fingerprints["wpResultHash/v1"] = sha.hexdigest()

        return attr.evolve(node, fingerprints=fingerprints)


def fingerprint() -> _FingerprintVisitor:
    return _FingerprintVisitor()


@dataclass
class down_rate_failed_sources(Visitor[Options]):
    failed_sources: set[str] = field(default_factory=set, init=True)

    def visit_Result(self, node: Result, opts: Options) -> Result:
        for location in node.locations:
            if not location.physicalLocation:
                continue
            if not location.physicalLocation.artifactLocation:
                continue
            if not location.physicalLocation.artifactLocation.uri:
                continue
            uri = location.physicalLocation.artifactLocation.uri
            # some tools report the failed source files as relative and some as absolut path
            # artifactLocation should be always absolut path
            if any(map(lambda x: uri.endswith(x), self.failed_sources)):
                return attr.evolve(node, rank=10)
        return node
