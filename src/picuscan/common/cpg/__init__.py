# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Iterator, Self
from urllib.parse import urlparse

from neo4j import GraphDatabase

from picuscan.sarif.models import Result, location, message


class CPG:
    def __init__(self, uri: str, auth: tuple[str, str]) -> None:
        self.driver = GraphDatabase.driver(uri, auth=auth)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.driver.close()

    def find_funcs_like(self, func: str) -> Iterator[Result]:
        q = """MATCH (n:CallExpression)
            WHERE
            toLower(n.name) contains toLower($func)
            RETURN n.artifact, n.startLine, n.startColumn, n.name
            LIMIT 100"""
        with self.driver.session() as tx:
            for record in tx.run(q, func=func):
                if path := _artifact(record):
                    loc = location(path, record["n.startLine"], record["n.startColumn"])
                    yield Result(message=message(record["n.name"]), locations=(loc,))

    def find_array_accesses(self) -> Iterator[ArrayAccess]:
        q = """MATCH (n:ArraySubscriptionExpression)-[:ARRAY_EXPRESSION]->()-[:TYPE]->(t)
            WHERE not t.name ENDS WITH 'std.vector'
            RETURN n.artifact, n.startLine, n.startColumn, n.code, t.name
            LIMIT 100"""
        with self.driver.session() as tx:
            for record in tx.run(q):
                if path := _artifact(record):
                    yield ArrayAccess(
                        path, record["n.startLine"], record["n.startColumn"], record["n.code"], record["t.name"]
                    )

    def find_missing_return_checks(self) -> Iterator[Result]:
        q = """MATCH (n:CallExpression)-[r:EOG]->(p)-[r2:EOG]->(p2), (n)-[:TYPE]->(t)
            WHERE
            not t.name = 'void'
            and not (n)-[r]->(p:IfStatement)-[r2]->(p2)
            and not (n)-[r]->(p:BinaryOperator)-[r2]->(p2)
            and not (n)-[r]->(p:Expression)-[r2]->(p2:BinaryOperator)
            and not (n)-[r]->(p:VariableDeclaration)
            and not n.name = 'printf'
            RETURN n.artifact, n.startLine, n.startColumn, n.name
            LIMIT 100"""
        with self.driver.session() as tx:
            for record in tx.run(q):
                if path := _artifact(record):
                    loc = location(path, record["n.startLine"], record["n.startColumn"])
                    yield Result(message=message(record["n.name"]), locations=(loc,))


def _artifact(record: Any) -> Path | None:
    uri = urlparse(record["n.artifact"])
    if not uri.scheme == "file":
        return None
    return Path(uri.path)


@dataclass
class ArrayAccess:
    path: Path
    line: int
    col: int
    code: str
    type: str

    @property
    def sarif(self) -> Result:
        return Result(
            message=message(f"{self.code} of type {self.type}"), locations=(location(self.path, self.line, self.col),)
        )
