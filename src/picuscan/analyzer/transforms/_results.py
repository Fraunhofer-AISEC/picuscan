# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import typing as t

import attrs
import cattrs
import fnmatch

from picuscan.analyzer.options import Options
from picuscan.sarif.models import Result
from picuscan.sarif.visitor import Visitor

_Matcher = t.Callable[[Result], bool]
_Action = t.Callable[[Result], Result]

_Rule = tuple[_Matcher | None, _Action]


@attrs.frozen
class _UpdateResultsVisitor(Visitor[Options]):
    rules: t.Sequence[_Rule]

    def visit_Result(self, node: Result, *args: t.Any, **kwds: t.Any) -> Result:
        for matcher, action in self.rules:
            if matcher is None or matcher(node):
                return action(node)
        return node


@t.overload
def update_results(action: _Action, /, matcher: _Matcher | None = None) -> _UpdateResultsVisitor: ...


@t.overload
def update_results(rules: t.Iterable[_Rule], /) -> _UpdateResultsVisitor: ...


def update_results(
    action_or_rules: _Action | t.Iterable[_Rule], matcher: _Matcher | None = None
) -> _UpdateResultsVisitor:
    """
    Return a visitor which transforms a SARIF log based on some rules. A
    rule is composed of an action that transforms SARIF result objects
    and an optional matcher that decides whether the rule is applicable.
    """
    if isinstance(action_or_rules, t.Iterable):
        if matcher is not None:
            raise ValueError("matcher cannot be set when the first argument is an iterable.")
        return _UpdateResultsVisitor(tuple(action_or_rules))
    return _UpdateResultsVisitor(((matcher, action_or_rules),))


@attrs.frozen
class _JsonRule:
    match: str
    changes: t.Mapping[str, t.Any]

    def to_rule(self) -> _Rule:
        def _match(result: Result) -> bool:
            return fnmatch.fnmatch(result.ruleId or "", self.match)

        def _action(result: Result) -> Result:
            return attrs.evolve(result, **self.changes)

        return _match, _action


def update_results_with_json(obj: t.Any) -> _UpdateResultsVisitor:
    """Structure the input into a set of rules that can be accepted by
    `update_results()` and return a visitor."""
    rules = cattrs.structure(obj, tuple[_JsonRule, ...])
    return update_results(r.to_rule() for r in rules)
