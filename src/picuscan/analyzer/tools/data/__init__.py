# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from importlib import resources
from typing import Any

from picuscan.typing import JsonValue
from picuscan.sarif.models import Level

_files = resources.files(__package__)

_rules_cache: dict[str, JsonValue] = {}


def loader_hook(obj: dict[str, Any]) -> dict[str, Any]:
    key = "level"
    if key in obj and isinstance(obj[key], str):
        try:
            obj[key] = Level(obj[key])
        except Exception as e:
            raise ValueError(f"Invalid {key}: {obj[key]}") from e
    return obj


def load_rules(name: str) -> JsonValue:
    try:
        rules = _rules_cache[name]
    except KeyError:
        traversable = _files / "rules" / f"{name}.json"
        rules = json.loads(traversable.read_text("utf-8"), object_hook=loader_hook)
        _rules_cache[name] = rules
    return rules
