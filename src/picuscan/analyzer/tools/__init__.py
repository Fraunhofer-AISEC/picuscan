# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""
This package holds the analysis tool definitions.

You can define a new tool like this in a submodule:
```python
class Foo(Tool):
    async def run(self):
        raise NotImplementedError
```

`load_tools()` will automatically find and load the tool definition at runtime.
"""

import importlib
import pkgutil

from picuscan import logging

logger = logging.get_logger(__name__)


def load_tools() -> None:
    """This function simply loads all submodules of this package."""
    for _, name, _ in pkgutil.iter_modules(__path__):
        try:
            importlib.import_module(f"{__name__}.{name}")
        except Exception:
            logger.warning("Failed to load tool '%s'.", name, exc_info=True)
