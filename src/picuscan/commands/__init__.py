# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

"""
When you run `picuscan some-command`, Picuscan tries to locate the
command definition in this package. More specifically, it tries to
import the module `some_command` and then loads `cli` from the imported
module, which is supposed to be an instance of `click.Command`.

To define a new command, just create a new submodule in this package:
```python
import click
@click.command(help="Describe the command here.")
def cli():
    pass
```

More realistically, though, a command will look like this:
```python
from picuscan.misc.decorators import unasync
import click
@click.command(help="Describe the command here.")
@unasync  # Click doesn't support async functions
async def cli():
    pass
```
"""
