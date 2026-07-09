<!--
SPDX-FileCopyrightText: 2026 AISEC Code Audit Team

SPDX-License-Identifier: CC0-1.0
-->

# Usage

## Analysis

You need a [compilation database][compdb] for the analysis to work. If your build system does not or cannot generate a compilation database for you, check `picuscan compile-commands` out.

The `analyze` command runs a bunch of static analysis tools on the target project and combines the results of these tools into a single [SARIF] "log" file. Here is a list of currently supported tools:

* [CodeChecker](https://codechecker.readthedocs.io/en/latest/)
* [clang](https://clang-analyzer.llvm.org/)
* [Cppcheck](https://cppcheck.sourceforge.io)
* [Flawfinder](https://dwheeler.com/flawfinder/)
* [IKOS](https://github.com/NASA-SW-VnV/ikos)
* [Infer](https://fbinfer.com)
* [RATS](https://github.com/andrew-d/rough-auditing-tool-for-security)
* [GCC](https://gcc.gnu.org/wiki/StaticAnalyzer)

You need a [compilation database][compdb] for this command to work. If your build system does not or cannot generate a compilation database for you, check the `preprocess` or `compile-commands` commands out.

```bash
# Run the default set of analyzers.
$ picuscan analyze
# Run Flawfinder and RATS only.
$ picuscan analyze -t flawfinder -t rats
# Run IKOS (which is disabled by default) and the default analyzers.
$ picuscan analyze -e ikos
# Run the default analyzers, with the exception of Infer.
$ picuscan analyze -d infer

# You can also pass arguments directly to a specific tool.
$ picuscan analyze --codechecker-args --ctu
# For commonly used options, Picuscan provides shorthand versions.
$ picuscan analyze --codechecker-ctu # Equivalent to the former
```

The generated SARIF file can be inspected with [SARIF Viewer](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer) or [SARIF Explorer](https://marketplace.visualstudio.com/items?itemName=trailofbits.sarif-explorer).

See `picuscan analyze --help` for more details.

## Generating a compilation database

You can generate a [compilation database][compdb] with the `gen` subcommand. The following command invocation will locate all C/C++ source files in the current directory and populate the compilation database.
With `-o` you can optionally specify an output file.

```bash
$ ls
foo.c
$ picuscan compile-commands gen -o compile_commands.json
$ cat compile_commands.json
[
  {
    "directory": "/path/to/current/dir",
    "file": "foo.c",
    "arguments": ["clang", "-c", "-o", "foo.c.o", "foo.c"]
  }
]
```

You can also set the `-I` and `-D` compiler options for the compile commands by specifying a file with a list of include directories and/or config file with macro definitions.

```bash
$ cat includes.txt 
/usr/include
$ cat config.h 
#define BAR 1
$ picuscan compile-commands gen --includes-file includes.txt --config-file config.h -o compile_commands.json
$ cat compile_commands.json
[
  {
    "directory": "/path/to/current/dir",
    "file": "foo.c",
    "arguments": ["clang", "-I/usr/include", "-DBAR=1", "-c", "-o", "foo.c.o", "foo.c"]
  }
]
```

## Filtering and Transforming a compilation database

If you already have a compilation database, you can also filter and/or transform the compilation database entries with the `select` subcommand. This subcommand works with most Python expressions. 
Unless otherwise specified, the following are accessible in Python expressions: 
* dir [Path object]: The compile command directory
* file [Path object]: The file that the compile command operates on
* args [str list]: The compile command arguments
* path [Path object]: The absolute path of the file that the compile command operates on
* cmd [Function]: A function that takes a directory, a file name/path and a list of arguments to generate a compile command. Example: cmd(dir, file, args)

The only global builtin python functions allowed are: `all, any, enumerate, len, list, range, reversed, set, sorted, str, tuple, zip`

```bash
$ picuscan compile-commands select --where 'file.is_absolute()' compile_commands.json
$ picuscan compile-commands select --filter "'/Crypto/' in str(path) and '/dilithium/' not in str(path)" compile_commands.json
$ picuscan compile-commands select --map 'cmd(dir, file if file.is_absolute() else dir / file, args)' compile_commands.json
$ picuscan compile-commands select --reduce 'x + 1' 0 compile_commands.json
$ picuscan compile-commands select --count compile_commands.json
```

See `picuscan compile-commands --help` for more details.

## `preprocess` and `preprocess2`

These two commands are used for normalizing the source code and locating missing header files.

```bash
# Process the C/C++ files in the repository and write the list of
# missing headers to 'missing'.
$ picuscan preprocess -o missing
# Try to locate the missing headers. Populate 'includes' with the
# include directories which contain the missing headers. If there are
# headers that are still missing, write them to 'missing'.
$ picuscan preprocess2 --header-list missing --write-header-list missing --write-include-list includes
# Manually complete the include directories list.
$ echo /usr/include >> includes
# Rerun preprocess2 to ensure that there are no more missing headers.
$ picuscan preprocess2 --header-list missing --write-header-list missing --include-list includes --write-include-list includes
# Generate a compilation database.
$ picuscan compile-commands gen --includes-file includes -o compile_commands.json
# Or combine the previous two steps.
$ picuscan preprocess2 \
    --header-list missing --write-header-list missing \
    --include-list includes --write-include-list includes \
    --write-compile-db compile_commands.json
```

[compdb]: https://clang.llvm.org/docs/JSONCompilationDatabase.html
[sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
