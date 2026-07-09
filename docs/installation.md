<!--
SPDX-FileCopyrightText: 2026 AISEC Code Audit Team

SPDX-License-Identifier: CC0-1.0
-->

# Installation

Picuscan is an orchestration and utility tool that provides a unified interface for multiple static analysis tools. The actual code analysis tools (CodeChecker, Cppcheck, Flawfinder, IKOS, Infer, RATS, GCC) must be installed separately or provided via the Docker image.

## Docker (Recommended)

We provide a Docker image with all supported analysis tools pre-installed.
The entrypoint is set to `picuscan`, but you can override it to launch an interactive shell.
It is recommended to map the target source code into the container at the same location as on your host system, so that paths are compatible.

```bash
$ docker pull ghcr.io/fraunhofer-aisec/picuscan:main
$ docker run --rm -it -v $PWD:$PWD:z -w $PWD --entrypoint bash picuscan
$ picuscan --help
```

## From PyPI

Install Picuscan with [pipx](https://pipx.pypa.io/stable/) from [PyPI](https://pypi.org/). You must install the analysis tools separately.

```bash
$ pipx install picuscan
$ picuscan --help
```

## From Source

Install Picuscan from source with [uv](https://docs.astral.sh/uv). You must install the analysis tools separately.

```bash
$ git clone https://github.com/Fraunhofer-AISEC/picuscan.git
$ cd picuscan
$ uv run picuscan --help
```

### Dependencies

The following analysis tools are supported. Install them according to your operating system's package manager or use the Docker image:

| Tool | Description |
|------|-------------|
| [CodeChecker](https://codechecker.readthedocs.io/en/latest/) | CodeChecker static analysis infrastructure |
| [clang](https://clang-analyzer.llvm.org/) | Clang compiler with Static Analyzer (clangsa) |
| [clang-tidy](https://clang.llvm.org/extra/clang-tidy/) | A clang-based C++ “linter” tool |
| [Cppcheck](https://cppcheck.sourceforge.io/) | C/C++ static analysis |
| [Flawfinder](https://dwheeler.com/flawfinder/) | Security vulnerability scanner |
| [IKOS](https://github.com/NASA-SW-VnV/ikos) | Abstract interpretation analyzer |
| [Infer](https://fbinfer.com) | Facebook Infer analyzer |
| [RATS](https://github.com/andrew-d/rough-auditing-tool-for-security) | Security auditing tool |
| [GCC](https://gcc.gnu.org/wiki/StaticAnalyzer) | GCC compiler with Static Analyzer (-fanalyzer) |

See [Analyzers](analyzers.md) for configuration options.
