<!--
SPDX-FileCopyrightText: 2026 AISEC Code Audit Team

SPDX-License-Identifier: CC0-1.0
-->

# Picuscan

Picuscan is an orchestration and utility tool for C/C++ security code audits. It provides a unified interface for running multiple external static analysis (SAST) tools, aggregates and normalizes their findings, and enriches the results with security metadata such as CWE categories.

Picuscan does not perform static analysis itself; instead, it collects tool outputs and turns them into a single, audit-focused view. It also ranks findings using a heuristic that combines tool feedback with practical experience to help auditors prioritize likely true positives. Additional utilities support audit preparation, including generating compilation databases, preparing source code, and working with SARIF files.

## Quick Start

### Docker (Recommended)

```bash
$ docker pull ghcr.io/fraunhofer-aisec/picuscan:main
$ docker run --rm -it -v $PWD:$PWD:z -w $PWD --entrypoint bash ghcr.io/fraunhofer-aisec/picuscan:main
$ picuscan --help
```

See [Installation → Docker](docs/installation.md#docker) for more details.

### From PyPI

```bash
$ pipx install picuscan
$ picuscan --help
```

**Note:** When installing via pip, you must install the analysis tools separately. See [Installation → Dependencies](docs/installation.md#dependencies) for a list of supported tools.

## Usage

You need a [compilation database][compdb] for the analysis to work.
Run analysis and generate a SARIF report:

```bash
$ picuscan analyze
```

See [Usage](docs/usage.md) for comprehensive documentation.

## Documentation

- [Installation](docs/installation.md) - Docker and pip installation
- [Usage](docs/usage.md) - Analysis, compilation databases, preprocessing
- [Analyzers](docs/analyzers.md) - Tool-specific options and configurations

## License

[Apache-2.0](LICENSE)

## Acknowledgments

This work was partly funded by the German Federal Ministry of Economic Affairs and Energy (BMWE) as part of the ATLAS-L4 project (grant no. 19A21048D).
This work was partly funded by the German Federal Ministry of Education and Research (BMBF) as part of the SHIQ project (grant no. 16KIS1955).

[compdb]: https://clang.llvm.org/docs/JSONCompilationDatabase.html