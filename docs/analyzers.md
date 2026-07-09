<!--
SPDX-FileCopyrightText: 2026 AISEC Code Audit Team

SPDX-License-Identifier: CC0-1.0
-->

# Analyzer Options

Picuscan uses the default options of the individual tools, with some additions.
The analyzer performance can be further improved, by tweaking the options specifically for the code to be analyzed.

Tool specific options can be forwarded via the option `--<tool>-args='...'`.
Multiple arguments can be forwarded.
Example:
```bash
$ picuscan analyze --codechecker-args="--analyzer-config=clangsa:max-nodes=400000" --codechecker-args="--analyzer-config=clangsa:max-symbol-complexity=40"
```

## clangsa

For the complete list of options, see the [clangsa documentation](https://clang-analyzer.llvm.org/).

| Option                                | Type | Default | Description |
|---------------------------------------|------|---------|-------------|
| max-nodes                             | int  | 225000  | Maximum nodes for exploration |
| max-symbol-complexity                 | int  | 35      | Maximum complexity of symbolic constraint |
| unroll-loops                          | bool | false   | Try to unroll loops with known bounds |
| prune-paths                           | bool | true    | Prune irrelevant parts of bug report paths |
| ctu-import-threshold                  | int  | 24      | Max translation units for CTU import |

## Infer

For the complete list of options, see the [Infer documentation](https://fbinfer.com/docs/man-infer-analyze).

| Option                               | Type  | Default | Description |
|--------------------------------------|-------|---------|-------------|
| pulse-max-cfg-size                   | int   | 15000   | Skip larger CFGs in Pulse |
| pulse-max-disjuncts                  | int   | 20      | Stop after i disjunctions |
| pulse-max-heap                       | int   | no-limit| Avoid OutOfMemory crashes |
| pulse-model-malloc-pattern           | regex |         | Model malloc wrappers |
| pulse-widen-threshold                | int   | 3       | Stop after i loop iterations |

## Cppcheck

For the complete list of options, see the [Cppcheck documentation](https://cppcheck.sourceforge.io/).

| Option        | Type | Default | Description |
|---------------|------|---------|-------------|
| max-ctu-depth | int  | 2       | Max depth in whole program analysis |

## IKOS

For the complete list of options, see the [IKOS documentation](https://github.com/NASA-SW-VnV/ikos/blob/master/analyzer/README.md#analysis-options).

| Option             | Type | Default  | Description |
|--------------------|------|----------|-------------|
| domain             | str  | interval | Abstract domains |
| widening-strategy  | str  | widen    | Strategy for increasing iterations |
| narrowing-strategy | str  | auto     | Strategy for decreasing iterations |
| widening-delay     | int  | 1        | Loop iterations before widening |
| widening-period    | int  | 1        | Iterations between widenings |
