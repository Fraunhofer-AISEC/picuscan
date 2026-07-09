# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

from picuscan.sarif.models import (
    Tool,
    ToolComponent,
    Result,
    PropertyBag,
    Level,
    Message,
    Location,
    PhysicalLocation,
    ArtifactLocation,
    Region,
    Log,
    Version,
    Run,
    ExternalPropertyFileReferences,
    ExternalPropertyFileReference,
    ReportingDescriptor,
    MultiformatMessageString,
    ReportingDescriptorRelationship,
    ReportingDescriptorReference,
    ToolComponentReference,
    Invocation,
    ColumnKind,
)
from picuscan.sarif import unstructure


def test_tool():
    t = Tool(driver=ToolComponent(name="test"))
    u = unstructure(t)
    assert u["driver"]["name"] == "test"


def test_result():
    r = frozenset(
        {
            Result(
                properties=PropertyBag(tags=(), severity=None),
                ruleId="FF1004",
                taxa=(),
                kind="open",
                level=Level.WARNING,
                message=Message(
                    properties=PropertyBag(tags=(), severity=None),
                    text="buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                    id=None,
                ),
                locations=(
                    Location(
                        properties=PropertyBag(tags=(), severity=None),
                        physicalLocation=PhysicalLocation(
                            properties=PropertyBag(tags=(), severity=None),
                            artifactLocation=ArtifactLocation(
                                properties=PropertyBag(tags=(), severity=None),
                                uri="/home/tobias/Downloads/sca-training/src/dilithium/ref/aes256ctr.c",
                                uriBaseId="SRCROOT",
                            ),
                            region=Region(
                                properties=PropertyBag(tags=(), severity=None),
                                startLine=536,
                                startColumn=3,
                                endLine=None,
                                endColumn=53,
                            ),
                        ),
                        message=None,
                    ),
                ),
                fingerprints={
                    "contextHash/v1": "942700efb8393a5c98022b1b2ab240687a820108e3cbda075c66ab2525074e0f",
                    "wpResultHash/v1": "d213165065ed27284c0a3f69c636636b59145a6a",
                },
                codeFlows=(),
                stacks=(),
                suppressions=(),
                rank=20.0,
            ),
        }
    )
    unstructure(r)


def test_log():
    log = Log(
        properties=PropertyBag(tags=(), severity=None),
        version=Version.V2_1_0,
        schema="https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        runs=(
            Run(
                properties=PropertyBag(tags=(), severity=None),
                externalPropertyFileReferences=ExternalPropertyFileReferences(
                    properties=PropertyBag(tags=(), severity=None),
                    taxonomies=(
                        ExternalPropertyFileReference(
                            properties=PropertyBag(tags=(), severity=None),
                            location=ArtifactLocation(
                                properties=PropertyBag(tags=(), severity=None),
                                uri="https://raw.githubusercontent.com/sarif-standard/taxonomies/main/CWE_v4.4.sarif",
                                uriBaseId=None,
                            ),
                            guid="FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5",
                        ),
                    ),
                ),
                tool=Tool(
                    properties=PropertyBag(tags=(), severity=None),
                    driver=ToolComponent(
                        properties=PropertyBag(tags=(), severity=None),
                        name="Flawfinder",
                        fullName=None,
                        version="2.0.19",
                        rules=(
                            ReportingDescriptor(
                                properties=PropertyBag(tags=(), severity=None),
                                id="FF1004",
                                name="buffer/memcpy",
                                shortDescription=MultiformatMessageString(
                                    properties=PropertyBag(tags=(), severity=None),
                                    text="Does not check for buffer overflows when copying to destination (CWE-120).",
                                ),
                                fullDescription=None,
                                relationships=(
                                    ReportingDescriptorRelationship(
                                        properties=PropertyBag(tags=(), severity=None),
                                        target=ReportingDescriptorReference(
                                            properties=PropertyBag(tags=(), severity=None),
                                            id="CWE-120",
                                            toolComponent=ToolComponentReference(
                                                properties=PropertyBag(tags=(), severity=None),
                                                name="CWE",
                                                guid="FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5",
                                            ),
                                        ),
                                        kinds=("relevant",),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
                invocations=[
                    Invocation(
                        properties=PropertyBag(tags=(), severity=None),
                        executionSuccessful=True,
                        arguments=[
                            "flawfinder",
                            "--neverignore",
                            "--sarif",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/fips202.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/aes256ctr.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-shake.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-aes.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-shake.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-aes.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-shake.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/sign.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/packing.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/polyvec.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/poly.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/ntt.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/reduce.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/rounding.c",
                            "/home/tobias/Downloads/sca-training/src/dilithium/ref/symmetric-aes.c",
                        ],
                        exitCode=0,
                        startTimeUtc="2023-12-04T06:56:25.310853+00:00",
                        endTimeUtc="2023-12-04T06:56:25.519324+00:00",
                    )
                ],
                originalUriBaseIds={},
                results=frozenset(
                    {
                        Result(
                            properties=PropertyBag(tags=(), severity=None),
                            ruleId="FF1004",
                            taxa=(),
                            kind="open",
                            level=Level.WARNING,
                            message=Message(
                                properties=PropertyBag(tags=(), severity=None),
                                text="buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                                id=None,
                            ),
                            locations=(
                                Location(
                                    properties=PropertyBag(tags=(), severity=None),
                                    physicalLocation=PhysicalLocation(
                                        properties=PropertyBag(tags=(), severity=None),
                                        artifactLocation=ArtifactLocation(
                                            properties=PropertyBag(tags=(), severity=None),
                                            uri="/home/tobias/Downloads/sca-training/src/dilithium/ref/aes256ctr.c",
                                            uriBaseId="SRCROOT",
                                        ),
                                        region=Region(
                                            properties=PropertyBag(tags=(), severity=None),
                                            startLine=535,
                                            startColumn=3,
                                            endLine=None,
                                            endColumn=53,
                                        ),
                                    ),
                                    message=None,
                                ),
                            ),
                            fingerprints={
                                "contextHash/v1": "3391cb56bab7c668124b6a168373db6ed611bdf261d963139cc09c212fd20442",
                                "wpResultHash/v1": "402a393645028c13db9a04076256395200593325",
                            },
                            codeFlows=(),
                            stacks=(),
                            suppressions=(),
                            rank=20.0,
                        ),
                        Result(
                            properties=PropertyBag(tags=(), severity=None),
                            ruleId="FF1004",
                            taxa=(),
                            kind="open",
                            level=Level.WARNING,
                            message=Message(
                                properties=PropertyBag(tags=(), severity=None),
                                text="buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                                id=None,
                            ),
                            locations=(
                                Location(
                                    properties=PropertyBag(tags=(), severity=None),
                                    physicalLocation=PhysicalLocation(
                                        properties=PropertyBag(tags=(), severity=None),
                                        artifactLocation=ArtifactLocation(
                                            properties=PropertyBag(tags=(), severity=None),
                                            uri="/home/tobias/Downloads/sca-training/src/dilithium/ref/aes256ctr.c",
                                            uriBaseId="SRCROOT",
                                        ),
                                        region=Region(
                                            properties=PropertyBag(tags=(), severity=None),
                                            startLine=536,
                                            startColumn=3,
                                            endLine=None,
                                            endColumn=53,
                                        ),
                                    ),
                                    message=None,
                                ),
                            ),
                            fingerprints={
                                "contextHash/v1": "942700efb8393a5c98022b1b2ab240687a820108e3cbda075c66ab2525074e0f",
                                "wpResultHash/v1": "d213165065ed27284c0a3f69c636636b59145a6a",
                            },
                            codeFlows=(),
                            stacks=(),
                            suppressions=(),
                            rank=20.0,
                        ),
                        Result(
                            properties=PropertyBag(tags=(), severity=None),
                            ruleId="FF1004",
                            taxa=(),
                            kind="open",
                            level=Level.WARNING,
                            message=Message(
                                properties=PropertyBag(tags=(), severity=None),
                                text="buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                                id=None,
                            ),
                            locations=(
                                Location(
                                    properties=PropertyBag(tags=(), severity=None),
                                    physicalLocation=PhysicalLocation(
                                        properties=PropertyBag(tags=(), severity=None),
                                        artifactLocation=ArtifactLocation(
                                            properties=PropertyBag(tags=(), severity=None),
                                            uri="/home/tobias/Downloads/sca-training/src/dilithium/ref/aes256ctr.c",
                                            uriBaseId="SRCROOT",
                                        ),
                                        region=Region(
                                            properties=PropertyBag(tags=(), severity=None),
                                            startLine=537,
                                            startColumn=3,
                                            endLine=None,
                                            endColumn=53,
                                        ),
                                    ),
                                    message=None,
                                ),
                            ),
                            fingerprints={
                                "contextHash/v1": "75af09b3f64718fe549ecd2426657a8e60bd519abb2dff5f7531ba55f4844304",
                                "wpResultHash/v1": "90b33a75ee061a1f18c48a683f59297721a2bc80",
                            },
                            codeFlows=(),
                            stacks=(),
                            suppressions=(),
                            rank=20.0,
                        ),
                    }
                ),
                columnKind=ColumnKind.UTF16_CODE_UNITS,
            ),
        ),
    )
    unstructure(log)
