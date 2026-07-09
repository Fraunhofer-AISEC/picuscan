# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

ARG BASE_IMAGE_VERSION=latest

#
# Build picuscan container image
#

FROM ghcr.io/fraunhofer-aisec/picuscan-base:${BASE_IMAGE_VERSION}

COPY . /opt/picuscan
RUN sudo chown -R picuscan:picuscan /opt/picuscan
WORKDIR /opt/picuscan
RUN uv sync && uv tool install . && uv tool update-shell

WORKDIR /home/picuscan

# Smoke Tests
RUN picuscan --version \
    && picuscan analyze --help

ENTRYPOINT ["picuscan"]
