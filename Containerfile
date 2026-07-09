# SPDX-FileCopyrightText: 2026 AISEC Code Audit Team
#
# SPDX-License-Identifier: Apache-2.0

#
# Configuration
#

ARG CPG_VERSION=92eee9f4cfaabbbb27bf60abe0a8cc8e76cfded0

ARG LLVM_VERSION=14
ARG LLVM_VERSION_NEW=18
ARG IKOS_LLVM_VERSION=14

ARG INFER_VERSION=v1.3.0
ARG CODECHECKER_VERSION=6.28.2
ARG CPPCHECK_VERSION=2.21.0

#
# Build CPG
#

FROM debian:stable-slim AS cpg-builder

ARG CPG_VERSION

WORKDIR /src

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        git \
        openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

ENV GRADLE_OPTS=-Dorg.gradle.daemon=false

COPY gradle.properties /tmp/gradle.properties

RUN git clone --depth 1 https://github.com/Fraunhofer-AISEC/cpg.git /cpg \
    && cp /tmp/gradle.properties /cpg/gradle.properties \
    && mkdir -p /root/.gradle \
    && echo "org.gradle.daemon=false" >> /root/.gradle/gradle.properties \
    && cd /cpg \
    && git fetch origin $CPG_VERSION \
    && git checkout $CPG_VERSION \
    && ./gradlew --no-daemon installDist \
        -x pnpmInstall \
        -x pnpmBuild \
        -x :codyze-console:processResources \
        -x :codyze-console:processIntegrationTestResources \
        -x :codyze-console:processTestResources \
    && ./gradlew --stop \
    && rm -rf /root/.kotlin /tmp/hsperfdata_root

#
# Build Cppcheck
#

FROM debian:13-slim AS cppcheck-builder

ARG CPPCHECK_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL --tlsv1.2 https://github.com/danmar/cppcheck/archive/$CPPCHECK_VERSION.tar.gz | tar zxf - \
    && cd cppcheck-$CPPCHECK_VERSION \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DFILESDIR=/usr/local/share/cppcheck -DUSE_MATCHCOMPILER=ON -DHAVE_RULES=OFF .. \
    && make \
    && make install/strip DESTDIR=/tmp \
    && cd ../.. && rm -rf cppcheck-$CPPCHECK_VERSION

#
# Build IKOS
#

FROM debian:13-slim AS ikos-builder

ARG IKOS_LLVM_VERSION

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    make \
    gcc g++ \
    gpg \
    curl \
    git \
    ca-certificates \
    python3-venv \
    python3-setuptools \
    libz-dev \
    libsqlite3-dev \
    libboost-filesystem-dev \
    libboost-test-dev \
    libboost-thread-dev \
    && rm -rf /var/lib/apt/lists/*

# Use bookworm repo for llvm 14
RUN echo "deb http://deb.debian.org/debian/ bookworm main" >> /etc/apt/sources.list.d/bookworm.list
RUN echo "Package: *" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin: release n=trixie" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin-Priority: 900" >> /etc/apt/preferences.d/99-pinning \
 && echo "" >> /etc/apt/preferences.d/99-pinning \
 && echo "Package: *" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin: release n=bookworm" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin-Priority: 50" >> /etc/apt/preferences.d/99-pinning

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-$IKOS_LLVM_VERSION \
    llvm-$IKOS_LLVM_VERSION-dev \
    && rm -rf /var/lib/apt/lists/*

# IKOS requires a more recent version of TBB than the one that is included in
# the repository.
RUN curl -fsSL --tlsv1.2 https://github.com/oneapi-src/oneTBB/archive/refs/tags/v2021.7.0.tar.gz | tar -xzf - \
    && cd oneTBB-2021.7.0 \
    && mkdir build && cd build \
    && cmake -DCMAKE_BUILD_TYPE=Release -DTBB_TEST=OFF -DCMAKE_INSTALL_PREFIX=/opt/TBB .. \
    && make -j4 \
    && make install

# Install APRON from source, as it is not in the repo of bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libgmp-dev libmpfr-dev libppl-dev libflint-dev libglpk-dev libptl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/antoinemine/apron.git \
    && cd apron \
    && ./configure -no-java -no-ocaml -prefix /opt/apron \
    && make -j4 \
    && make install

COPY patches/ikos /tmp/patches
RUN git clone --depth=1 https://github.com/NASA-SW-VnV/ikos.git \
    && git -C ikos apply /tmp/patches/*.patch

RUN cd ikos \
    && mkdir build && cd build \
    && python3 -m venv /opt/IKOS \
    && . /opt/IKOS/bin/activate \
    && cmake \
    -DCMAKE_INSTALL_PREFIX=/opt/IKOS \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DAPRON_ROOT=/opt/apron \
    -DTBB_ROOT=/opt/TBB \
    -DLLVM_CONFIG_EXECUTABLE=/usr/bin/llvm-config-14 .. \
    && make -j4 \
    && make install/strip

#
# Build Infer
#

FROM debian:13-slim AS infer-builder
ARG INFER_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    clang \
    cmake \
    ninja-build \
    curl \
    git \
    libgmp-dev \
    libsqlite3-dev \
    make \
    opam \
    openjdk-21-jdk-headless \
    pkg-config \
    python3 \
    sqlite3 \
    zlib1g-dev \
    patchelf \
    rsync \
    build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libsqlite3-dev libreadline-dev libffi-dev curl libbz2-dev libunwind-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python 3.10 for Infer
RUN curl -O https://www.python.org/ftp/python/3.10.20/Python-3.10.20.tar.xz && tar -xf Python-3.10.20.tar.xz && cd Python-3.10.20 && ./configure --enable-shared --prefix=/opt/python3.10 && make -j4 build_all && make install
ENV PATH=/opt/python3.10/bin/:$PATH
ENV LD_LIBRARY_PATH=/opt/python3.10/lib/:$LD_LIBRARY_PATH

# Build Infer
RUN opam init --reinit --bare --disable-sandboxing --yes --auto-setup && eval $(opam env)
RUN git clone --depth=1 --branch $INFER_VERSION https://github.com/facebook/infer.git
WORKDIR $PWD/infer
RUN ./build-infer.sh --yes clang -- --prefix=/opt/infer --enable-python-analyzers
RUN make install-with-libs \
    DESTDIR=/tmp \
    PATCHELF=patchelf \
    libdir_relative_to_bindir="../lib" \
    BUILD_MODE=opt

#
# Build RATS
#

FROM debian:13-slim AS rats-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    git \
    libc6-dev \
    libexpat1-dev \
    make \
    && rm -rf /var/lib/apt/lists/*
COPY patches/rats /tmp/patches
RUN git clone --depth=1 https://github.com/andrew-d/rough-auditing-tool-for-security.git \
    && cd rough-auditing-tool-for-security \
    && git apply /tmp/patches/*.patch \
    && ./configure --prefix=/opt/rats \
    && make \
    && make install \
    && strip -s /opt/rats/bin/rats

#
# Build Docker Image
#

FROM debian:13-slim

ARG LLVM_VERSION
ARG LLVM_VERSION_NEW
ARG CODECHECKER_VERSION

ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_NO_CACHE_DIR=1
ENV DEBIAN_FRONTEND=noninteractive

# Install some generally useful stuff
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    gpg \
    bear \
    flex \
    make \
    git \
    cmake \
    ca-certificates \
    g++-multilib \
    gcc-multilib \
    jq \
    less \
    man \
    moreutils \
    ripgrep \
    vim \
    file \
    zstd \
    cloc \
    tokei \
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    libxml2-dev \
    libxslt-dev \
    libxslt-dev \
    pipx \
    python3-setuptools \
    fish \
    neovim \
    tmux \
    htop \
    sudo \
    fd-find \
    dos2unix \
    xz-utils \
    cmake-extras \
    libgmock-dev \
    libgtest-dev \
    && rm -rf /var/lib/apt/lists/*

# Install some commonly used open source libraries
RUN dpkg --add-architecture i386 && apt-get update && apt-get install -y --no-install-recommends \
    libboost-dev googletest \
    libarchive-dev libsystemd-dev libssl-dev libssl-dev:i386 pkg-config libcap-dev libboost-all-dev wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Use bookworm repo for llvm 14 (required for IKOS)
RUN echo "deb http://deb.debian.org/debian/ bookworm main" >> /etc/apt/sources.list.d/bookworm.list
RUN echo "Package: *" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin: release n=trixie" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin-Priority: 900" >> /etc/apt/preferences.d/99-pinning \
 && echo "" >> /etc/apt/preferences.d/99-pinning \
 && echo "Package: *" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin: release n=bookworm" >> /etc/apt/preferences.d/99-pinning \
 && echo "Pin-Priority: 50" >> /etc/apt/preferences.d/99-pinning

RUN apt-get update && apt-get install -y --no-install-recommends \
    llvm-$LLVM_VERSION \
    llvm-$LLVM_VERSION-dev \
    clang-$LLVM_VERSION \
    clang-tidy-$LLVM_VERSION \
    clang-$LLVM_VERSION_NEW \
    clang-tidy-$LLVM_VERSION_NEW \
    llvm-$LLVM_VERSION_NEW \
    llvm \
    libclang-rt-$LLVM_VERSION_NEW-dev \
    libclang-rt-$LLVM_VERSION-dev \
    libclang-rt-dev \
    clang \
    clang-tidy \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/python python /usr/bin/python3.13 1 && \
    update-alternatives  --set python /usr/bin/python3.13

# Install CPG
RUN apt-get update && apt-get upgrade -y && apt-get install --no-install-recommends -y \
    openjdk-17-jre-headless openjdk-21-jre-headless && \
    rm -rf /var/lib/apt/lists/*
COPY --from=cpg-builder /cpg/cpg-*/build/install /opt/
RUN find /opt/cpg-*/bin -type f ! -name '*.bat' -exec ln -s {} /usr/local/bin \;

# Install Cppcheck
COPY --from=cppcheck-builder /tmp/usr/local /usr/local

# Install flawfinder
RUN python -m venv /opt/flawfinder \
    && /opt/flawfinder/bin/pip install flawfinder \
    && ln -s /opt/flawfinder/bin/flawfinder /usr/local/bin

# Install IKOS
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgmp10 libmpfr6 libppl-c4 libflint19 libglpk40 libptl2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=ikos-builder /opt/apron /opt/apron
COPY --from=ikos-builder /opt/TBB /opt/TBB
COPY --from=ikos-builder /opt/IKOS /opt/IKOS
ENV PATH=$PATH:/opt/IKOS/bin/
ENV LD_LIBRARY_PATH=/opt/apron/lib/:$LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH=/opt/IKOS/lib/:$LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH=/opt/TBB/lib/:$LD_LIBRARY_PATH

# Install Infer
COPY --from=infer-builder /tmp/opt/infer /opt/infer
COPY --from=infer-builder /opt/python3.10 /opt/python3.10
ENV PATH=/opt/infer/bin:$PATH
ENV LD_LIBRARY_PATH=/opt/python3.10/lib:$LD_LIBRARY_PATH

# Install RATS
COPY --from=rats-builder /opt/rats /opt/rats
ENV PATH=/opt/rats/bin:$PATH

# Install penrun
RUN wget https://raw.githubusercontent.com/rumpelsepp/penrun/refs/heads/master/penrun -O /usr/bin/penrun && chmod +x /usr/bin/penrun

# Finally, install Picuscan
RUN apt-get update && apt-get install -y --no-install-recommends \
    graphviz-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash picuscan
RUN echo "picuscan ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/01_picuscan
COPY . /opt/picuscan
RUN chown -R picuscan:picuscan /opt/picuscan
USER picuscan
ENV LLVM_CONFIG=/usr/bin/llvm-config-14
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH=/home/picuscan/.local/bin:$PATH
WORKDIR /opt/picuscan
RUN uv sync && uv tool install . && uv tool update-shell


WORKDIR /home/picuscan

# Install CodeChecker
RUN pipx install codechecker==$CODECHECKER_VERSION


# Smoke Tests
RUN ikos --version \
    && infer --version \
    && cppcheck --version \
    && CodeChecker version \
    && CodeChecker log --help \
    && flawfinder --version \
    && picuscan --version \
    && picuscan analyze --help \
    && cpg-neo4j --schema-markdown /tmp/graph.md

RUN echo "alias ll='ls -l'\nalias la='ls -A'" >> .bashrc
RUN echo "set mouse-=a\nsyntax on" >> .vimrc

ENTRYPOINT ["picuscan"]
