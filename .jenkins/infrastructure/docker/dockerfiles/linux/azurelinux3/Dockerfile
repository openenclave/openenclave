# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Minimal, non-SGX image used to compile and test Open Enclave in simulation
# mode on Azure Linux 3. Hardware and DCAP setup are intentionally deferred to
# the Azure Linux 3 SGX-agent workstream.
FROM mcr.microsoft.com/azurelinux/base/core:3.0

RUN tdnf install -y \
        autoconf \
        binutils \
        ca-certificates \
        clang \
        cmake \
        curl \
        diffutils \
        doxygen \
        expat-devel \
        file \
        findutils \
        gawk \
        gcc \
        gcc-c++ \
        git \
        glibc-devel \
        graphviz \
        gzip \
        kernel-headers \
        libcurl-devel \
        libtool \
        make \
        ncurses-devel \
        ninja-build \
        openssl-devel \
        patch \
        perl \
        pkg-config \
        python3 \
        sqlite-devel \
        tar \
        unzip \
        which \
    && tdnf clean all \
    && update-ca-trust

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

WORKDIR /src
