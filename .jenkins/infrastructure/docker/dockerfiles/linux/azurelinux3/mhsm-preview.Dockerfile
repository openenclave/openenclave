# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

ARG AZURELINUX_BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core@sha256:4d0522bb656cfe2bc567c254bb87c2b086a002db6cba51f71870eb5c6630195c
FROM ${AZURELINUX_BASE_IMAGE} AS ocaml-build

ARG OCAML_VERSION=4.14.2
ARG OCAML_SHA256=c2d706432f93ba85bd3383fa451d74543c32a4e84a1afaf3e8ace18f7f097b43

RUN tdnf install -y \
        binutils \
        ca-certificates \
        curl \
        gcc \
        gawk \
        glibc-devel \
        kernel-headers \
        make \
        tar \
    && update-ca-trust \
    && curl -fsSL "https://github.com/ocaml/ocaml/archive/refs/tags/${OCAML_VERSION}.tar.gz" -o /tmp/ocaml.tar.gz \
    && echo "${OCAML_SHA256}  /tmp/ocaml.tar.gz" | sha256sum -c - \
    && mkdir /tmp/ocaml \
    && tar -xzf /tmp/ocaml.tar.gz -C /tmp/ocaml --strip-components=1 \
    && cd /tmp/ocaml \
    && ./configure --prefix=/opt/ocaml \
    && make -j"$(nproc)" world.opt \
    && make install

FROM ${AZURELINUX_BASE_IMAGE}

ARG OE_IMAGE_VERSION=local
ARG OE_RPM=build/mhsm-preview/open-enclave-azl3.rpm
ARG TARGET_KERNEL_VERSION=6.6.150.1-1.azl3
ARG INTEL_SGX_REPO_URL=https://download.01.org/intel-sgx/sgx-dcap/1.27.1/linux/distro/AzureLinux3.0/sgx_rpm_local_repo.tgz
ARG INTEL_SGX_REPO_SHA256=69fd89120046d228d569f8d3f63474400c2a3eb086db45a95885c30436306ea1

LABEL org.opencontainers.image.title="Open Enclave MHSM Azure Linux 3 Preview"
LABEL org.opencontainers.image.version="${OE_IMAGE_VERSION}"
LABEL org.opencontainers.image.source="https://github.com/openenclave/openenclave"
LABEL com.microsoft.openenclave.openssl.version="3.5.7"
LABEL com.microsoft.openenclave.support="integration-preview"

RUN tdnf install -y \
        autoconf \
        automake \
        binutils \
        ca-certificates \
        clang \
        cmake \
        createrepo_c \
        curl \
        dotnet-sdk-8.0 \
        file \
        gcc \
        gcc-c++ \
        gawk \
        git \
        glibc-devel \
        gzip \
        kernel-headers \
        kernel-devel-${TARGET_KERNEL_VERSION} \
        json-c-devel \
        libstdc++-devel \
        libtool \
        make \
        ninja-build \
        openssl-devel \
        patchelf \
        pkg-config \
        python3 \
        tar \
    && curl -fsSL "${INTEL_SGX_REPO_URL}" -o /tmp/sgx_rpm_local_repo.tgz \
    && echo "${INTEL_SGX_REPO_SHA256}  /tmp/sgx_rpm_local_repo.tgz" | sha256sum -c - \
    && mkdir -p /opt/intel \
    && tar -xzf /tmp/sgx_rpm_local_repo.tgz -C /opt/intel \
    && createrepo_c /opt/intel/sgx_rpm_local_repo \
    && printf '[intel-sgx-local]\nname=Intel SGX Local Repository\nbaseurl=file:///opt/intel/sgx_rpm_local_repo\nenabled=1\ngpgcheck=0\n' > /etc/yum.repos.d/intel-sgx-local.repo \
    && tdnf install -y \
        libsgx-enclave-common \
        libsgx-enclave-common-devel \
        libsgx-dcap-ql \
        libsgx-dcap-ql-devel \
        libsgx-dcap-quote-verify \
        libsgx-dcap-default-qpl \
        libsgx-quote-ex \
    && ln -sf /usr/lib64/libdcap_quoteprov.so.1 /usr/lib64/libdcap_quoteprov.so \
    && rm -rf /tmp/sgx_rpm_local_repo.tgz /opt/intel/sgx_rpm_local_repo /etc/yum.repos.d/intel-sgx-local.repo \
    && tdnf remove -y createrepo_c \
    && tdnf clean all

COPY ${OE_RPM} /tmp/open-enclave.rpm
COPY --from=ocaml-build /opt/ocaml/ /opt/ocaml/
COPY .jenkins/infrastructure/docker/dockerfiles/linux/azurelinux3/mhsm-smoke/ /tmp/mhsm-smoke/

RUN rpm -Uvh /tmp/open-enclave.rpm \
    && rm /tmp/open-enclave.rpm \
    && cmake \
        -S /tmp/mhsm-smoke \
        -B /tmp/mhsm-smoke-build \
        -DOpenEnclave_DIR=/opt/openenclave/lib64/openenclave/cmake \
    && test -x /opt/ocaml/bin/ocamllex \
    && test -x /opt/ocaml/bin/ocamlyacc \
    && test -x /opt/ocaml/bin/ocamlopt \
    && rm -rf /tmp/mhsm-smoke /tmp/mhsm-smoke-build

ENV PATH=/opt/openenclave/bin:/opt/ocaml/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/openenclave/lib64:/opt/openenclave/lib64/openenclave:/opt/openenclave/lib:/opt/openenclave/lib/openenclave:/usr/lib64
ENV SGX_AESM_ADDR=1
ENV TARGET_KERNEL_VERSION=${TARGET_KERNEL_VERSION}

RUN printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -o errexit' \
    'set -o nounset' \
    'set -o pipefail' \
    'if [[ ! -e /dev/sgx_enclave || ! -e /dev/sgx_provision ]]; then' \
    '  echo "Warning: SGX devices are not mounted; hardware workloads will not run." >&2' \
    'fi' \
    'exec "$@"' \
    > /usr/local/bin/run-mhsm-workload \
    && chmod 0755 /usr/local/bin/run-mhsm-workload

ENTRYPOINT ["/usr/local/bin/run-mhsm-workload"]
CMD ["bash"]
