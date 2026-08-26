# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

ARG AZURELINUX_BASE_IMAGE=mcr.microsoft.com/azurelinux/base/core@sha256:4d0522bb656cfe2bc567c254bb87c2b086a002db6cba51f71870eb5c6630195c
FROM ${AZURELINUX_BASE_IMAGE}

ARG OE_IMAGE_VERSION=local
ARG OE_INSTALL_DIR=build/mhsm-preview/staging/opt/openenclave
ARG INTEL_SGX_REPO_URL=https://download.01.org/intel-sgx/sgx-dcap/1.27.1/linux/distro/AzureLinux3.0/sgx_rpm_local_repo.tgz
ARG INTEL_SGX_REPO_SHA256=69fd89120046d228d569f8d3f63474400c2a3eb086db45a95885c30436306ea1

LABEL org.opencontainers.image.title="Open Enclave MHSM Azure Linux 3 Preview"
LABEL org.opencontainers.image.version="${OE_IMAGE_VERSION}"
LABEL org.opencontainers.image.source="https://github.com/openenclave/openenclave"
LABEL com.microsoft.openenclave.openssl.version="3.5.7"
LABEL com.microsoft.openenclave.support="integration-preview"

RUN tdnf install -y \
        ca-certificates \
        clang \
        cmake \
        createrepo_c \
        curl \
        git \
        glibc-devel \
        gzip \
        libstdc++-devel \
        make \
        ninja-build \
        openssl-devel \
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
    && rm -rf /tmp/sgx_rpm_local_repo.tgz /opt/intel/sgx_rpm_local_repo \
    && tdnf remove -y createrepo_c curl \
    && tdnf clean all

COPY ${OE_INSTALL_DIR}/ /opt/openenclave/

ENV PATH=/opt/openenclave/bin:${PATH}
ENV LD_LIBRARY_PATH=/opt/openenclave/lib64:/opt/openenclave/lib64/openenclave:/opt/openenclave/lib:/opt/openenclave/lib/openenclave:/usr/lib64
ENV SGX_AESM_ADDR=1

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
