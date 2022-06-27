# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# Please use the associated build.sh to build this Dockerfile
ARG UBUNTU_CODENAME
FROM ubuntu:${UBUNTU_CODENAME}
ARG UBUNTU_VERSION
ARG UBUNTU_CODENAME
ENV DEBIAN_FRONTEND noninteractive

# Copy apt preferences to pin to a specific Intel SGX version
COPY --chmod=644 apt_preference_files/intel-sgx.pref /etc/apt/preferences.d/intel-sgx.pref
# Add keyrings for required apt repositories
COPY --chmod=644 microsoft.asc.gpg /usr/share/keyrings/msprod-keyring.gpg
COPY --chmod=644 intel-sgx-deb.key.gpg /usr/share/keyrings/intel-sgx-keyring.gpg

# Update certs
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Register required apt repositories
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_CODENAME} main" | tee /etc/apt/sources.list.d/intel-sgx.list
RUN echo "deb [arch=amd64 signed-by=/usr/share/keyrings/msprod-keyring.gpg] https://packages.microsoft.com/ubuntu/${UBUNTU_VERSION}/prod ${UBUNTU_CODENAME} main" | tee /etc/apt/sources.list.d/msprod.list

# Install Intel SGX and Azure DCAP Client
RUN apt-get update && \
    apt-get install -y \
      az-dcap-client \
      libsgx-ae-pce \
      libsgx-ae-qe3 \
      libsgx-ae-qve \
      libsgx-enclave-common \
      libsgx-pce-logic \
      libsgx-qe3-logic \
      libsgx-dcap-ql \
      libsgx-quote-ex \
      libsgx-urts \
      libssl1.1 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
