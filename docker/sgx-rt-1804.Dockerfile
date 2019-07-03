# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
FROM ubuntu:18.04
RUN apt update; apt -y install wget gnupg python apt-transport-https libssl1.1
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main' | tee /etc/apt/sources.list.d/msprod.list && wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
# Due to limitation with libsgx-enclave-common, create /etc/init so the package will not fail to install
RUN mkdir -p /etc/init
RUN apt update && apt -y install libsgx-enclave-common libsgx-dcap-ql az-dcap-client
