# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#
# IMPORTANT- Please update the version number in the next sentence
# when you create a new docker image.
#
# This Dockerfile script builds an image for tag oetools-azure:1.5

# To use this Dockerfile, you will need to install docker-ce.
# Instructions for installing it on Ubuntu 16.04 LTS are at:
# https://docs.docker.com/install/linux/docker-ce/ubuntu/
#
# Once installed, build a docker image from .jenkins folder and
# it will use this Dockerfile by default:
#     .jenkins$ sudo docker build --no-cache=true -t oetools-azure:<version> .
#
# For example, for version 1.x:
#     .jenkins$ sudo docker build --no-cache=true -t oetools-azure:1.x .
#
# Note that DNS forwarding in a VM can interfere with Docker
# getting updates from Ubuntu apt-get repositories as part of the
# Dockerfile script. To work around this, try disabling dnsmasq:
#     $ sudo nano /etc/NetworkManager/NetworkManager.conf
#     $ sudo service network-manager restart
#     $ sudo service docker restart
#
# To view the image after it is created or tagged:
#     $ sudo docker image ls
#
# Jenkins pulls the images it uses from the private oejenkinscidockerregistry
# repository on Azure. To upload the image to that repository:
#     $ sudo docker login oejenkinscidockerregistry.azurecr.io
#     $ sudo docker tag oetools-azure:<version> oejenkinscidockerregistry.azurecr.io/oetools-azure:<version>
#     $ sudo docker push oejenkinscidockerregistry.azurecr.io/oetools-azure:<version>
#     $ sudo docker logout
#
# You can check that the image has been successfully uploaded by checking
# the oejenkinscidockerregistry Container registry in Azure at this link,
# assuming you have proper permissions:
# https://ms.portal.azure.com/#@microsoft.onmicrosoft.com/resource/subscriptions/e5839dfd-61f0-4b2f-b06f-de7fc47b5998/resourceGroups/OE-Jenkins-CI/providers/Microsoft.ContainerRegistry/registries/oejenkinscidockerregistry/overview

FROM ubuntu:16.04

RUN \
  apt-get update && apt-get install --no-install-recommends -y wget ca-certificates \
  # Install the LLVM 7 toolchain repo.
  && echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list \
  && echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list \
  && wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
  && apt-get update \
  # Install Clang 7 to build with Spectre mitigation.
  && apt-get install --no-install-recommends -y clang-7 lldb-7 lld-7 \
  # Install all the packages specified in install-prereqs except CMake.
  && apt-get install --no-install-recommends -y \
  # Please keep these sorted alphabetically.
  autoconf \
  automake \
  clang-format \
  dh-exec \
  doxygen \
  dpkg-dev \
  g++ \
  gawk \
  gcc \
  gdb \
  git \
  graphviz \
  libcurl3 \
  libexpat1-dev \
  libmbedtls10 \
  libprotobuf9v5 \
  libssl-dev \
  libtool \
  make \
  ocaml-native-compilers \
  openssl \
  subversion \
  sudo \
  && rm -rf /var/lib/apt/lists/*

# Install packages not available in repositories.
ARG webserver=10.31.100.105
RUN \
  # Install CMake 3.11 so that skipped tests are not marked as failures.
  wget https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.tar.gz \
  && tar xf cmake-3.11.4-Linux-x86_64.tar.gz \
  && rm cmake-3.11.4-Linux-x86_64.tar.gz \
  # Install the Intel DCAP dependencies.
  && wget https://download.01.org/intel-sgx/dcap-1.0/SGX_installers/ubuntu16.04/libsgx-enclave-common_2.3.100.46354-1_amd64.deb \
  && dpkg -i libsgx-enclave-common_2.3.100.46354-1_amd64.deb \
  && rm      libsgx-enclave-common_2.3.100.46354-1_amd64.deb \
  && wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/pool/main/libs/libsgx-enclave-common-dev/libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb \
  && dpkg -i libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb \
  && rm      libsgx-enclave-common-dev_2.3.100.0-1_amd64.deb \
  && wget https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb \
  && dpkg -i libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb \
  && rm      libsgx-dcap-ql_1.0.100.46460-1.0_amd64.deb \
  && wget https://download.01.org/intel-sgx/dcap-1.0/DCAP_installers/ubuntu16.04/libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb \
  && dpkg -i libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb \
  && rm      libsgx-dcap-ql-dev_1.0.100.46460-1.0_amd64.deb \
  && wget https://download.01.org/intel-sgx/dcap-1.0/sgx_linux_x64_driver_dcap_36594a7.bin -O sgx_linux_x64_driver.bin \
  && chmod +x sgx_linux_x64_driver.bin \
  && mkdir -p /opt/bits \
  && mv       sgx_linux_x64_driver.bin /opt/bits \
  # Install the Azure Quote Provider package.
  && wget http://$webserver/azquotprov_0.3-1_amd64.deb \
  && dpkg -i azquotprov_0.3-1_amd64.deb \
  && rm      azquotprov_0.3-1_amd64.deb

ENV PATH="/cmake-3.11.4-Linux-x86_64/bin:${PATH}"

# Configure Git in target image to enable merge/rebase actions.
RUN git config --global user.email "oeciteam@microsoft.com"
RUN git config --global user.name "OE CI Team"
