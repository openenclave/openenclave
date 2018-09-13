# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#
# IMPORTANT- Please update the version number in the next sentence
# when you create a new docker image.
#
# This Dockerfile script builds an image for tag oetools-azure:1.2

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

ENV PATH="/cmake-3.11.4-Linux-x86_64/bin:${PATH}"

RUN apt-get -y update
RUN apt-get -y install wget
RUN echo "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list; echo "deb-src http://apt.llvm.org/xenial/ llvm-toolchain-xenial-7 main" >> /etc/apt/sources.list; wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -; apt-get -y update; apt-get -y install clang-7 lldb-7 lld-7

# install all the packages specified in install-prereqs except cmake
RUN apt-get -y install clang-format gcc g++ make gdb autoconf libtool doxygen graphviz gawk libexpat1-dev openssl libssl-dev subversion ocaml-native-compilers libcurl3 dh-exec libmbedtls10 sudo git dpkg-dev

# install wget as this is needed for getting latest cmake & Libsgx FLC packages
# dpkg-dev is also needed by those packages for installing symlinks to lib files

# Install cmake v3.11 so that skipped tests are not marked as failures. This
# version is not currently available via apt-get.
RUN wget https://cmake.org/files/v3.11/cmake-3.11.4-Linux-x86_64.tar.gz
RUN tar xf cmake-3.11.4-Linux-x86_64.tar.gz

# Download the Libsgx FLC packages
ARG webserver=10.31.100.105
RUN wget http://$webserver/libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
RUN wget http://$webserver/libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
RUN wget http://$webserver/libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
RUN wget http://$webserver/libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
RUN wget http://$webserver/azquotprov_0.2-1_amd64.deb
RUN wget http://$webserver/sgx_linux_x64_driver.bin

RUN dpkg -i libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
RUN dpkg -i libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
RUN dpkg -i libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
RUN dpkg -i libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
RUN dpkg -i azquotprov_0.2-1_amd64.deb
RUN chmod +x sgx_linux_x64_driver.bin; mkdir -p /opt/bits; mv sgx_linux_x64_driver.bin /opt/bits

RUN git config --global user.email "oeciteam@microsoft.com"
RUN git config --global user.name "OE CI Team"

# Cleanup after we are done
RUN rm -f cmake-3.11.4-Linux-x86_64.tar.gz

RUN rm -f libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
RUN rm -f libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
RUN rm -f libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
RUN rm -f libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
RUN rm -f azquotprov_0.2-1_amd64.deb
