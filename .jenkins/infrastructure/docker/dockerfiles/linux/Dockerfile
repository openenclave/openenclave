# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

#
# IMPORTANT- Please update the version number in the next sentence
# when you create a new docker image.
#
# This Dockerfile script builds an image for tag oetools-18.04/20.04

# To use this Dockerfile, you will need to install docker-ce.
#
# Once installed, build a docker image from .jenkins folder and
# it will use this Dockerfile by default:
#     openenclave$ sudo docker build --no-cache=true --build-arg ubuntu_version=<ubuntu_version> -t oetools-<ubuntu_version>:<version> -f .jenkins/Dockerfile.full .
#
# For example, for version 1.x with Ubuntu 18.04 :
#     openenclave$ sudo docker build \
#         --no-cache=true \
#         --build-arg ubuntu_version=18.04 \
#         --build-arg devkits_uri=https://oejenkins.blob.core.windows.net/oejenkins/OE-CI-devkits-d1634ce8.tar.gz \
#         -t oetools-18.04:1.x \
#         -f .jenkins/infrastructure/docker/dockerfiles/linux/Dockerfile \
#         .
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
#     $ sudo docker tag oetools-<ubuntu_version>:<version> oejenkinscidockerregistry.azurecr.io/oetools-<ubuntu_version>:<version>
#     $ sudo docker push oejenkinscidockerregistry.azurecr.io/oetools-<ubuntu_version>:<version>
#     $ sudo docker logout
#
# This image includes out-of-proc attestation using Intel SGX by default.
# To allow this, the Intel SGX AESM Service will need to be made available by creating the container with the following parameter:
#   --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket
#

ARG ubuntu_version=18.04

FROM ubuntu:${ubuntu_version}

ARG UNAME=jenkins
ARG GNAME=jenkins
# This UID/GID needs to match Jenkins agent UID/GID
ARG UID=1000
ARG GID=1000
ARG devkits_uri

# Workaround for https://githubmemory.com/repo/pypa/pip/issues/10219
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# Install essential packages
RUN apt-get update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y install make build-essential git jq vim curl wget netcat apt-transport-https unzip && \
    apt-get clean && \
    rm -rf rm /var/lib/apt/lists/*

# Setup devkit
RUN curl ${devkits_uri} | tar xvz --no-same-permissions --no-same-owner
RUN echo ${devkits_uri##*/} > /devkits/TARBALL

# Add Microsoft repo
RUN echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ bionic main" | tee /etc/apt/sources.list.d/azure-cli.list && \
    wget https://packages.microsoft.com/keys/microsoft.asc && \
    apt-key add microsoft.asc

# Install Azure CLI
RUN apt-get update && \
    apt-get -y install azure-cli && \
    apt-get clean && \
    rm -rf rm /var/lib/apt/lists/*

# Install packer
RUN wget https://releases.hashicorp.com/packer/1.5.5/packer_1.5.5_linux_amd64.zip && \
    unzip packer_1.5.5_linux_amd64.zip -d /usr/sbin && \
    rm packer_1.5.5_linux_amd64.zip

# Run Ansible
COPY ./scripts/ansible /ansible
COPY ./scripts/lvi-mitigation /lvi-mitigation
RUN /ansible/install-ansible.sh && \
    ansible localhost --playbook-dir=/ansible -m import_role -a "name=linux/docker tasks_from=ci-setup.yml" -vvv && \
    /ansible/remove-ansible.sh && \
    apt-get remove -y python3-pip && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /ansible /lvi-mitigation /root/.cache /root/.ansible /var/lib/apt/lists/*

# Configure Git in target image to enable merge/rebase actions.
RUN git config --global user.email "oeciteam@microsoft.com"
RUN git config --global user.name "OE CI Team"

# Create user
RUN groupadd --gid ${GID} ${GNAME}
RUN useradd --create-home --uid ${UID} --gid ${GID} --shell /bin/bash ${UNAME}
RUN echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set up out-of-proc attestation
ENV SGX_AESM_ADDR=1
