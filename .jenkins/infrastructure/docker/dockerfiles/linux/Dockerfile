# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

#
# IMPORTANT- Please update the version number in the next sentence
# when you create a new docker image.
#
# This Dockerfile script builds an image for oetools-20.04

# To use this Dockerfile, you will need to install docker-ce.
#
# Once installed, build a docker image from .jenkins folder and
# it will use this Dockerfile by default:
#     openenclave$ sudo docker build --no-cache=true --build-arg ubuntu_version=<ubuntu_version> -t oetools-<ubuntu_version>:<version> -f .jenkins/Dockerfile.full .
#
# For example, for Ubuntu 20.04 :
#     openenclave$ sudo docker build \
#         --no-cache=true \
#         --build-arg ubuntu_version=20.04 \
#         --build-arg devkits_uri=https://openenclavepublicstorage.blob.core.windows.net/openenclavedependencies/OE-CI-devkits-d1634ce8.tar.gz \
#         -t oetools-20.04 \
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
# This image includes out-of-proc attestation using Intel SGX by default.
# To allow this, the Intel SGX AESM Service will need to be made available by creating the container with the following parameter:
#   --volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket
#
# Note that while building Ubuntu 22.04 is possible, it is not currently supported by Open Enclave SDK.

ARG ubuntu_version=20.04
ARG ubuntu_source_repo=""

FROM ${ubuntu_source_repo}ubuntu:${ubuntu_version}

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

# Run Ansible
COPY ./scripts/ansible /ansible
COPY ./scripts/lvi-mitigation /lvi-mitigation
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC /ansible/install-ansible.sh && \
    ansible localhost --playbook-dir=/ansible -m import_role -a "name=linux/docker tasks_from=ci-setup.yml" -vvv && \
    /ansible/remove-ansible.sh && \
    apt-get remove -y python3-pip && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /ansible /lvi-mitigation /root/.cache /root/.ansible /var/lib/apt/lists/*

# Create user
RUN groupadd --gid ${GID} ${GNAME}
RUN useradd --create-home --uid ${UID} --gid ${GID} --shell /bin/bash ${UNAME}
RUN echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set up out-of-proc attestation
ENV SGX_AESM_ADDR=1
