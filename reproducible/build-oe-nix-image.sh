#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# build-oe-nix-image.sh  
# Builds the nix based build image for OpenEnclave SDK

#
# We fix the user name and id or else the tar files in the deb won't match from location to location. It is possible
# that a build system requires a different user name and id. If so, then they need to ensure that those ids are 
# used consistently or the build won't be reproducible, at least at the level of the .deb.
export BUILD_USER=azureuser
export BUILD_USER_ID=1000
export BUILD_USER_HOME=/home/azureuser

# The base images for ubu 20.04 are multiarchitecture so there is only one sha for aarch64 and x86_64.
# Do not assume that for other cases.
export BUILD_BASE_IMAGE="ubuntu@sha256:fff16eea1a8ae92867721d90c59a75652ea66d29c05294e6e2f898704bdb8cf1"

docker build -f Dockerfile.nix --build-arg BASE_IMAGE=$BUILD_BASE_IMAGE --build-arg BUILD_USER=$BUILD_USER --build-arg BUILD_USER_ID=$BUILD_USER_ID --build-arg BUILD_USER_HOME=$BUILD_USER_HOME --no-cache . -t openenclave-build
