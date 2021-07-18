# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
ARG BASE_IMAGE="ubuntu@sha256:fff16eea1a8ae92867721d90c59a75652ea66d29c05294e6e2f898704bdb8cf1"
FROM $BASE_IMAGE

#
# Build container to produce reproducible nix derivation and .deb package of the OpenEnclave SDK
# 
# Uses nix package manager to wrap the standard build process.
#
# 
#
RUN apt-get update \
        && apt-get install -y curl python3 perl git vim \
        && mkdir -p /nix /etc/nix \
        && chmod a+rwx /nix \
        && echo 'sandbox = false\nkeep-derivations = true\nkeep-env-derivations = true' > /etc/nix/nix.conf \
        && rm -rf /var/lib/apt/lists/*

ADD https://oejenkins.blob.core.windows.net/oejenkins/oe-nix-artifacts/nix-libs.tar.gz /tmp
RUN chmod a+r /tmp/nix-libs.tar.gz
RUN mkdir -p /output
RUN mkdir -p /output/build
RUN chmod -R 777 /output
RUN mkdir -p /opt/openenclave
RUN chmod -R 777 /opt/openenclave
ENV ARCH=$(arch)

#
# We allow overriding these settings, but if one does, the build user and id must match or else the .deb tars won't have 
# a reproducible signature, since tar entries include user and group ownerships.
ARG BUILD_USER=azureuser
ARG BUILD_USER_ID=1000
ARG BUILD_USER_HOME=/home/azureuser

# This will exclude oegdb, samples, and report 
ARG TEST_EXCLUSIONS="-E samples\|oegdb-test\|report"

#add a user for Nix
RUN echo "adduser $BUILD_USER --uid $BUILD_USER_ID --home $BUILD_USER_HOME"
RUN adduser $BUILD_USER --uid $BUILD_USER_ID --home $BUILD_USER_HOME --disabled-password --gecos "" --shell /bin/bash
RUN addgroup nixbld 
RUN adduser $BUILD_USER  nixbld
ENV USER=$BUILD_USER
USER $BUILD_USER
CMD /bin/bash -l
WORKDIR /home/$BUILD_USER
# 
RUN echo "User is $USER "
#install the required software
#RUN touch .bash_profile \
#
# We add the nix install and packages into the container rather than waiting for run time.
# The packages are then located in the nix store until the next push of the container
ADD ./install-nix.sh /home/$BUILD_USER
RUN  /bin/bash /home/$BUILD_USER/install-nix.sh
ENV NIX_PATH=/home/$BUILD_USER
ADD ./prep-nix-build.sh /home/$BUILD_USER
RUN /bin/bash ./prep-nix-build.sh /home/$BUILD_USER/nixpkgs

ADD ./openenclave-sdk.nix /home/$BUILD_USER
ADD ./sort_deb_sum.sh /home/$BUILD_USER
ADD ./nix-build.sh /home/$BUILD_USER
ADD ./nix-shell.sh /home/$BUILD_USER
ADD ./nix-ctest.sh /home/$BUILD_USER
ADD ./build_deb_pkg.sh /home/$BUILD_USER
RUN mkdir -p /home/$BUILD_USER/.nix_libs
