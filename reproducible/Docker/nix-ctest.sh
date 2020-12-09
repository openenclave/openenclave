#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# nix-shell.sh runs nix-shell with arguments.
#
. /home/$USER/.nix-profile/etc/profile.d/nix.sh

for i in /output/*openenclave-sdk-references*.nar /output/*openenclave-sdk-[0-9]*.nar
do
    echo "import $i"
    cat $i | nix-store --import
done

if [[ ! -f ~/.nix-libs/libsgx_launch.so.1 ]]
then
     pushd /tmp
     tar xvfz nix-libs.tar.gz
     popd
     cp /tmp/nix-libs/libsgx_enclave_common.so ~/.nix_libs 
     cp /tmp/nix-libs/libsgx_enclave_common.so.1 ~/.nix_libs
     cp /tmp/nix-libs/libsgx_launch.so.1 ~/.nix_libs
     cp /tmp/nix-libs/libprotobuf.so.22  ~/.nix_libs
     cp /tmp/nix-libs/libstdc++.so.6  ~/.nix_libs
fi

nix-shell -I. openenclave-sdk.nix --substituters 'https://cache.nixos.org' \
	    --argstr REV $BUILD_REV \
	    --argstr SHA $BUILD_SHA 
