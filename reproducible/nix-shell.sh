#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# nix-shell.sh runs nix-shell with arguments.
#
. /home/$USER/.nix-profile/etc/profile.d/nix.sh

for i in /output/*.nar
do
   cat $i | nix-store --import
done

DO_CHECK=true DO_PACKAGE=false nix-shell -I. openenclave-sdk.nix --substituters 'https://cache.nixos.org' \
	    --argstr REV $BUILD_REV \
	    --argstr SHA $BUILD_SHA 
