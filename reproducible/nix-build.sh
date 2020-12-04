#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 
# nix-build.sh runs nix-build with arguments resolved
set -x
. /home/$USER/.nix-profile/etc/profile.d/nix.sh

if [ $OE_SIMULATION ]
then 
OE_SIM="--argstr OE_SIM OE_SIMULATION=1"
fi

nix-build -I. openenclave-sdk.nix --substituters 'https://cache.nixos.org' \
	    --argstr REV $BUILD_REV \
	    --argstr SHA $BUILD_SHA 

NIX_FILE1="$(basename /nix/store/*openenclave-sdk)-$(date +%Y%j%H%M).nar"
NIX_FILE2="$(basename /nix/store/*openenclave-sdk)-references-$(date +%Y%j%H%M).nar"

nix-store --export $(ls -d /nix/store/*openenclave-sdk*) >/output/${NIX_FILE1}
nix-store --export $(nix-store --realize $(nix-store --query --references /nix/store/*openenclave-sdk*)) >/output/${NIX_FILE2}

nix-shell -I. openenclave-sdk.nix --substituters 'https://cache.nixos.org' \
	    --argstr REV $BUILD_REV \
	    --argstr SHA $BUILD_SHA 


set +x
