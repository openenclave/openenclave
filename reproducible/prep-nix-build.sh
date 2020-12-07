#!/bin/bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 

#
# Set up a host for docker builds using nix. This assumes nix has been installed.
# Setting up the nix build on the host as opposed to completely restricting the build
# infrastructure means we don't need to set up libsgx infrastructure in the container
# and can instead run tests separately. This is desirable as many build machines don't support
# SGX, or at least don't have it enabled. 
#
# prep-nix-build.sh $nixpkgs_dest
#
#
# First clone the nixpkgs repo. With a little discipline we can 
# keep all package accesses on this machine.
#
export NIX_PKGS_REPO=https://github.com/yakman2020/nixpkgs.git

export NIX_PKGS=$1

export NIX_PKGS_BRANCH=acc-test2

if [ -d ${NIX_PKGS} ]
then
    # We should checkout a specific tag here
    pushd ${NIX_PKGS} ; git pull ; git checkout ${NIX_PKGS_BRANCH} ; popd
else
    git clone https://github.com/yakman2020/nixpkgs.git ${NIX_PKGS}
    pushd ${NIX_PKGS} ; git pull ; git checkout ${NIX_PKGS_BRANCH} ; popd
fi

# Install the packages 

set -x
source /home/azureuser/.nix-profile/etc/profile.d/nix.sh 
nix-channel --remove nixpkgs # Only get packages from our local nixpkgs via -I or NIX_PATH.
export NIX_PATH=$NIX_PKGS/..

#
# Some basic info for the log file.
#
pwd
id
pushd ./nixpkgs
git status
popd
#
# This is a workaround to the fact that nix cannot simply specify versions of packages.
# we prime the nix store with specific package signatures.
# 
# We are using a known branch of nixpkgs, so we can predict the derivation signature.
# We instantate the package, then install the "known" derivation. This should be robust 
# unless there is some change to the branch. We know the derviation, so we don't make that 
# a variable.  If the derivation signature is different, something changed and we should fail.
#
# Priming nix-store like this should gaurantee we will get the needed versions when we 
# build openenclave.
#
# We are currently installing the buildinputs for openenclave as derivations 
# so we could audit the code. 
#
# Outside this script we are configuring nix to keep-derivations so we can inspect them as 
# needed. With that, we can inspect source of all the build inputs if desired.
#
# We can also force a complete build from source by building openenclave via
# nix-build --substituters '' .... . Since the build result is deterministic, 
# we can verify we are getting the packages we think we are, as the output will have
# the same sha256 hash.
#

if [ $(uname -m) == "aarch64" ]
then
    nix-instantiate -I. -E '(import <nixpkgs> {}).cmake'
    nix-env -I. -i /nix/store/p34s8yj3ws6289xa30z4gf7yy5933g4l-cmake-3.16.3.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).openssl'
    nix-env -I. -i /nix/store/mddaj30wwqyfg3pvid3q7zmhsr3mjnp4-openssl-1.1.1g.drv!bin
    nix-instantiate -I. -E '(import <nixpkgs> {}).gnumake'
    nix-env -I. -i /nix/store/34k6saz5kl8j0945b28s00kxhyx3y10p-gnumake-4.2.1.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).binutils'
    nix-env -I. -i /nix/store/k2kiqgagj53mq9hv6m0rx9dihsdpyd0w-binutils-wrapper-2.31.1.drv
    nix-env -I. --set-flag priority 5 binutils-2.31.1 
    nix-instantiate -I. -E '(import <nixpkgs> {}).llvm_7'
    nix-env -I. -i /nix/store/gx4i3qg3rq112igqb4vnv629ci7kyd72-llvm-7.1.0.drv
    nix-env -I. --set-flag priority 10 llvm_7
    nix-instantiate -I. -E '(import <nixpkgs> {}).clang7'
    nix-env -I. =i /nix/store/plh8xpy580gd117jpi4pnmv0dl2qdbh4-clang-wrapper-7.1.0.drv
    nix-env -I. --set-flag priority 20 clang_7
    nix-instantiate -I. -E '(import <nixpkgs> {}).python3'
    nix-env -I. -i /nix/store/iwf5i1f72inw05in0vr9bbp1a7hwmxh5-python3-3.7.6.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).doxygen'
    nix-env -I. -i /nix/store/gbhhc8mxvw8hxx2k8r73jj5brbi7hk62-doxygen-1.8.17.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).dpkg'
    nix-env -I. -i /nix/store/dfdvxn42glnb9xgy8yrkd70gjnvhx6y0-dpkg-1.19.7.drv

    # needed for nix-shell debug
    nix-env -I. -i /nix/store/z976i71y86b771hz14k62j5x8cifnppf-vim-8.2.1522.drv
else
    nix-instantiate -I. -E '(import <nixpkgs> {}).cmake'
    nix-env -I. -i /nix/store/p34s8yj3ws6289xa30z4gf7yy5933g4l-cmake-3.16.3.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).openssl'
    nix-env -I. -i /nix/store/mddaj30wwqyfg3pvid3q7zmhsr3mjnp4-openssl-1.1.1g.drv!bin
    nix-instantiate -I. -E '(import <nixpkgs> {}).gnumake'
    nix-env -I. -i /nix/store/34k6saz5kl8j0945b28s00kxhyx3y10p-gnumake-4.2.1.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).binutils'
    nix-env -I. -i /nix/store/k2kiqgagj53mq9hv6m0rx9dihsdpyd0w-binutils-wrapper-2.31.1.drv
    nix-env -I. --set-flag priority 5 binutils-2.31.1 
    nix-instantiate -I. -E '(import <nixpkgs> {}).llvm_7'
    nix-env -I. -i /nix/store/gx4i3qg3rq112igqb4vnv629ci7kyd72-llvm-7.1.0.drv
    nix-env -I. --set-flag priority 10 llvm_7
    nix-instantiate -I. -E '(import <nixpkgs> {}).clang_7'
    nix-env -I. -i /nix/store/plh8xpy580gd117jpi4pnmv0dl2qdbh4-clang-wrapper-7.1.0.drv
    nix-env -I. --set-flag priority 20 clang_7
    nix-instantiate -I. -E '(import <nixpkgs> {}).python3'
    nix-env -I. -i  /nix/store/iwf5i1f72inw05in0vr9bbp1a7hwmxh5-python3-3.7.6.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).doxygen'
    nix-env -I. -i /nix/store/gbhhc8mxvw8hxx2k8r73jj5brbi7hk62-doxygen-1.8.17.drv
    nix-instantiate -I. -E '(import <nixpkgs> {}).dpkg'
    nix-env -I. -i /nix/store/dfdvxn42glnb9xgy8yrkd70gjnvhx6y0-dpkg-1.19.7.drv

    # needed for nix-shell debug
    nix-env -I. -i /nix/store/6a6ilqysgz1gwfs0ahriw94q35vj84sy-vim-8.2.1123 
fi

set +x
