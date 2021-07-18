#!/bin/sh
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
# 

# This script installs the Nix package manager on your system by
# downloading a binary distribution and running its installer script
# (which in turn creates and populates /nix).

set -x
{ # Prevent execution if this script was only partially downloaded
oops() {
    echo "$0:" "$@" >&2
    exit 1
}

tmpDir="$(mktemp -d -t nix-binary-tarball-unpack.XXXXXXXXXX || \
          oops "Can't create temporary directory for downloading the Nix binary tarball")"
cleanup() {
    rm -rf "$tmpDir"
}
trap cleanup EXIT INT QUIT TERM

require_util() {
    command -v "$1" > /dev/null 2>&1 ||
        oops "you do not have '$1' installed, which I need to $2"
}

case "$(uname -s).$(uname -m)" in
    Linux.x86_64) system=x86_64-linux; hash=d77c1fd1d6bc597bce390455313e5e42b1bc3d5752994059eed69d43588d022b;;
    Linux.i?86) system=i686-linux; hash=51bc060dfeaa80d10597e61953ae4ca75ba5fd80cf91fe17c90218420e823d69;;
    Linux.aarch64) system=aarch64-linux; hash=bf50a6b41cb0f61c05c2b6ee98b5c544272a1ab088c0595784d7c7e17989f49b;;
    Darwin.x86_64) system=x86_64-darwin; hash=0896dffeb266d17cf28a6f1cf9ab110909dd2a5dc76f6b333edb1619131b0a4c;;
    *) oops "sorry, there is no binary distribution of Nix for your platform";;
esac

url="https://releases.nixos.org/nix/nix-2.3.7/nix-2.3.7-$system.tar.xz"

tarball="$tmpDir/$(basename "$tmpDir/nix-2.3.7-$system.tar.xz")"

require_util curl "download the binary tarball"
require_util tar "unpack the binary tarball"
if [ "$(uname -s)" != "Darwin" ]; then
    require_util xz "unpack the binary tarball"
fi

echo "downloading Nix 2.3.7 binary tarball for $system from '$url' to '$tmpDir'..."
curl -L "$url" -o "$tarball" || oops "failed to download '$url'"

if command -v sha256sum > /dev/null 2>&1; then
    hash2="$(sha256sum -b "$tarball" | cut -c1-64)"
elif command -v shasum > /dev/null 2>&1; then
    hash2="$(shasum -a 256 -b "$tarball" | cut -c1-64)"
elif command -v openssl > /dev/null 2>&1; then
    hash2="$(openssl dgst -r -sha256 "$tarball" | cut -c1-64)"
else
    oops "cannot verify the SHA-256 hash of '$url'; you need one of 'shasum', 'sha256sum', or 'openssl'"
fi

if [ "$hash" != "$hash2" ]; then
    oops "SHA-256 hash mismatch in '$url'; expected $hash, got $hash2"
fi

unpack=$tmpDir/unpack
mkdir -p "$unpack"
tar -xJf "$tarball" -C "$unpack" || oops "failed to unpack '$url'"

script=$(echo "$unpack"/*/install)

[ -e "$script" ] || oops "installation script is missing from the binary tarball!"
"$script" "$@"

set +x
} # End of wrapping
