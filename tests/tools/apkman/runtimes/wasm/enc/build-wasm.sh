#!/bin/sh
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

rm -rf wasm3 build

# Clone repository and build it via cmake.
git clone https://github.com/wasm3/wasm3 --depth 1 --branch v0.4.8
mkdir build

(
  cd build || exit 1
  export CC=gcc
  export CXX=g++
  export CFLAGS="-g -fpic -ftls-model=local-exec"
  export CXXFLAGS="$CFLAGS"
  cmake ../wasm3 -DCMAKE_BUILD_TYPE=RelWithDebInfo
  make -j 4
)

# Copy generated libraries for building enclave.
cp /apkbuild/exe-libs/wasm3.a/* .

# Compile main program and generate object file.
cd wasm3 || exit 1
gcc -Og -g  -Isource -Dd_m3HasWASI platforms/app/main.c -c -o ../main.o

# Copy tests
cp -r test/benchmark ..
