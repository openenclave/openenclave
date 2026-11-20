#!/usr/bin/env bash
# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Usage: bash run.sh <installed-sdk-prefix> <build-root>
# Run on Linux with GCC, Clang, CMake, Ninja and the SDK runtime dependencies.
set -euo pipefail
sdk=$(cd -- "${1:?Specify the installed SDK prefix}" && pwd)
build_root=${2:?Specify an unused consumer build root}
source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Never reuse caches from a different SDK/compiler or overwrite prior results.
if [[ -e $build_root ]]; then
    echo "Consumer build root already exists: $build_root" >&2
    exit 1
fi

for compiler in gcc clang; do
    if [[ $compiler == gcc ]]; then cxx=g++; else cxx=clang++; fi
    "$compiler" --version
    for standard in 14 17; do
        for optimization in O2 O3; do
            build="$build_root/$compiler-cxx$standard-$optimization"
            cmake -S "$source_dir" -B "$build" -G Ninja \
                -DCMAKE_PREFIX_PATH="$sdk" \
                -DCMAKE_C_COMPILER="$compiler" -DCMAKE_CXX_COMPILER="$cxx" \
                -DCMAKE_CXX_STANDARD="$standard" -DCMAKE_BUILD_TYPE=Release \
                "-DCMAKE_CXX_FLAGS_RELEASE=-$optimization -DNDEBUG"
            cmake --build "$build" --parallel 2
            ctest --test-dir "$build" --output-on-failure --no-tests=error
        done
    done
done
