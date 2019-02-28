# !/bin/bash
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#
# script to test the samples
#
# Arguments: [-i <install_prefix> <bin_dir>]
#
# -i <bin_dir> <install_prefix> <tmp_prefix>]
#   Temporary install prior to test-run, use this for verification inside
#   the build tree
#
#    <bin_dir> - PROJECT_BINARY_DIR from cmake
#    <install_prefix> - the CMAKE_INSTALL_PREFIX prefix configured w/ cmake
#    <tmp_prefix> - absolute path to put the tmp install under
#
# run the make-variant with make
# run the cmake-variant in separate cmake instance

printandexit(){
    echo An error occured
    exit 1
}

# Collect arguments and do a temporary install if requested
if test "$1" = "-i" ; then
    # inside build tree. install using DESTDIR mechanism.
    BIN_DIR=$(realpath $2)
    INSTALL_DIR=$(realpath -m $4$3)
    rm -rf "$INSTALL_DIR"
    DESTDIR=$4 cmake --build "$BIN_DIR" --target install
else
    # inside installed tree. Assume this is placed under
    # prefix/share/openenclave/samples/
    INSTALL_DIR=$(realpath $(dirname $0)/../../..)
fi || printandexit

TEST_MAKE_DIR="$INSTALL_DIR/share/openenclave/samples"

# Set the PKG_CONFIG_PATH environment variable so that the samples will use
# the OE pkg-config scripts located in the build directory.
export PKG_CONFIG_PATH="$BIN_DIR/pkgconfig"

# Add bin path  on the path first:
export PATH="$INSTALL_DIR/bin:${PATH}"

# build and run the make samples
# The only exception is to not run them in simulation mode on SGX1-FLC platforms
if [ $OE_SIMULATION ] && [ $USE_LIBSGX ]; then
    MAKE_TASKS="clean build"
    echo "Skip running NGSA samples in simulation mode."
else
    MAKE_TASKS="world"
fi
make -C "$TEST_MAKE_DIR" OE_PREFIX=$INSTALL_DIR $MAKE_TASKS || printandexit

exit 0
