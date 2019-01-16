#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"

OE_PATH=$PWD/../..
NP_PATH=$OE_PATH/new_platforms

OPTEE_OS_PATH=$OE_PATH/3rdparty/optee_os

# Select default architecture.
if [ -z "$ARCH" ]; then
    ARCH=arm
elif [ $ARCH != "arm" ] && [ $ARCH != "aarch64" ]; then
    echo FAILED: ARCH must be set to either "arm", "aarch64" or empty, which implies "arm".
    exit 1
fi

# -------------------------------------
# Package Prerequisites
# -------------------------------------

echo Installing Prerequisites

sudo apt-get update
sudo apt-get -y install android-tools-adb android-tools-fastboot autoconf \
    automake bc bison build-essential cscope curl device-tree-compiler \
    doxygen flex ftp-upload gdisk iasl libattr1-dev libcap-dev libfdt-dev \
    libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev \
    libssl-dev libtool make mtools netcat python-crypto python-serial \
    python-wand unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev \
    gcc-arm-linux-gnueabi graphviz gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu sshpass cmake

# -------------------------------------
# Download ARM Toolchain
# -------------------------------------

echo Downloading ARM Toolchain

# Create directory for toolchains.
if [ ! -d toolchains ]; then
    mkdir toolchains
fi
pushd toolchains

# Select toolchain for this build.
GCC_DIR_ARM=arm-linux-gnueabihf
GCC_DIR_AARCH64=aarch64-linux-gnu

GCC_ARM=gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
GCC_AARCH64=gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu

if [ $ARCH = "arm" ]; then
    GCC_DIR=$GCC_DIR_ARM
    GCC=$GCC_ARM
elif [ $ARCH = "aarch64" ]; then
    GCC_DIR=$GCC_DIR_AARCH64
    GCC=$GCC_AARCH64
fi

# Download it.
if [ ! -f $GCC.tar.xz ]; then
    wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/$GCC_DIR/$GCC.tar.xz || exit 1

    # Extract it.
    if [ ! -d $ARCH ]; then
        mkdir $ARCH
        pushd $ARCH

        tar --strip-components=1 -xvf ../$GCC.tar.xz || exit 1

        popd  # $ARCH
    fi
fi

popd  # toolchains

# -------------------------------------
# Configure ARM Toolchain
# -------------------------------------

if [ $ARCH = "arm" ]; then
    TA_DEV_KIT_BITS=32

    TA_CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-

    CROSS_COMPILE=$PWD/toolchains/$ARCH/bin/arm-linux-gnueabihf-
elif [ $ARCH = "aarch64" ]; then
    TA_DEV_KIT_BITS=64

    TA_CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-
    TA_CROSS_COMPILE_32=/usr/bin/arm-linux-gnueabi-

    CROSS_COMPILE=$PWD/toolchains/$ARCH/bin/aarch64-linux-gnu-
fi

# -------------------------------------
# Build OP-TEE
# -------------------------------------

PROC_COUNT=$(eval "cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l")

if [ -z "$TA_DEV_KIT_DIR" ]; then
    echo Building OP-TEE OS

    pushd $OPTEE_OS_PATH

    OPTEE_VIRT_FLAGS=platform-cflags-optimization=-Os \
                     CFG_CRYPTO_SIZE_OPTIMIZATION=y   \
                     CFG_PAGED_USER_TA=n              \
                     CFG_REE_FS=n                     \
                     CFG_RPMB_FS=y                    \
                     CFG_RPMB_TESTKEY=y               \
                     CFG_RPMB_WRITE_KEY=n             \
                     CFG_RPMB_RESET_FAT=n             \
                     CFG_TA_RPC=y                     \
                     CFG_TEE_CORE_DEBUG=y             \
                     CFG_TEE_CORE_LOG_LEVEL=2         \
                     CFG_TEE_TA_LOG_LEVEL=4           \
                     CFG_UNWIND=n                     \
                     CFG_WITH_PAGER=n                 \
                     CFG_WITH_USER_TA=y

    if [ $ARCH = "arm" ]; then
        if [ -z "$MACHINE" ] || [ "$MACHINE" = "virt" ]; then
            ARCH=arm make -j $PROC_COUNT PLATFORM=vexpress-qemu_virt       \
                                         $OPTEE_VIRT_FLAGS                 \
                                         CROSS_COMPILE=$CROSS_COMPILE      \
                                         CROSS_COMPILE_core=$CROSS_COMPILE \
                                         $* || exit 1
            TA_DEV_KIT_PLAT=vexpress
        else
            echo FAILED: For ARM, MACHINE must be either "virt" or empty, which implies "virt".
            exit 1
        fi
    elif [ $ARCH = "aarch64" ]; then
        if [ -z "$MACHINE" ] || [ "$MACHINE" = "virt" ]; then
            ARCH=arm make -j $PROC_COUNT PLATFORM=vexpress-qemu_armv8a               \
                                         $OPTEE_VIRT_FLAGS                           \
                                         CROSS_COMPILE=$CROSS_COMPILE                \
                                         CROSS_COMPILE_core=$CROSS_COMPILE           \
                                         CROSS_COMPILE_ta_arm64=$TA_CROSS_COMPILE    \
                                         CROSS_COMPILE_ta_arm32=$TA_CROSS_COMPILE_32 \
                                         CFG_ARM64_core=y                            \
                                         $* || exit 1
            TA_DEV_KIT_PLAT=vexpress

        elif [ "$MACHINE" = "ls1012grapeboard" ]; then
            ARCH=arm make -j $PROC_COUNT PLATFORM=ls-ls1012grapeboard                \
                                         CROSS_COMPILE=$CROSS_COMPILE                \
                                         CROSS_COMPILE_core=$CROSS_COMPILE           \
                                         CROSS_COMPILE_ta_arm64=$TA_CROSS_COMPILE    \
                                         CROSS_COMPILE_ta_arm32=$TA_CROSS_COMPILE_32 \
                                         CFG_ARM64_core=y                            \
                                         $* || exit 1
            TA_DEV_KIT_PLAT=ls
        else
            echo FAILED: For AARCH64, MACHINE must be either "virt", "ls1012grapeboard" or empty, which implies "virt".
            exit 1
        fi
    fi

    popd  # $OPTEE_OS_PATH
    
    TA_DEV_KIT_DIR=$OE_PATH/3rdparty/optee_os/out/arm-plat-$TA_DEV_KIT_PLAT/export-ta_arm$TA_DEV_KIT_BITS
fi

# -------------------------------------
# Build Open Enclave SDK
# -------------------------------------

echo Building Open Enclave SDK

# Create directory structure.
if [ ! -d build ]; then
    mkdir build
fi
pushd build

if [ ! -d $ARCH ]; then
    mkdir $ARCH
fi
pushd $ARCH

# Configure build (mind the trailing period).
ln -s $NP_PATH/scripts/toolchains .

cmake -DOE_TEE=TZ                                                \
      -DTA_DEV_KIT_DIR=$TA_DEV_KIT_DIR                           \
      -DCMAKE_TOOLCHAIN_FILE=$NP_PATH/cmake/linux-$ARCH-v6.cmake \
      $NP_PATH || exit 1

# Build.
cmake --build . -- -j $PROC_COUNT || exit 1

popd  # $ARCH
popd  # build

# -------------------------------------
# Documentation
# -------------------------------------

echo Building Documentation

doxygen $NP_PATH/Doxyfile || exit 1
