#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"

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
    gcc-arm-linux-gnueabi graphviz gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

# -------------------------------------
# Download ARM Toolchain
# -------------------------------------

echo Installing ARM Toolchain

GCC_32=gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
GCC_64=gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu

if [ -z "$ARCH" ]; then
    export ARCH=aarch32
fi

if [ "$ARCH" = "aarch32" ]; then
    if [ ! -d $GCC_32 ]; then
        if [ ! -f $GCC_32.tar.xz ]; then
            wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/$GCC_32.tar.xz || exit 1
        fi
        tar xvf $GCC_32.tar.xz || exit 1
    fi
elif [ "$ARCH" = "aarch64" ]; then
    if [ ! -d $GCC_64 ]; then
        if [ ! -f $GCC_64.tar.xz ]; then
            wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/aarch64-linux-gnu/$GCC_64.tar.xz || exit 1
        fi
        tar xvf $GCC_64.tar.xz || exit 1
    fi
fi

# -------------------------------------
# Configure ARM Toolchain
# -------------------------------------

if [ "$ARCH" = "aarch32" ]; then
    TA_DEV_KIT_BITS=32

    TA_CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-

    export CROSS_COMPILE=$PWD/$GCC_32/bin/arm-linux-gnueabihf-
elif [ "$ARCH" = "aarch64" ]; then
    TA_DEV_KIT_BITS=64

    TA_CROSS_COMPILE=/usr/bin/aarch64-linux-gnu-
    TA_CROSS_COMPILE_32=/usr/bin/arm-linux-gnueabi-

    export CROSS_COMPILE=$PWD/$GCC_64/bin/aarch64-linux-gnu-
fi

# -------------------------------------
# Configure Intel SGX SDK
# -------------------------------------

echo Checking for Intel SGX SDK

# Test whether Intel SGX SDK is installed.  If not, but the
# IntelSGXSDKInstallerURI environment variable is set,
# then fetch it from there, else tell the user to go get it.
# This provides a mechanism usable by github-CI.
if [ -e ../3rdparty/SGXSDK/bin/x64/sgx_edger8r ]; then
    export PATH="$PATH:$PWD/../3rdparty/SGXSDK/bin/x64"
fi
if [ -e ../3rdparty/SGXSDK/bin/win32/Release/sgx_edger8r ]; then
    export PATH="$PATH:$PWD/../3rdparty/SGXSDK/bin/win32/Release"
fi
edgepath=`which sgx_edger8r`
if [ -z "$edgepath" ]; then
    edgepath=`which sgx_edger8r.exe`
fi
if [ -z "$edgepath" ]; then
    if [ ! -e ../3rdparty/SGXSDK ]; then
        if [ -n "${IntelSGXSDKInstallerURI}" ]; then
            wget ${IntelSGXSDKInstallerURI} || exit 1
        fi
        if [ -e SGXSDK.zip ]; then
            unzip SGXSDK.zip -d ../3rdparty || exit 1
        fi
    fi
    if [ -e ../3rdparty/SGXSDK ]; then
        export PATH="$PATH:$PWD/../3rdparty/SGXSDK/bin/x64"
        chmod 755 $PWD/../3rdparty/SGXSDK/bin/x64/sgx_edger8r
    fi
fi
edgepath=`which sgx_edger8r`
if [ ! -z "$edgepath" ]; then
    export SGX_EDGER8R=sgx_edger8r
    export SGX_PATHSEP=:
else
    edgepath=`which sgx_edger8r.exe`
    if [ ! -z "$edgepath" ]; then
        export SGX_EDGER8R=sgx_edger8r.exe
        export SGX_PATHSEP=\;
    fi
fi
if [ -z "$edgepath" ]; then
    echo FAILED: You need to first install the Intel SGX SDK from https://software.intel.com/en-us/sgx-sdk/download
    exit 1
fi
if [ "${SGX_EDGER8R}" = "sgx_edger8r.exe" ]; then
    binWin32ReleasePath=$(dirname "${edgepath}")
    binWin32Path=$(dirname "${binWin32ReleasePath}")
    binPath=$(dirname "${binWin32Path}")
else
    binX64Path=$(dirname "${edgepath}")
    binPath=$(dirname "${binX64Path}")
fi
sgxSdkPath=$(dirname "${binPath}")

# -------------------------------------
# Configure OE Edger8r
# -------------------------------------

oeedgepath=`which oeedger8r`
if [ ! -z "$oeedgepath" ]; then
    export OEEDGER8R=$oeedgepath
    export OEPATHSEP=:
else
    oeedgepath=`which oeedger8r.exe`
    if [ ! -z "$oeedgepath" ]; then
        export OEEDGER8R=$oeedgepath
        export OEPATHSEP=;
    fi
fi
if [ -z "$oeedgepath" ]; then
   if [ -e oeedger8r ]; then
      oeedgepath=$PWD/oeedger8r
      export OEEDGER8R=$oeedgepath
      export OEPATHSEP=:
   fi
fi
if [ -z "$oeedgepath" ]; then
    wget https://oedownload.blob.core.windows.net/binaries/master/85/oeedger8r/build/output/bin/oeedger8r || exit 1
    chmod 755 oeedger8r
    export OEEDGER8R=$PWD/oeedger8r
    export OEPATHSEP=:
fi
echo Found $OEEDGER8R

# The linaro tools have problems with spaces in include paths,
# so create a link we can use without spaces.
if [ ! -e ../3rdparty/SGXSDK ]; then
    ln -s "${sgxSdkPath}" ../3rdparty/SGXSDK
fi
export SGX_RELATIVE_PATH=../3rdparty/SGXSDK/
export SGX_PATH=$PWD${SGX_RELATIVE_PATH}
export SGX_SDK=$PWD/../3rdparty/SGXSDK

PROC_COUNT=$(eval "cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l")

# -------------------------------------
# Build OP-TEE
# -------------------------------------

if [ -z "$TA_DEV_KIT_DIR" ]; then
    echo Building OP-TEE OS

    pushd ../3rdparty/optee_os/

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

    if [ $ARCH = "aarch32" ]; then
        if [ -z "$MACHINE" ] || [ "$MACHINE" = "virt" ]; then
            ARCH=arm make -j $PROC_COUNT PLATFORM=vexpress-qemu_virt \
                                        $OPTEE_VIRT_FLAGS            \
                                        $* || exit 1
            TA_DEV_KIT_PLAT=vexpress
        else
            echo FAILED: For AARCH32, MACHINE must be either "virt" or empty, which implies "virt".
            exit 1
        fi
    elif [ $ARCH = "aarch64" ]; then
        if [ -z "$MACHINE" ] || [ "$MACHINE" = "virt" ]; then
            ARCH=arm make -j $PROC_COUNT PLATFORM=vexpress-qemu_armv8a              \
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

    popd
    
    export TA_DEV_KIT_DIR=$PWD/../3rdparty/optee_os/out/arm-plat-$TA_DEV_KIT_PLAT/export-ta_arm$TA_DEV_KIT_BITS
fi

# -------------------------------------
# Build Open Enclave SDK
# -------------------------------------

echo Building Open Enclave SDK

make -j ${PROC_COUNT} $* || exit 1

# -------------------------------------
# Documentation
# -------------------------------------

echo Building Documentation

doxygen Doxyfile || exit 1
