#!/bin/bash
cd "$( dirname "${BASH_SOURCE[0]}" )"

echo Installing build essentials

sudo apt-get update
sudo apt-get -y install build-essential

echo Installing arm toolchain

GCCPREFIX=gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf

if [ ! -d $GCCPREFIX ]; then
    if [ ! -f $GCCPREFIX.tar.xz ]; then
        wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/arm-linux-gnueabihf/$GCCPREFIX.tar.xz
    fi
    tar xvf $GCCPREFIX.tar.xz
fi

echo Installing prerequisites

sudo apt-get -y install android-tools-adb android-tools-fastboot autoconf automake bc bison build-essential cscope curl device-tree-compiler doxygen flex ftp-upload gdisk iasl libattr1-dev libcap-dev libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev libssl-dev libtool make mtools netcat python-crypto python-serial python-wand unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev gcc-arm-linux-gnueabi

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
           wget ${IntelSGXSDKInstallerURI}
       fi
       if [ -e SGXSDK.zip ]; then
           unzip SGXSDK.zip -d ../3rdparty
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

# Next, install oeedger8r
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
    wget https://oedownload.blob.core.windows.net/binaries/master/85/oeedger8r/build/output/bin/oeedger8r
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

export CROSS_COMPILE=$PWD/$GCCPREFIX/bin/arm-linux-gnueabihf-
export PROC_COUNT=$(eval "cat /proc/cpuinfo | awk '/^processor/{print $3}' | wc -l")

echo Building OP-TEE OS

pushd ../3rdparty/optee_os/

export ARCH=arm

# TODO: change imx-mx6qmbbedge to imx-mx6qgeneric below once we find a branch
# that supports both it and PTA_CYREP_GET_CERT_CHAIN_SIZE
make -j ${PROC_COUNT} PLATFORM=imx-mx6qhmbedge CFG_PSCI_ARM32=y CFG_RPMB_FS=y CFG_REE_FS=n \
                      CFG_RPMB_TESTKEY=y CFG_RPMB_WRITE_KEY=n CFG_RPMB_RESET_FAT=n CFG_WITH_USER_TA=y \
                      CFG_PAGED_USER_TA=n CFG_WITH_PAGER=n CFG_CRYPTO_SIZE_OPTIMIZATION=y \
                      platform-cflags-optimization=-Os CFG_UNWIND=n CFG_TEE_CORE_DEBUG=y \
                      CFG_BOOT_SECONDARY_REQUEST=y CFG_NS_ENTRY_ADDR=0x10820000 CFG_TEE_TA_LOG_LEVEL=4 \
                      CFG_TEE_CORE_LOG_LEVEL=2 CFG_TZ_SPI_CONTROLLERS=0x2 CFG_TA_RPC=y \
                      CFG_CONSOLE_UART=UART3_BASE

popd

echo Building TCPS-SDK

export TA_DEV_KIT_DIR=$PWD/../3rdparty/optee_os/out/arm-plat-imx/export-ta_arm32
export ARCH=aarch32

make -j ${PROC_COUNT}

export CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-
export ARCH=arm

make -j ${PROC_COUNT} -C samples/sockets/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug $*
make -j ${PROC_COUNT} -C samples/helloworld/HelloWorldEnc/optee -f linux_gcc.mak BUILD_TARGET=debug $*

doxygen Doxyfile
