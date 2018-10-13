#!/bin/bash

echo Installing build essentials

sudo apt-get update
sudo apt-get -y install build-essential

echo Installing arm toolchain

GCCPREFIX=gcc-linaro-4.9.4-2017.01-x86_64_arm-linux-gnueabi

if [ ! -d $GCCPREFIX ]; then
    if [ ! -f $GCCPREFIX.tar.xz ]; then
        wget https://releases.linaro.org/components/toolchain/binaries/4.9-2017.01/arm-linux-gnueabi/$GCCPREFIX.tar.xz
    fi
    tar xvf $GCCPREFIX.tar.xz
fi

echo Installing prerequisites

sudo apt-get -y install android-tools-adb android-tools-fastboot autoconf automake bc bison build-essential cscope curl device-tree-compiler flex ftp-upload gdisk iasl libattr1-dev libcap-dev libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev libssl-dev libtool make mtools netcat python-crypto python-serial python-wand unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev gcc-arm-linux-gnueabi

echo Checking for Intel SGX SDK

# Test whether Intel SGX SDK is installed.  If not, but the
# IntelSGXSDKInstallerURI environment variable is set,
# then fetch it from there, else tell the user to go get it.
# This provides a mechanism usable by github-CI.
if [ -e External/SGXSDK/bin/x64/sgx_edger8r ]; then
    export PATH="$PATH:$PWD/External/SGXSDK/bin/x64"
fi
edgepath=`which sgx_edger8r`
if [ -z "$edgepath" ]; then
    edgepath=`which sgx_edger8r.exe`
fi
if [ -z "$edgepath" ]; then
    if [ ! -e External/SGXSDK ]; then
       if [ -n "${IntelSGXSDKInstallerURI}" ]; then
           wget ${IntelSGXSDKInstallerURI}
       fi
       if [ -e SGXSDK.zip ]; then
           unzip SGXSDK.zip -d External
       fi
    fi
    if [ -e External/SGXSDK ]; then
        export PATH="$PATH:$PWD/External/SGXSDK/bin/x64"
	chmod 755 $PWD/External/SGXSDK/bin/x64/sgx_edger8r
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
export SGX_PATH=${sgxSdkPath}/

# The linaro tools have problems with spaces in include paths,
# so create a link we can use without spaces.
if [ ! -e External/SGXSDK ]; then
    ln -s "${sgxSdkPath}" External/SGXSDK
fi

echo Building OPTEE OS

pushd External/optee_os/

export CROSS_COMPILE=../../$GCCPREFIX/bin/arm-linux-gnueabi-
export ARCH=arm

# TODO: change imx-mx6qmbbedge to imx-mx6qgeneric below once we find a branch
# that supports both it and PTA_CYREP_GET_CERT_CHAIN_SIZE
make PLATFORM=imx-mx6qhmbedge CFG_PSCI_ARM32=y CFG_RPMB_FS=y CFG_REE_FS=n CFG_RPMB_TESTKEY=y CFG_RPMB_WRITE_KEY=n CFG_RPMB_RESET_FAT=n CFG_WITH_USER_TA=y CFG_PAGED_USER_TA=n CFG_WITH_PAGER=n CFG_CRYPTO_SIZE_OPTIMIZATION=y platform-cflags-optimization=-Os CFG_UNWIND=n CFG_TEE_CORE_DEBUG=y CFG_BOOT_SECONDARY_REQUEST=y CFG_NS_ENTRY_ADDR=0x10820000 CFG_TEE_TA_LOG_LEVEL=4 CFG_TEE_CORE_LOG_LEVEL=2 CFG_TZ_SPI_CONTROLLERS=0x2 CFG_TA_RPC=y CFG_CONSOLE_UART=UART3_BASE

popd

echo Building TCPS-SDK

export CROSS_COMPILE=/usr/bin/arm-linux-gnueabi-
export TA_DEV_KIT_DIR=$PWD/External/optee_os/out/arm-plat-imx/export-ta_arm32

make -C Src/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug $*

make -C Samples/EchoSockets/Trusted/optee -f linux_gcc.mak BUILD_TARGET=debug $*

make -C Samples/OEHelloWorld/HelloWorldEnc/optee -f linux_gcc.mak BUILD_TARGET=debug $*

make -C Tests/TcpsSdkTestTA/optee -f linux_gcc.mak BUILD_TARGET=debug $*
