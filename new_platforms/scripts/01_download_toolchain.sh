# -------------------------------------
# Download ARM Toolchains
# -------------------------------------

# Create directory for toolchains.
if [ ! -d toolchains ]; then
    mkdir toolchains
fi
pushd toolchains

# Download the toolchains.
GCC_DIR_ARM=arm-linux-gnueabihf
GCC_DIR_AARCH64=aarch64-linux-gnu

GCC_ARM=gcc-linaro-6.2.1-2016.11-x86_64_arm-linux-gnueabihf
GCC_AARCH64=gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu

# ARM toolchain first.
if [ ! -f $GCC_ARM.tar.xz ]; then
    wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/$GCC_DIR_ARM/$GCC_ARM.tar.xz || exit 1

    # Extract.
    if [ ! -d arm ]; then
        mkdir arm
        
        pushd arm
        tar --strip-components=1 -xvf ../$GCC_ARM.tar.xz || exit 1
        popd  # arm
    fi    
fi

# AARCH64 toolchain second.
if [ ! -f $GCC_AARCH64.tar.xz ]; then
    wget https://releases.linaro.org/components/toolchain/binaries/6.2-2016.11/$GCC_DIR_AARCH64/$GCC_AARCH64.tar.xz || exit 1

    # Extract.
    if [ ! -d aarch64 ]; then
        mkdir aarch64

        pushd aarch64
        tar --strip-components=1 -xvf ../$GCC_AARCH64.tar.xz || exit 1
        popd  # aarch64
    fi
fi

popd  # toolchains
