#!/bin/bash

# -------------------------------------
# Environment Configuration
# -------------------------------------

# Instruct build_optee.sh to build for an AARCH64 QEMU guest.
export ARCH=aarch64
export MACHINE=virt

# -------------------------------------
# Build the Open Enclave SDK
# -------------------------------------

echo [CI] Building Open Enclave

chmod +x ./new_platforms/build_optee.sh
./new_platforms/build_optee.sh || exit 1

# -------------------------------------
# Install CI Prerequisites
# -------------------------------------

echo [CI] Installing Prerequisites

# Needed to log in via SSH with password on the command line.
sudo apt install sshpass -y || exit 1

# -------------------------------------
# Download Test Environment
# -------------------------------------

echo [CI] Downloading Emulated Environment

CI_DIR=ci
CI_ENV=OE-CI-Ubuntu-16.04-AARCH64

# The tarball contains QEMU, a root FS and guest firmware (i.e. ATF, OP-TEE,
# etc.).
if [ ! -d $CI_DIR ]; then
    if [ ! -f $CI_ENV.tar.xz ]; then
        wget https://tcpsbuild.blob.core.windows.net/tcsp-build/$CI_ENV.tar.xz || exit 1
    fi
    tar xvf $CI_ENV.tar.xz --no-same-owner || exit 1
fi

# -------------------------------------
# Launch Test Environment
# -------------------------------------

echo [CI] Launching QEMU

cd $CI_DIR
nohup ./qemu-system-aarch64 \
        -nographic \
        -serial file:ree.log -serial file:tee.log \
        -smp 1 \
        -machine virt,secure=on -cpu cortex-a57 \
        -m 1057 \
        -bios bl1.bin \
        -semihosting-config enable,target=native \
        -d unimp \
        -initrd rootfs.cpio.gz \
        -kernel Image \
        -no-acpi \
        -append 'console=ttyAMA0,38400 keep_bootcon root=/dev/vda2' \
        -netdev user,id=net0,hostfwd=tcp::5555-:22 -device virtio-net,netdev=net0 \
        -virtfs local,id=sh0,path=$PWD/..,security_model=passthrough,readonly,mount_tag=sh0 &
disown

# -------------------------------------
# Connect to Test Environment
# -------------------------------------

echo [CI] Connecting to QEMU Guest

# Ensure .ssh exists.
mkdir $HOME/.ssh

# Retrieve guest SSH keys.
ssh-keyscan -T 300 -p 5555 localhost >> $HOME/.ssh/known_hosts

echo [CI] Running Test Suite in QEMU Guest

# Launch the test suite in the guest.
CMD="su -c \""
CMD="$CMD mkdir /mnt/oe &&"
CMD="$CMD mount -t 9p -o trans=virtio sh0 /mnt/oe -oversion=9p2000.L &&"
CMD="$CMD cp /mnt/oe/new_platforms/bin/optee/tests/3156152a-19d1-423c-96ea-5adf5675798f.ta /lib/optee_armtz &&"
if [ -z "$TESTS_NOT_TO_RUN" ]; then
    CMD="$CMD /mnt/oe/new_platforms/tests/oetests_host/oetests_host"
else
    CMD="$CMD /mnt/oe/new_platforms/tests/oetests_host/oetests_host --gtest_filter=-$TESTS_NOT_TO_RUN"
fi
CMD="$CMD \""

sshpass -p test ssh test@localhost -p 5555 "$CMD"

# If either SSH failed, or the command sent to the guest failed, which is
# propagated, terminate QEMU and exit with a non-zero exit code.
if [ $? -ne 0 ]; then
    # The process name is truncated.
    pkill -9 qemu-system-aar

    exit 1
fi

# -------------------------------------
# Epilogue
# -------------------------------------

echo [CI] Stopping QEMU

# See previous invocation.
pkill -9 qemu-system-aar
