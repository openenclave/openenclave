#!/usr/bin/env bash

# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

EMU_PATH=emulator
COLLECT_PATH=emu/vexpress-qemu_armv8a

mkdir -p $COLLECT_PATH

# Copy firmware, kernel, and root FS
cp $EMU_PATH/out/bin/* $COLLECT_PATH/

# Copy QEMU & its firmware
cp $EMU_PATH/qemu/aarch64-softmmu/qemu-system-aarch64 $COLLECT_PATH/
cp $EMU_PATH/qemu/pc-bios/efi-virtio.rom $COLLECT_PATH/

# Include tee.elf for OP-TEE OS symbols
cp $EMU_PATH/optee_os/out/arm/core/tee.elf $COLLECT_PATH/

# Include the OP-TEE OS devkit for reference
cp -r $EMU_PATH/optee_os/out/arm/export-ta_arm64 $COLLECT_PATH/devkit
