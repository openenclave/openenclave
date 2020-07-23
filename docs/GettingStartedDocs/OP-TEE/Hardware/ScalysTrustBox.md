# Getting Started with Open Enclave for the Scalys TrustBox

The [TrustBox](https://scalys.com/trustbox-industrial) is an industrial router
manufactured by Scalys and serves as Open Enclave's reference hardware
implementation for ARM TrustZone. The TrustBox incorporates a
[Grapeboard](https://www.grapeboard.com), also produced by Scalys, which is in
turn based on the NXP Layerscape LS1012A SoC. The latter provides a hardware
root of trust as well as cryptographic and network acceleration.

In this guide, you will learn how to retrieve, build and flash the firmware for
the TrustBox. Further, you will see how to build and flash a root filesystem
containing an Ubuntu 18.04 user-mode installation onto an SD card. Lastly, you
will learn how to run OP-TEE's test suite as well as some of Open Enclave's
own tests on the TrustBox.

## Overview

The TrustBox internally contains a Grapeboard. The latter has a MicroSD card
reader from which the board can boot as well as a serial port offered over a
Micro-USB Type B connector (effectively, serial-over-USB). Flashing the firmware
requires connecting to the board over the serial connection while flashing the
MicroSD card requires opening the TrustBox, retrieving the Grapeboard inside and
either overwriting the MicroSD card it ships with with the root filesystem that
you will build in this guide, or replacing the MicroSD card with your own card
after you flash the latter with the required root filesystem.

### Caution

The Linux-based system that you will install to the TrustBox is configured to
ease testing. Additionally, the secure firmware, such as OP-TEE OS, is currently
meant for preview purposes only.

> **The resulting setup is not suitable for use in production and/or hostile
environments!**

### Prerequisites

- Ubuntu 18.04 LTS (64-bit)
- 1 TrustBox
- 1 Power supply
- 1 MicroSD card
  - Optional if the TrustBox you are using ships with one
- 1 T8 Torx screwdriver
- 1 Micro-USB Type B to USB Type A cable
- Wired network (Ethernet)
  - Optional

**Note:** The procedure below has not been validated on Ubuntu 16.04 LTS.

### Required Packages

The following command installs all the packages necessary on Ubuntu 18.04 LTS:

```bash
sudo apt update && sudo apt install -y android-tools-adb                       \
    android-tools-fastboot autoconf automake bc bison build-essential ccache   \
    cgdb cscope curl device-tree-compiler expect flex                          \
    ftp-upload gdb-multiarch gdisk iasl libattr1-dev libc6 libcap-dev          \
    libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev        \
    libpixman-1-dev libssl-dev libstdc++6 libtool libz1 make mtools netcat     \
    python-crypto python-pyelftools python-serial python-wand                  \
    python3-pyelftools repo unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev \
    flex bison python-pip libssl-dev build-essential gcc-aarch64-linux-gnu     \
    g++-aarch64-linux-gnu minicom u-boot-tools device-tree-compiler            \
    qemu-user-static udisks2
```

## Serial Communication

Connect the TrustBox to your computer via its serial-over-USB port. On a
computer running Ubuntu 18.04 LTS the TrustBox appears as a `ttyUSB#` device
node under `/dev`.

For example:

```bash
$ ll /dev/ttyUSB*

crw-rw---- 1 root dialout 188, 0 Oct 21 18:14 /dev/ttyUSB0
```

To establish a duplex serial connection, replace the device node with the one on
your system in the command below to invoke `minicom`:

```bash
sudo minicom -D /dev/ttyUSB0
```

Before the connection is usable, `minicom` must be configured to disable
hardware flow control.

Inside the `minicom` window, type:

```
<Ctrl-a> o
```

From the pop-up list, select "Serial port setup". In the new dialog, press `f`
to switch off Hardware Flow Control. Press `<Enter>` to confirm, then `<Esc>` to
dismiss the parent dialog. `minicom` should now be able to communicate with the
board.

Once you have finished this guide and are ready to exit `minicom`:

```
<Ctrl-a> q
```

When prompted if you would like to leave without reset, select `Yes`.

**Note:** You must turn off hardware flow control every time you connect anew.

## Source Code

All the code necessary to build the TrustBox's firmware and software, as well
as the requisite build scripts may be obtained from Open Enclave's fork of
NXP's Layerscape SDK (LSDK):

```bash
git clone --recursive https://github.com/ms-iot/lsdk -b ms-iot-openenclave-3.6.0 --depth=1
```

This operation will take some time as multiple submodules will be cloned, too.

## Firmware

In this subsection, you will build the firmware that contains the Secondary
Program Loader (SPL), U-Boot, OP-TEE OS, and the NXP Primary Protected
Application (PPA). You will then flash this firmware to your board.

### Building Firmware

To build the firmware, in the same folder where you cloned the LSDK repository,
type:

```bash
make firmware
```

If the board has HAB enabled, do instead:

```bash
make firmware HAB=1
```

**Note:** Do not attempt to use `-j`. The steps that are parallelizable will be
parallelized automatically.

The build will generate the following files:

- U-Boot
    - `build/u-boot-with-spl-pbl.bin`
- OP-TEE OS and NXP PPA
    - `build/ppa.itb`
- HAB Signature Data (if enabled)
  - build/hdr_spl.out

### Flashing Firmware

To flash the newly built firmware, place the files listed above in the root
directory of a FAT-formatted MicroSD card. Then, boot into recovery U-Boot as
follows:

1. Connect the Grapeboard to your computer;
2. Establish a `minicom` connection as outlined above;
3. Press and hold the push-button labelled `S2` on the board;
4. Power up the board, or, if already powered up, reset it by pressing and
releasing the push-button labelled `S1`.
5. Release the `S2` button when U-Boot prompts you to.

This should leave you at the recovery U-Boot prompt.

Flash the firmware by issuing the following commands:

```
# Update U-Boot
mmc rescan
fatload mmc 0:1 $load_addr u-boot-with-spl-pbl.bin
sf probe 0:0
sf erase u-boot 200000
sf write $load_addr u-boot $filesize

# Update OPTEE-OS + PPA
mmc rescan
fatload mmc 0:1 $load_addr ppa.itb
sf probe 0:0
sf erase ppa 100000
sf write $load_addr ppa $filesize

# Update CSF Header (only if HAB is enabled)
mmc rescan
fatload mmc 0:1 $load_addr hdr_spl.out
sf probe 0:0
sf erase u-boot_hdr 40000
sf write $load_addr u-boot_hdr $filesize
```

**Note:** Do not copy-paste more than one command at a time to the serial
console.

To reboot, type:

```
reset
```

Upon reboot, you should see messages similar to the following with HAB disabled:

```
U-Boot SPL 2018.09-g8947717e16 (Oct 21 2019 - 17:01:00 -0700)
PPA Firmware: Version LSDK-18.09
SEC Firmware: 'loadables' present in config
loadables: 'trustedOS@1'
can't get CSF - HAB disabled
SSM not in secure/trusted state: 0x9
Security state failure
Continuing with non-secret testing identity
I/TC:
I/TC: OP-TEE version: v0.4.0-1123-gd1634ce8 #1 Tue Oct 22 00:01:37 UTC 2019 aarch64
I/TC: Successfully captured Cyres certificate chain
I/TC: Successfully captured Cyres private key
I/TC: Initialized
Trying to boot from RAM
```

If HAB is enabled, the messages will instead look as follows:

```
U-Boot SPL 2018.09-00480-gdc28a9fa63-dirty (Jan 17 2019 - 11:17:15 -0800)
PPA Firmware: Version LSDK-18.09
SEC Firmware: 'loadables' present in config
loadables: 'trustedOS@1'
I/TC:
I/TC: OP-TEE version: v0.4.0-443-g9cdcf55b-dev #6 Sat Jan 26 05:59:52 UTC 2019 aarch64
I/TC: Successfully captured Cyres certificate chain
I/TC: Successfully captured Cyres private key
I/TC: Initialized
Trying to boot from RAM
```

### Recovery

If upon reset the board fails to boot, you can repeat the procedure to re-enter
recovery U-Boot to flash the firmware again. Flashing the firmware does not
overwrite the copy of U-Boot, which is part of the recovery ROM.

## Root File System

In this subsection, you will build a root filesystem comprised of Linux, Ubuntu
18.04 user-mode as well as the necessary libraries and supporting binaries to
communicate with OP-TEE OS. You will then flash the resulting filesystem onto
a MicroSD card.

### Building the Filesystem

In the same folder where you cloned the LSDK repository, do:

```bash
make os
```

**Note:** Do not attempt to use `-j` here either. The steps that are
parallelizable will be parallelized automatically.

### Flashing the Filesystem

Plug in the MicroSD card into your system, determine which block device node
corresponds to the MicroSD card, then issue the following command from within
the directory where you cloned the LSDK repository:

```bash
make sdcard DEV=/dev/sdX
```

When the script finishes, it is safe to remove the MicroSD card.

**Note:** You might observe an error related to copying an `Image` file. This is
expected if the MicroSD card is empty; copying this file is part of a backup
step. `make` is configured to ignore the error and continue.

### Booting the Filesystem

Insert the MicroSD card you just flashed into the TrustBox and power it up.
In the `minicom` window you should see Linux booting up.

The default login credentials are:

```
Username: root
Password: root
```

To log in over SSH, issue the `ifconfig` command to see your board's IP address,
if it is connected to a network.

## OP-TEE OS Test Suite

To ensure that the build of OP-TEE OS is sane, first start the TEE supplicant on
the board:

```bash
tee-supplicant &
```

You need only do this once per boot. Then, issue:

```
xtest
```

**Note:** `xtest` causes failures on purpose; do not be alarmed by the numerous
stack traces scrolling by.

Once `xtest` finishes, you should see the following output:

```
24078 subtests of which 1 failed
95 test cases of which 1 failed
0 test cases were skipped
TEE test application done!
```

The single failed test is a
[known issue](https://github.com/openenclave/openenclave/issues/2275).

## Open Enclave SDK

In this subsection, you will retrieve the Open Enclave SDK from source, set up
your build environment, then build the SDK to target the TrustBox. Additionally,
you will copy a test host and enclave to the TrustBox. Lastly, you will execute
these on the TrustBox.

### Building

To build the Open Enclave SDK for the TrustBox, issue the commands below, taking
care to replace the path indicated for `OE_TA_DEV_KIT_DIR` to point to the
output of the LSDK build as generated in the previous steps:

```bash
git clone --recursive https://github.com/openenclave/openenclave.git sdk

cd sdk

# Set up the build environment (only once).
sudo scripts/ansible/install-ansible.sh
sudo ansible-playbook scripts/ansible/oe-contributors-setup-cross-arm.yml

cd ..

mkdir build
cd build

# Configure the SDK
cmake ../sdk \
    -G Ninja \
	-DCMAKE_TOOLCHAIN_FILE=../sdk/cmake/arm-cross.cmake \
	-DOE_TA_DEV_KIT_DIR=$PWD/../lsdk/build/optee/export-ta_arm64 \
	-DCMAKE_BUILD_TYPE=Debug

# Build the SDK
ninja
```

### Copy Hosts & Enclaves

All OP-TEE OS enclaves are named `UUID.ta`, where `UUID` is a random UUID. These
must be placed on the board's filesystem under the `/lib/optee_armtz` folder.
Otherwise, enclaves will not load. The hosts may be located anywhere on the
filesystem.

For the purposes of this guide, the test host and enclave are the following two
binaries located in the SDK's `build` folder as created above:

```
tests/hexdump/host/hexdump_host
tests/hexdump/enc/126830b9-eb9f-412a-89a7-bcc8a517c12e.ta
```

To copy these, you can either:

1. Mount the MicroSD card on your Ubuntu 18.04 LTS machine and copy the files,
or;
2. Copy the files via SCP over the network.

An example for using SCP:

```bash
scp tests/hexdump/host/hexdump_host root@192.168.0.10:
scp tests/hexdump/enc/126830b9-eb9f-412a-89a7-bcc8a517c12e.ta root@192.168.0.10:/lib/optee_armtz
```

### Execution

To run the test, log into the TrustBox as `root`, either over serial or SSH, and
do:

```bash
cd ~

./hexdump_host 126830b9-eb9f-412a-89a7-bcc8a517c12e
```
