Debugging OP-TEE TAs with QEMU
===============================

[QEMU](https://www.qemu.org/) is a system emulator that can run ARM TrustZone
Trusted Applications (TAs) on an x86/64 machine as though they were running on
TrustZone-capable hardware.

This SDK allows you to build host applications and TAs for simulation.
Simulation builds work by replacing the ECALL/OCALL mechanism such that they do
not occur via hardware mechanisms. This is useful for rapid development and
testing without requiring physical TEE-capable hardware. However, these
simulation builds do not attempt to replicate the complex behaviors observed
when TAs run on real devices. For example, if a host program attempts to access
memory inside a TA, which it must not be allowed to do, a simulation build will
not catch this. It is for this reason that QEMU is of great utility by providing
an emulated environment whose behavior matches real ARM TrustZone-capable
hardware without requiring any: secure memory access violations, alignment
errors, and the like, can be caught using QEMU.

In this guide, you will learn how to retrieve and build a QEMU environment for
debugging Open Enclave TAs on ARM TrustZone. Then, you will see how to build the
Open Enclave SDK samples and run them in the emulated environment. Lastly, you
will learn how to set up and use GDB for source-level debugging of the sample
TAs that ship with this SDK.

This guide is loosely based on [OP-TEE's own Build and Debug
Guide](https://github.com/OP-TEE/build#op-tee-buildgit) with some modifications
to render it more pertinent to this SDK.

# Prerequisites

This guide presumes you have a Ubuntu 18.04.1 LTS environment available. You may
install Ubuntu on bare-metal or in a virtual machine using your preferred
hypervisor. Some commands launch GUIs, so a graphical environment is necessary.

**Note:** To use this guide with the Windows Subsystem for Linux (WSL), read
through [Debugging OP-TEE TAs on WSL](ta_debugging_wsl.md) first.

## Required Packages

The following command installs all the packages necessary on Ubuntu 18.04.1 LTS:

```
sudo apt update && sudo apt install -y android-tools-adb \
    android-tools-fastboot autoconf automake bc bison build-essential \
    cscope curl device-tree-compiler expect flex ftp-upload gdisk iasl \
    libattr1-dev libc6 libcap-dev libfdt-dev libftdi-dev libglib2.0-dev \
    libhidapi-dev libncurses5-dev libpixman-1-dev libssl-dev libstdc++6 \
    libtool libz1 make mtools netcat python-crypto python-serial \
    python-wand unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev repo \
    gdb-multiarch cgdb
```

## Directory Structure

The instructions in this guide assume that:

* You have three terminals open;
* The current working directory on all three is your home directory to start
  with.

The terminals are referred to as `TERM 1`, `TERM 2` and `TERM 3`, respectively.
At the top of each command, the terminal to run them in is listed, unless
otherwise specified.

All work will be done in:

```
[ TERMS 1 & 2 & 3 ]

mkdir openenclave_qemu
cd openenclave_qemu
```

This is so that you may be able to easily run the commands listed here,
especially the ones that must be run inside the emulator.

# Getting Started

The runtime environment inside a QEMU virtual machine has the same software
requirements as real hardware. As such, firmware and a filesystem from which to
boot must be generated. This section shows you how to retrieve all the software
components required, how to build them, and how to run them in QEMU.

## Sources

The `repo` utility can manipulate multiple Git repositories as though they were
one. The following commands instruct `repo` to clone all the repositories that
are required to build a QEMU-based debugging environment:

```
[ TERM 1 ]

mkdir emulation
cd emulation

repo init -u https://github.com/ms-iot/optee_manifest -m oe_default.xml -b oe-3.2.0
repo sync
```

`repo sync` takes some time, seeing as it clones the Linux kernel, among other
things.

You may emulate an ARMv7 or an ARMv8 machine:

* For ARMv7, specify `oe_default.xml`;
* For ARMv8, specify `oe_qemu_v8.xml`.

**Note**: To clone multiple repositories in parallel, add the `-j` switch to the
`repo sync` command in the same way you would an invocation of `make`.

## Building

To create and launch a debugging environment all you need is `make`. Depending
on your machine, this may take upward of an hour the first time; subsequent runs
only take a few seconds, plus compiling anything that you may have changed:

```
[ TERM 1 ]

cd build

make toolchains -j2
make run
```

**Note**: Be sure to add the `-j` switch to decrease build time if you have the
cores to spare.

**Note**: `make toolchains` need only be called once, and since it downloads two
files, the `-j2` is already included.

Once this command is complete, it launches QEMU inside the same terminal as
where you executed `make run` along with two XTerm windows. In the terminal, you
can control QEMU via its monitor interface. For example, typing `c <Enter>`
resumes execution and `q <Enter>` quits QEMU.

The two XTerm windows are connected to one emulated serial port each: one shows
output from the Normal World (the REE, or untrusted side) and the other shows
output from the Secure World (the TEE, or trusted side). The Normal World XTerm
window allows you to interact with the emulated Linux environment through a
BusyBox shell.

By default, the emulated processor is halted when QEMU starts. To ensure that
the build is sane, resume execution by issuing the `c <Enter>` command in the
QEMU monitor (`c` is short for "continue").

In the Secure World XTerm window you should see OP-TEE's initialization output.
In the Normal World XTerm window you should see Linux boot. Try logging into
Linux in the Normal World XTerm window once it is done booting (see the output
in XTerm on how to log in).

## Emulator Setup

To debug Open Enclave TAs on ARM TrustZone, you must build host applications and
TAs for the same architecture and against the same OP-TEE TA Dev kit as what
runs in the emulator. Then, you must copy your TAs into it.

### Building Hosts & TAs

To build host applications and TAs in a manner compatible with the emulated
environment, you need to:

* Clone the Open Enclave SDK;
* Set `ARCH` according to the manifest you picked above:
    * `oe_default.xml` = ARMv7, so ARCH => `aarch32`;
    * `oe_qemu_v8.xml` = ARMv8, so ARCH => `aarch64`.
* Set `MACHINE` to `virt`;
* Set `TA_DEV_KIT_DIR` to the absolute path where the TA Dev Kit was placed by
  `make run` previously.

Here's a complete example for ARMv7:

```
[ TERM 2 ]

wget https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/sgx_linux_x64_sdk_2.3.101.46683.bin

chmod +x ./sgx_linux_x64_sdk_2.3.101.46683.bin
sudo ./sgx_linux_x64_sdk_2.3.101.46683.bin

git clone --recurse-submodules https://github.com/Microsoft/openenclave -b feature.new_platforms emu_v7
cd emu_v7

export ARCH=aarch32
export MACHINE=virt
export TA_DEV_KIT_DIR=$HOME/openenclave_qemu/emulation/optee_os/out/arm/export-ta_arm32

./new_platforms/build_optee.sh
```

And here's the same for ARMv8:

```
[ TERM 2 ]

wget https://download.01.org/intel-sgx/linux-2.3.1/ubuntu18.04/sgx_linux_x64_sdk_2.3.101.46683.bin

chmod +x ./sgx_linux_x64_sdk_2.3.101.46683.bin
sudo ./sgx_linux_x64_sdk_2.3.101.46683.bin

git clone --recurse-submodules https://github.com/Microsoft/openenclave -b feature.new_platforms emu_v8
cd emu_v8

export ARCH=aarch64
export MACHINE=virt
export TA_DEV_KIT_DIR=$HOME/openenclave_qemu/emulation/optee_os/out/arm/export-ta_arm64

./new_platforms/build_optee.sh
```

### Copying TAs

To debug Open Enclave TAs on ARM TrustZone, the TA binaries must be present
inside the emulator. A simple way to achieve this is using QEMU's built-in
host-guest file sharing capabilities.

By default, the `make run` instructs QEMU to share your home directory read-only
into the emulated guest. Once the guest boots and you have logged in via the
Normal World XTerm window, type:

```
mkdir /mnt/home
mount -t 9p -o trans=virtio sh0 /mnt/home -oversion=9p2000.L

cd /mnt/home
```

`sh0` is the name of the share as specified in QEMU's command line by `make
run`.

For example, if you were trying to debug the SDK test suite on ARMv7, you would
do the following on the Normal World XTerm window:


```
cp /mnt/home/openenclave_qemu/emu_v7/new_platforms/scripts/build/arm/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.ta /lib/optee_armtz
/mnt/home/openenclave_qemu/emu_v7/new_platforms/scripts/build/arm/out/bin/oetests_host
```

For ARMv8:

```
cp /mnt/home/openenclave_qemu/emu_v8/new_platforms/scripts/build/aarch64/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.ta /lib/optee_armtz
/mnt/home/openenclave_qemu/emu_v8/new_platforms/scripts/build/aarch64/out/bin/oetests_host
```

Notice how it is not necessary to copy the host application into the emulator,
it can run directly from the share. The TA, however, must be inside.

**Note**: QEMU environments built with this tooling automatically start
`tee-supplicant` for you on boot.

# Debugging

QEMU exposes a GDB server on `localhost:1234` with system-wide visibility into
the emulated environment. After starting QEMU with `make run`, start the
architecture-aware version of GDB.

For ARMv7:

```
[ TERM 2 ]

gdb-multiarch

target remote localhost:1234
symbol-file ./emu_v7/new_platforms/scripts/build/arm/out/bin/oetests_host

b main
c
```

And ARMv8:

```
[ TERM 2 ]

gdb-multiarch

target remote localhost:1234
symbol-file ./emu_v8/new_platforms/scripts/build/aarch64/out/bin/oetests_host

b main
c
```

This command sequence connects GDB to QEMU, loads the symbols from
`oetests_host`, sets a breakpoint on the `main` function and resumes execution.
If you then run `oetests_host` inside the emulator, it will break on `main`.

## Loading TA symbols

Instructing GDB to load symbols for a TA requires some work the first time.

After launching QEMU, copying the sample TA into it and launching the
corresponding host application, OP-TEE prints lines similar to the following in
the Secure World XTerm window:

```
D/TC:? 0 tee_ta_init_pseudo_ta_session:273 Lookup pseudo TA 3156152a-19d1-423c-96ea-5adf5675798f
D/TC:? 0 load_elf:908 Lookup user TA ELF 3156152a-19d1-423c-96ea-5adf5675798f (Secure Storage TA)
D/TC:? 0 load_elf:908 Lookup user TA ELF 3156152a-19d1-423c-96ea-5adf5675798f (REE)
D/TC:? 0 load_elf_from_store:867 ELF load address 0x40005000
D/TC:? 0 tee_ta_init_user_ta_session:1095 Processing relocations in 3156152a-19d1-423c-96ea-5adf5675798f
```

The fourth line indicates where in secure virtual memory OP-TEE has loaded the
TA. In this case it's `0x40005000`. This value should remain the same throughout
repeated runs as well as across reboots of the emulator. Note this value.

Due to how OP-TEE loads TAs, you must manually line up the symbols in the ELF
file produced for TAs with how the code is laid out in memory:

For ARMv7:

```
[ TERM 3 ]

cd $HOME/openenclave_qemu

./emulation/toolchains/aarch32/bin/arm-linux-gnueabihf-objdump -x \
    ./emu_v7/new_platforms/scripts/build/arm/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.elf | less
```
And ARMv8:

```
[ TERM 3 ]

cd $HOME/openenclave_qemu

./emulation/toolchains/aarch64/bin/aarch64-linux-gnu-objdump -x \
    ./emu_v8/new_platforms/scripts/build/aarch64/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.elf | less
```

In the `Sections` table, you will see output like this:

```
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .ta_head      00000020  0000000000000000  0000000000000000  00010000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
  1 .text         00014ad0  0000000000000020  0000000000000020  00010020  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  2 .rodata       00001dd4  0000000000014af0  0000000000014af0  00024af0  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .gnu.hash     0000001c  00000000000168c8  00000000000168c8  000268c8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
```

Take note of the `LMA` (Load Memory Address) of the `.text` section.

Add the value you noted before from OP-TEE's output to the value of `LMA` for
the `.text` section. In this case:

```
0x40005000 + 0x20 = 0x40005020
```

Switch back to `TERM 2` where GDB is running and type, for ARMv7:

```
<CTRL-c>
add-symbol-file ./emu_v7/new_platforms/scripts/build/arm/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.elf 0x109020
```

And ARMv8:

```
<CTRL-c>
add-symbol-file ./emu_v8/new_platforms/scripts/build/aarch64/out/bin/3156152a-19d1-423c-96ea-5adf5675798f.elf 0x40005020
```

**Note:** The different addresses in the command samples are intentional, the
load address changes depending on the architecture, but it is calculated in the
same way.

From this point forward, even if you rebuild TAs, the load address for the
symbols should remain the same, so you do not need to go through of all this
every time you want to debug. Just execute the `add-symbol-file` command in GDB.
However, should your breakpoints stop being hit, do verify that these addresses
have not changed, especially after a `git pull` and a rebuild.

There is a known issue, either in GDB or QEMU, where once OP-TEE and Linux have
fully booted up, it is not possible to place breakpoints inside TAs. To work
around this, switch to `TERM 1` where QEMU is running and type:

```
system_reset
```

On `TERM 2` where GDB is running:

```
b ecall_RunClient
b ecall_StartServer
c
```

When you run the `oetests_host` host application and the ECALL is performed,
there will be two breaks:

* One in the host application just prior to the transition into the TA, and;
* One in the TA just prior to executing the ECALL functionality proper.

This duplication is due to the fact that there exist functions with the same
name in the host application and in the TA.

**Note**: Resetting QEMU means that emulator state is cleared, hence you must
repeat the steps of mounting your home directory inside the emulator and copying
the TA to `/lib/optee_armtz`. Any breakpoints you set in GDB, however, persist
across `system_reset`.

## Source-Level Debugging

GDB by default offers a command-line interface. To see source code, registers,
and more, you can use any GUI that can use GDB as a back-end. Some of these are:

* GDB in TUI mode
* CGDB
* Visual Studio
* Eclipse
* DDD

This guide shows you how to use the first two. Instructions on how to set up
Visual Studio are coming soon.

### GDB TUI

GDB's Text User Interface, or TUI, can be accessed from within the GDB
command-line interface. Once GDB is started and you are at the GDB command
prompt:

```
[ TERM 2 ]

<CTRL-x> a
```

This splits the GDB window in two horizontal panes: the top one shows source
code and the bottom one hosts the usual GDB command-line interface.

You can switch between different layouts using the `layout <name>` command,
where `<name>` can be any of:

* `asm`
* `regs`
* `src`
* `split`

You can also use `layout next` to cycle through all available layouts.

GDB is a powerful debugger with great documentation available
[here](https://sourceware.org/gdb/current/onlinedocs/gdb/).

### CGDB

CGDB is a terminal utility that wraps GDB and provides syntax highlighting as
well as a simpler way to browse through source code.

When started without arguments, CGDB uses the default GDB debugger on the
system. However, to debug an ARM or AARCH64 target from an x86/64 host, CGDB
must be told to use the same version of GDB used above. To start CGDB specifying
a particular version of GDB, issue the following command from a terminal:

```
cgdb -d gdb-multiarch
```

CGDB looks like the first layout in the GDB TUI, but with colors by default.
Unlike the GDB TUI, however, you may switch focus from the bottom pane to the
top pane with the `ESC` key. To move back, press the `i` key. When the top pane
is in focus, you can navigate through source code using Vim-style commands. The
GDB command-line pane behaves in the same way as the regular GDB command-line
interface.

CGDB sports a wide array of commands, be sure to read through its
[documentation](https://cgdb.github.io/docs/cgdb.html).

**Note:** CGDB does not currently support multiple layouts and issuing the
`layout` command corrupts the screen. The only split available is source + GDB
command-line.

Finally, to exit GDB, or CGDB:

```
q <Enter>
```
