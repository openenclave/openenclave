# Debugging Enclaves on OP-TEE OS with QEMU

[QEMU](https://www.qemu.org/) is a system emulator that can run ARM TrustZone
enclaves on an x86/64 machine as though they were running on TrustZone-capable
hardware. QEMU provides an emulated environment whose behavior matches real ARM
TrustZone-capable hardware without requiring any: secure memory access
violations, alignment errors, and the like, can be caught using QEMU.

In this guide, you will learn how to retrieve and build a QEMU environment for
debugging enclaves on ARM TrustZone. Then, you will see how to build the Open
Enclave SDK samples and run them in the emulated environment. Lastly, you will
learn how to set up and use GDB for source-level debugging of the sample
enclaves that ship with this SDK.

This guide is loosely based on [OP-TEE's own Build and Debug
Guide](https://optee.readthedocs.io/en/latest/building/index.html) with some
modifications to render it more pertinent to this SDK.

## Prerequisites

This guide presumes you have a Ubuntu 18.04 LTS environment available. You may
install Ubuntu on bare metal or in a virtual machine using your preferred
hypervisor. Some commands launch GUIs, so a graphical environment is necessary.

**Note:** To use this guide with the Windows Subsystem for Linux (WSL), read
through [Debugging Enclaves on OP-TEE OS with QEMU on WSL](QEMUOnWSL.md)
first.

## Required Packages

The following command installs all the packages necessary on Ubuntu 18.04 LTS:

```bash
sudo apt update && sudo apt install -y android-tools-adb                       \
    android-tools-fastboot autoconf automake bc bison build-essential ccache   \
    cgdb cscope curl device-tree-compiler expect flex ftp-upload gdb-multiarch \
    gdisk iasl libattr1-dev libc6 libcap-dev libfdt-dev libftdi-dev            \
    libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev libssl-dev    \
    libstdc++6 libtool libz1 make mtools netcat python-crypto                  \
    python-pyelftools python-serial python-wand python3-pyelftools repo unzip  \
    uuid-dev xdg-utils xterm xz-utils zlib1g-dev
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

```bash
# [ TERMS 1 & 2 & 3 ]

# Once
mkdir openenclave_qemu

# All terms
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

```bash
# [ TERM 1 ]

mkdir emulation
cd emulation

repo init -u https://github.com/ms-iot/optee_manifest -m oe_qemu_v8.xml -b oe-3.6.0
repo sync
```

`repo sync` takes some time, seeing as it clones the Linux kernel, among other
things. To clone multiple repositories in parallel, add the `-j` switch to the
`repo sync` command in the same way you would an invocation of `make`.

## Building

To create and launch a debugging environment all you need is `make`. Depending
on your machine, this may take upward of an hour the first time; subsequent runs
only take a few seconds, plus compiling anything that you may have changed:

```bash
# [ TERM 1 ]

cd build

make toolchains -j2
make run -j$(nproc)
```

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

To debug enclaves on ARM TrustZone, you must build host applications and
enclaves. Then, you must copy your enclaves into it.

### Building Hosts & Enclaves

```bash
# [ TERM 2 ]

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
	-DOE_TA_DEV_KIT_DIR=$PWD/../emulation/optee_os/out/arm/export-ta_arm64 \
	-DCMAKE_BUILD_TYPE=Debug

# Build the SDK
ninja

cd ..
```

For more information regarding these steps, see the [Getting Started with Open
Enclave for OP-TEE OS](../../../GettingStartedDocs/Contributors/OPTEEGettingStarted.md).

### Copying Enclaves

To debug enclaves on OP-TEE OS, the enclave binaries must be present inside the
emulator. A simple way to achieve this is using QEMU's built-in host-guest file
sharing capabilities.

By default, `make run` instructs QEMU to share your home directory read-only
into the emulated guest. Once the guest boots and you have logged in via the
Normal World XTerm window, type:

```bash
mkdir /mnt/home
mount -t 9p -o trans=virtio sh0 /mnt/home -oversion=9p2000.L

cd /mnt/home
```

`sh0` is the name of the share as specified in QEMU's command line by `make
run`.

For example, if you were trying to debug the SDK's test suite, you would do the
following on the Normal World XTerm window:

```bash
cp openenclave_qemu/build/tests/hexdump/enc/126830b9-eb9f-412a-89a7-bcc8a517c12e.ta /lib/optee_armtz
openenclave_qemu/build/tests/hexdump/host/hexdump_host 126830b9-eb9f-412a-89a7-bcc8a517c12e
```

Notice how it is not necessary to copy the host application into the emulator,
it can run directly from the share. The enclave, however, must be inside.

**Note**: QEMU environments built with this tooling automatically start
`tee-supplicant` on boot, unlike on some platforms where it might be necessary
to start it manually.

# Debugging

QEMU exposes a GDB server on `localhost:1234` with system-wide visibility into
the emulated environment. After starting QEMU with `make run`, start the
architecture-aware version of GDB.

```bash
# [ TERM 2 ]

gdb-multiarch

target remote localhost:1234
symbol-file ./build/tests/hexdump/host/hexdump_host

b main
c
```

This command sequence connects GDB to QEMU, loads the symbols from
`oetests_host`, sets a breakpoint on the `main` function and resumes execution.
If you then run `oetests_host` inside the emulator, it will break on `main`.

**Note:** Breakpoints on the host will not be hit if the latter is built as a
position-independent executable, which hosts are by default. This is because GDB
places breakpoints at virtual address offsets from the load address of the
executable. However, a position-independent executable may be loaded anywhere
within its virtual address space. It is possible to modify the host to print its
load address on each start, then line up the symbols with GDB correctly. For
debugging purposes, consider turning position-independent code generation off
temporarily.

## Loading Enclave Symbols

Instructing GDB to load symbols for an enclave requires some work the first
time.

After launching QEMU, copying the sample enclave into it and launching the
corresponding host application, OP-TEE prints lines similar to the following in
the Secure World XTerm window:

```
D/TC:? 0 system_open_ta_binary:286 Lookup user TA ELF 126830b9-eb9f-412a-89a7-bcc8a517c12e (Secure Storage TA)
D/TC:? 0 system_open_ta_binary:289 res=0xffff0008
D/TC:? 0 system_open_ta_binary:286 Lookup user TA ELF 126830b9-eb9f-412a-89a7-bcc8a517c12e (REE [buffered])
D/TC:? 0 system_open_ta_binary:289 res=0x0
D/LD:  ldelf:150 ELF (126830b9-eb9f-412a-89a7-bcc8a517c12e) at 0x40010000
```

The fifth line indicates where in secure virtual memory OP-TEE has loaded the
enclave. In this case it's `0x40010000`. This value should remain the same
throughout repeated runs as well as across reboots of the emulator. Note this
value.

Due to how OP-TEE loads enclaves, you must manually line up the symbols in the
ELF file produced for enclaves with how the code is laid out in memory:

```bash
#[ TERM 3 ]

cd $HOME/openenclave_qemu

./emulation/toolchains/aarch64/bin/aarch64-linux-gnu-objdump -x \
    ./build/tests/hexdump/enc/126830b9-eb9f-412a-89a7-bcc8a517c12e.elf | less
```

In the `Sections` table, you will see output like this:

```
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .ta_head      00000020  0000000000000000  0000000000000000  00001000  2**12
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  1 .text         0007d9a8  0000000000000020  0000000000000020  00001020  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  2 .eh_frame     0000bcd0  000000000007d9c8  000000000007d9c8  0007e9c8  2**3
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  3 .rodata       00009cb5  00000000000896a0  00000000000896a0  0008a6a0  2**4
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
```

Take note of the `LMA` (Load Memory Address) of the `.text` section.

Add the value you noted before from OP-TEE's output to the value of `LMA` for
the `.text` section. In this case:

```
0x40010000 + 0x20 = 0x40010020
```

Switch back to `TERM 2` where GDB is running and type:

```
<CTRL-c>
add-symbol-file ./build/tests/hexdump/enc/126830b9-eb9f-412a-89a7-bcc8a517c12e.elf 0x40010020
```

From this point forward, even if you rebuild enclaves, the load address for the
symbols should remain the same, so you do not need to go through of all this
every time you want to debug. Just execute the `add-symbol-file` command in GDB.
However, should your breakpoints stop being hit, do verify that these addresses
have not changed, especially after a `git pull` and a rebuild.

There is a [known
issue](https://github.com/openenclave/openenclave/issues/2276), either in GDB or
QEMU, where once OP-TEE and Linux have fully booted up, it is not possible to
place breakpoints inside enclaves. To work around this, switch to `TERM 1` where
QEMU is running and type:

```
system_reset
```

On `TERM 2` where GDB is running:

```
b test
c
```

When you run the `hexdump_host` host application and the ECALL is performed,
there will be two breaks (assuming the host was built with position-independent
code off):

* One in the host application just prior to the transition into the enclave,
and;
* One in the enclave at the ECALL.

This duplication is due to the fact that there exist functions with the same
name in the host application and in the enclave.

**Note**: Resetting QEMU means that emulator state is cleared, hence you must
repeat the steps of mounting your home directory inside the emulator and copying
the enclave to `/lib/optee_armtz`. Any breakpoints you set in GDB, however,
persist across `system_reset`.

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

```bash
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
