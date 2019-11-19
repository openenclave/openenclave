host
====

This directory contains the sources for the oehost library. This library
supports creating, invoking, and terminating enclaves.

# Enclave Layout

The host creates an enclave image with the following layout (for details, see
see [create.c](create.c)).

        +----------------------------------------+
        | Text pages:                            |
        |     _start() - enclave entry point     |
        |     oe_exit() - enclave entry routine  |
        +----------------------------------------+
        | Relocation pages:                      |
        |     (contains data relocations)        |
        +----------------------------------------+
        | ECALL address pages:                   |
        {     (ECALL virtual adddresses)         |
        +----------------------------------------+
        | Data pages:                            |
        |     __oe_numPages                      |
        |     __oe_virtualBaseAddr               |
        |     __oe_BaseRelocPage                 |
        |     __oe_numRelocPages                 |
        |     __oe_BaseECallPage                 |
        |     __oe_numECallPages                 |
        |     __oe_BaseHeapPage                  |
        |     __oe_numHeapPages                  |
        +----------------------------------------+ <--+
        | Guard page                             |    |
        +----------------------------------------+    |
        | Stack pages                            |    |
        +----------------------------------------+    |
        | Guard page                             |    |
        +----------------------------------------+    |
        | Thread Control Structure (TCS) Page    |    |
        |     state: 0 = available               |    |
        |     oentry - vaddress of _start()      |    |- Thread context
        |     fsbase - vaddress of FS segment    |    |  (one per TCS)
        |     gsbase - vaddress of GS segment    |    |
        +----------------------------------------+    |
        | Set Asside Area (SSA Slot 1) Page      |    |
        +----------------------------------------+    |
        | Set Asside Area (SSA Slot 2) Page      |    |
        +----------------------------------------+    |
        | Guard page                             |    |
        +----------------------------------------+    |
        | Thread local storage                   |    |
        +----------------------------------------+    |
        | Segment Page: (FS)                     |    |
        | (contains thread data structure        |    |
        | and Thread specific data (TSD))        |    |
        +----------------------------------------+ <--+
        | Padding Pages (must be a power of two) |
        +----------------------------------------+
The thread data (td) object is always populated at the start of the
FS segment, thus FS segment regiter points to td.

The existing Windows SGX enclave debugger finds the start of the thread data
by assuming that it is located at the start of the GS segment. i.e. it adds the
enclave base address and the offset to the GS segment stored in TCS.OGSBASGX.
OE SDK uses the FS segment for this purpose and has no separate use for the
GS register, so we point it at the FS segment to preserve the Windows debugger
behavior.
