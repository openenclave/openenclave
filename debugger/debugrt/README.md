debugrt
====

This directory contains the host and enclave side debugger runtimes.

The host side debugger runtime is built as an object library on Linux.
On Windows, it is built as a separate DLL: oedebugrt.dll.
debugrt implements the binary contract used by the debugger to introspect
and debug enclaves.
It contains the following
- a global, export linked list of enclaves.
- data types used by the SDK to describe enclaves which act as the binary
  contract for the debugger.
- functions to be called by a host application to notify the debugger about
  enclave creation, enclave termination, thread creation (future), thread
  deletion (future).
- On Linux, debugger listens to notifications by putting breakpoints in
  specific functions.
- On Windows, debugger listens to RaiseException events raised by the runtime.

The enclave side runtime consists of
- function to detect whether debugger has been attached or not.
- raise C++ exception thrown event to the debugger.

Note:
Enclave side does not make ocalls to communicate with the debugger. Doing so
will cause extract entries in the stack for ocall. Instead it uses int 3
preceeded by a known pattern of bytes to raise a debug event that the
debugger understands to be a special message by scanning the pattern preceeding
the int 3.
