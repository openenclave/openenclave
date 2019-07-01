debugger
====

This directory contains the sources for the debugger runtime, sgx_ptrace library
and Python extension. Debugger runtime (debugrt) implements the infrastructure
used by the SDK to allow the debugger to support enclave introspection and
debugging. The oe_ptrace library implements the customized ptrace function to
debug sgx enclave. The Python extension is a GDB extension to enable enclave
debugging and stack stitching etc.
