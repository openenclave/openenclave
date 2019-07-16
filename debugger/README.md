debugger
====

This directory contains the sources for the debugger runtime, sgx_ptrace library
and Python extension.

- **debugrt** is the debugger runtime that implements the contract between the
  Open Enclave runtime and debuggers. The contract allows the debuggers to
  enumerate, introspect and debug enclaves that have been built with debugging
  support.
- **ptraceLib** is the `oe_ptrace` library which implements the customized ptrace
  function to debug SGX enclave.
- **pythonExtension** is a GDB extension written in Python that adds support for
  debugging enclaves, stitching host and enclave stacks for ecalls and ocalls,
  attaching to a running enclave host and other debugging functionality.
