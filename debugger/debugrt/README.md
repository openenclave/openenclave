debugrt
====

debugrt provides the following as part of the debugger contract:

- Exports a global linked-list of enclaves in the current host process.
- Implements the binary data contract for describing enclave debug information.
- Implements functions invoked by the Open Enclave host library to notify the
  debugger of the following events:
-- Enclave creation
-- Enclave termination
-- Thread creation (not yet implemented)
-- Thread deletion (not yet implemented)

debugrt has implementation differences depending on the host platform:

- On Linux, debugrt is an object library linked directly into the Open Enclave
  host library. A Linux debugger hooks into event notifications by injecting
  internal breakpoints into the notification functions and handling the resulting
  interrupts.
- On Windows, debugrt is a DLL loaded at runtime. A Windows debugger hooks into
  event notifications by handling exceptions raised by the enclave runtime via
  RaiseException() as part of the notification functions.

Note:
To avoid modifying the enclave stack when communicating with the debugger, the
enclave runtime generates an interrupt with the `INT3` instruction instead of
making an ocall to the host. The `INT3` invocation is preceeded by a well-known
pattern of bytes as defined in the debugger contract, and the debugger is
expected to scanfor this pattern when handling the interrupt.
