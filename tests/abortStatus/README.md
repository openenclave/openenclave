abortStatus tests
============

This directory runs enclave abort status tests.

# Following scenarios are tested

* Host gets the abort status when enclave call oe_abort to abort itself.
* Host gets the abort status when un-handled hardware exception happens inside 
enclave.
* Enclave is aborted in one thread, other active enclave threads can return to 
host with correct abort status, and both enclave thread and host thread can exit
gracefully.
* Same case as scenario 3, but the enclave is aborted due to an un-handled
hardware exception.
