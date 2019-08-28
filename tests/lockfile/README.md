lockfile test
=============

Tests that multiple threads can perform simultaneous writes on the STDOUT
device. The host creates multiple threads that call into the enclave, which
iterates while writing to STDOUT. Writes are performed with **cout** which is
a wrapper around the the C stdout file stream.
