liboesyscall
============

This directory contains the source for **liboesyscall**, which routes
syscalls to devices (e.g., file systems, socket layers). Clients of this
library submit SYSCALL requests in two ways:

- By calling **oe_syscall()**, which handles software system calls (used
  by **libc**).

- By calling request functions directly. Examples include **oe_open()**,
  **oe_socket()**, and **oe_select()**.

So far, **liboesyscall** handles requests on the following kinds of objects.

- files
- directories
- sockets
- events (poll and select)

Devices are implemented as separate static libraries. See the implementations
in the [devices](./devices) directory for
more information.
