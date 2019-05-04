liboeposix:
===========

This directory contains the source for **liboeposix**, which routes POSIX
requests to devices (e.g., file systems, socket layers). Clients of this
library submit POSIX requests in two ways:

- By calling **oe_syscall()**, which handles software system calls (used
  by **libc**).

- By calling request functions directly. Examples include **oe_open()**,
  **oe_socket()**, and **oe_select()**.

So far, **liboeposix** handles requests on the following kinds of objects.

- files
- directories
- sockets
- events

Devices are implemented as separate static libraries. See the implementations
in the [devices](https://github.com/Microsoft/openenclave/posix/devices) for
more informations.
