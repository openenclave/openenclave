liboeposix:
===========

This directory contains the source for **liboeposix**, which routes POSIX
requests to devices (e.g., file systems, socket layers). Clients of this
library submit POSIX requests in two ways:

- By calling **oe_syscall()**, which handles software system calls.
  This method is used by **libc**.

- By calling the function for that request directly. Examples include
  **oe_open()**, **oe_socket()**, and **oe_select()**.

So far, **liboeposix** handles requests on the following categories.

- files
- directories
- sockets
- polling
