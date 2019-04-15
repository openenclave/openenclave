ptraceLib
====

This directory contains the sources for the oe_ptrace library. The oe_ptrace
library implements the customized ptrace and waitpid function to get and set
enclave registers, and fix the enclave breakpoint.

It will be preloaded into the GDB by oegdb script.
