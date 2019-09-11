EDL security and portability enhancements
=========================================

Motivation
----------

This document proposes EDL enhancements that will:

- Improve portability to TrustZone
- Mitigate security vulnerabilities

This feature is needed by TrustZone to ensure that applications developed with
EDL will work on TrustZone platforms. Currently the use of host shared memory
is problematic for TrustZone, which utilizes a different shared memory model.
SGX *implicitly* shares *all* host memory with the enclave, whereas, TrustZone
*explicitly* shares *some* host memory with the enclave. Therefore we
distinguish two models.

- **Implicit-all** -- implicitly shares all host memory (SGX)
- **Explicit-some** -- explicitly shares some host memory (TrustZone)

In TrustZone, developers may explicitly share designated memory regions. It
is not possible to share all host memory (stack, data, heap, etc.) as it is
in SGX.

The feature is also needed to protect developers from security vulnerabilities
caused by coding errors. Of particular concern are two scenarios:

1. Trusted code may unwittingly write secrets onto host memory.

2. Attackers may pass pointers to trusted memory where the trusted
   code expects to write to host memory, forcing trusted memory overwrites.

To prevent these kinds of errors, the stub routines must perform full
serialization and deserialization across the trust boundary so that:

- ECALL function parameters fall entirely within trusted memory.
- OCALL function parameters fall entirely within untrusted memory.

Most importantly, it should not be possible to *implicitly* pass untrusted
memory to an ECALL function implementation. The stub routines must copy
all untrusted memory to trusted memory buffers prior to dispatching the
ECALL.

There are currently three ways that EDL *implicitly* transfers untrusted memory.

1. Through ECALLs utilizing foreign structures, which may contain pointers to
   untrusted memory.

2. Through ECALLs utilizing local structures, which are not sufficiently
   annotated for deep copy.

3. Through OCALLs that return pointers.

All three of these subtly expose untrusted memory to the enclave developer.

To mitigate all three of these, the **edger8r** tool should impose three
constraints *by default*.

1. Reject foreign structures.
2. Reject under-annotated local structures.
3. Reject pointer return values.

There may be other cases, but the general rule is that all memory must be
copied to the trusted domain (ECALLs) or the untrusted domain (OCALLs). This
implies that the layout of all structures is known to the **edger8r**.

The above should be the default behavior of the **edger8r**. Options may be
added for relaxing one or more of these constraints.

User Experience
---------------

The user will run the **edger8r**, which will now run in a stricter mode by
default. At first this may break when unsafe EDL specifications are
encountered. The user must either address these errors or use an option to
ignore them. But even when these are ignored, the **edger8r** should still
print warnings.

However inconvenient this may seem, remember that it is aimed at mitigating
security flaws and promoting portability to TrustZone (and other future
platforms).

Specification
-------------

The design is straightforward; print error diagnostics when encountering:

1. Foreign structures.
2. Under-annotated local structures.
3. Pointer return values.

Also provide an option to turn off this checking for backwards compatibility.

Alternates
----------

We also considered alternative interface definition languages (IDL) such as
Google protobufs and other RPC-based systems. Any of these would provide
strong protections, but we opted for improving EDL for now. These other systems
could be offered later as an alternative.

Further, programming languages that support reflection might make generation
of edge routines much simpler by eliminating the need for an IDL specification.

Authors
-------

mikbras@microsoft.com
