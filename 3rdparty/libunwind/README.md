libunwind
=========

This directory contains a port of **libunwind** for enclaves. No **libunwind**
sources were changed. The **./libunwind** directory was copied intact from the 
following location.

```
https://github.com/pathscale/libunwind
```

The general porting approach is described as follows.

- Stub out functions unsupported for enclaves (see [stubs.h](stubs.h))

- Wrap **unw_step()** to verify that the cursor falls within enclave memory
  (see [libunwind-common.h](libunwind-common.h) and [Gstep.c](Gstep.c)).

- Provide a definition of **_Ux86_64_setcontext** that does not perform a
  system call (see [setcontext.S](setcontext.S))

- To fix multiple definition errors in clang-11 and later, _U_dyn_info_list is declared WEAK in src/x86_64/Ginit.c.
  This workaround is not needed in newer versions of libunwind.

This port also works with the newer libunwind version 1.3.

```
https://github.com/libunwind/libunwind
```
