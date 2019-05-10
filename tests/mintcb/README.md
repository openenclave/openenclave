mintcb
======

This test shows how to create a minimal-TCB enclave that only links
**liboecore** (thereby avoiding **liboeenclave** and its dependencies).

Ordinarily, the default entry point is **_start**, which is defined in
**liboeenclave**. This test sets the entry point to **oe_enter**. On Linux,
this is done with the following linker option:

```
-Wl,-e,oe_enter
```
