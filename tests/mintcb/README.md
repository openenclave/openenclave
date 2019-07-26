mintcb
======

This test shows how to create a minimal-TCB enclave that only links
**liboecore** (thereby avoiding **liboeenclave** and its dependencies).

Ordinarily, the **_start** entry point is linked from **liboeenclave**. This
test provides its own **_start** entry point.
