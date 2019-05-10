mintcb
======

This test shows how to create a minimal-TCB enclave that only links
**liboecore** (thereby avoiding **liboeenclave** and its dependencies).

Ordinarily, the **_start** entry point is linke from **liboeenclave**. This
test, links this entry point defined in **liboestart**.
