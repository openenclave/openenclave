[Index](index.md)

---
# oe_host_free()

Releases allocated memory.

## Syntax

    void oe_host_free(void *ptr)
## Description 

This function releases memory allocated with [oe_host_malloc()](enclave_8h_a10b3ff4164db3852c41fa431950bebb3_1a10b3ff4164db3852c41fa431950bebb3.md) or [oe_host_calloc()](enclave_8h_a4a6f218a37d256fdda8e5912f40c9dd9_1a4a6f218a37d256fdda8e5912f40c9dd9.md) by performing an OCALL where the host calls free().



## Parameters

#### ptr

Pointer to memory to be released or null.

---
[Index](index.md)

