[Index](index.md)

---
# OE_IsWithinEnclave()

Check whether the given buffer is strictly within the enclave.

## Syntax

    bool OE_IsWithinEnclave(
        const void *ptr,
        size_t size);
## Description 

Check whether the buffer given by the **ptr** and  parameters is strictly within the enclave's memory. If so, return true. If any portion of the buffer lies outside the enclave's memory, return false.

## Parameters

#### ptr

#### size

## Return value

#### true

#### false

---
[Index](index.md)

