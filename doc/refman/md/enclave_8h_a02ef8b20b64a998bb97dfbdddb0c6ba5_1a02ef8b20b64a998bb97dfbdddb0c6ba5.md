# OE_IsWithinEnclave()

Check whether the given buffer is strictly within the enclave.

## Syntax

    OE_IsWithinEnclave(
        const void * ptr,
        size_t size);
## Description 

Check whether the buffer given by the **ptr** and **size** parameters is strictly within the enclave's memory. If so, return true. If any portion of the buffer lies outside the enclave's memory, return false.



## Parameters

### The

ptr pointer to buffer.

### The

size size of buffer

## Return value

### true

The buffer is strictly within the enclave.

### false

At least some part of the buffer is outside the enclave.

