// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/rdrand.h>

// The RDRAND generates 8-byte random value.
#define RDRAND_BYTES 8

oe_result_t oe_random_internal(void* data, size_t size)
{
    for (size_t i = 0; i < size; i += RDRAND_BYTES)
    {
        size_t request_size = size - i;
        if (request_size > RDRAND_BYTES)
        {
            request_size = RDRAND_BYTES;
        }
        uint64_t random_bytes = oe_rdrand();
        memcpy((void*)((uint8_t*)data + i), (void*)&random_bytes, request_size);
    }

    return OE_OK;
}
