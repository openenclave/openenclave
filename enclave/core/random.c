// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/random.h>

oe_result_t oe_random(void* data, size_t size)
{
    /* For now just call oe_random_internal.  In the future, this should
     * return a cryptographically random set of bytes.
     */
    return oe_random_internal(data, size);
}
