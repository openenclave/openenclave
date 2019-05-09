// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safemath.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/reserve.h>

int oe_reserve(
    void** array,
    size_t size,
    size_t elem_size,
    size_t* capacity,
    size_t new_capacity)
{
    int ret = -1;

    if (!array || !capacity || size > *capacity)
        goto done;

    if (!array && size != 0)
        goto done;

    if (new_capacity > *capacity)
    {
        void* p;
        size_t n;

        /* Set n to the greater of new_capacity and size*2 */
        {
            size_t mul;

            if (oe_safe_mul_sizet(size, 2, &mul) != OE_OK)
                return -1;

            n = (mul > new_capacity) ? mul : new_capacity;
        }

        /* Reallocate the block. */
        if (!(p = oe_realloc(*array, n * elem_size)))
            goto done;

        /* Zero-fill the unused porition. */
        memset((uint8_t*)p + (size * elem_size), 0, (n - size) * elem_size);

        /* Update the in-out parameters. */
        *array = p;
        *capacity = n;
    }

    ret = 0;

done:

    return ret;
}
