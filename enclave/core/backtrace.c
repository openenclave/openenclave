// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/raise.h>

#define MAX_ADDRESSES 16

/* Return null if address is outside of the enclave; else return ptr. */
const void* _check_address(const void* ptr)
{
    if (!oe_is_within_enclave(ptr, sizeof(uint64_t)))
        return NULL;

    return ptr;
}

int oe_backtrace(void** buffer, int size)
{
    const void* addrs[MAX_ADDRESSES];
    int n = 0;
    int i;

    // It isn't possible to use iteration here since __builtin_return_address()
    // must take a constant argument. Also, the depth is limited to
    // MAX_ADDRESSES.
    do
    {
        if (!(addrs[n] = _check_address(__builtin_return_address(0))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(1))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(2))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(3))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(4))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(5))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(6))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(7))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(8))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(9))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(10))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(11))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(12))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(13))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(14))))
            break;

        if (!(addrs[++n] = _check_address(__builtin_return_address(15))))
            break;
    } while (0);

    /* If the caller's buffer is too small */
    if (n > size)
        n = size;

    /* Copy addresses to caller's buffer */
    if (buffer)
    {
        for (i = 0; i < n; i++)
            buffer[i] = (void*)addrs[i];
    }

    return n;
}
