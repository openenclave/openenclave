// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** The FUTEX system call is unsupported in OE so we replace the file-locking
** functions with versions that use OE recursive mutexes instead. Rather than
** using the stream->lock field, this implementation uses an array of recursive
** mutexes, which are assigned based on the address of the file stream
** structure. Collisions across file streams will occur in roughly 1 out of 256
** cases.
**
**==============================================================================
*/

#include <openenclave/internal/thread.h>

#include "stdio_impl.h"
/* Please do not remove this line: lock.h must be included after stdio_impl.h */
#include "lock.h"

#define MAX_LOCKS 256

static oe_mutex_t _locks[MAX_LOCKS];

static uint8_t _hash(FILE* stream)
{
    uint64_t x = (uint64_t)stream;
    const uint8_t* p = (const uint8_t*)&x;

    return p[0] ^ p[1] ^ p[2] ^ p[3] ^ p[4] ^ p[5] ^ p[6] ^ p[7];
}

int __lockfile(FILE* stream)
{
    size_t index = _hash(stream);
    oe_mutex_lock(&_locks[index]);

    /* A return value of 1 indicates that __unlockfile() must be called. */
    return 1;
}

void __unlockfile(FILE* stream)
{
    size_t index = _hash(stream);
    oe_mutex_unlock(&_locks[index]);
}
