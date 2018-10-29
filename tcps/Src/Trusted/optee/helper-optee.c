/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <errno.h>
#include <string.h>

errno_t memcpy_s( void * dst, size_t sizeInBytes, const void * src, size_t count )
{
    if (count == 0)
        return 0;

    if (dst == NULL)
       return EINVAL;

    if (src == NULL || sizeInBytes < count) {
        memset(dst, 0, sizeInBytes);

        if (src == NULL || sizeInBytes < count)
            return ERANGE;
    }

    memcpy(dst, src, count);
    return 0;
}

void
__assert(const char *file, int line, const char *func, const char *failedexpr)
{
    (void)(file);
    (void)(line);
    (void)(func);
    (void)(failedexpr);

    abort();
}

