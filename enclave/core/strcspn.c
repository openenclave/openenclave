// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>

size_t oe_strcspn(const char* s, const char* reject)
{
    const char* p = s;

    while (*p)
    {
        if (oe_strchr(reject, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}
