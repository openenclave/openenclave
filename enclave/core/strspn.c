// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>

size_t oe_strspn(const char* s, const char* accept)
{
    const char* p = s;

    while (*p)
    {
        if (!oe_strchr(accept, *p))
            break;
        p++;
    }

    return (size_t)(p - s);
}
