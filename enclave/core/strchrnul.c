// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>

char* oe_strchrnul(const char* s, int c)
{
    char* p;

    if (!(p = oe_strchr(s, c)))
        p = (char*)(s + oe_strlen(s));

    return p;
}
