// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/wchar.h>

size_t oe_wcslen(const wchar_t* s)
{
    const wchar_t* a;
    for (a = s; *s; s++)
        ;
    return (size_t)(s - a);
}
