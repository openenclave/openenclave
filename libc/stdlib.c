// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <locale.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>

long long int strtoll_l(const char* nptr, char** endptr, int base, locale_t loc)
{
    OE_UNUSED(loc);
    return strtoll(nptr, endptr, base);
}

unsigned long long strtoull_l(
    const char* nptr,
    char** endptr,
    int base,
    locale_t loc)
{
    OE_UNUSED(loc);
    return strtoull(nptr, endptr, base);
}
