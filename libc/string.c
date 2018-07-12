// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <locale.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <stdlib.h>
#include <string.h>

int strcoll(const char* s1, const char* s2)
{
    return strcmp(s1, s2);
}

int strcoll_l(const char* s1, const char* s2, locale_t loc)
{
    return strcoll(s1, s2);
}

size_t strxfrm(char* dest, const char* src, size_t n)
{
    strncpy(dest, src, n);
    return n;
}

char* strdup(const char* s)
{
    return oe_strdup(s);
}

size_t strxfrm_l(char* dest, const char* src, size_t n, locale_t loc)
{
    return strxfrm(dest, src, n);
}
