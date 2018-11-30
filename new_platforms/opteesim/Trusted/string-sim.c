/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
/* Licensed under the MIT License. */
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
typedef size_t ssize_t;
#define _SSIZE_T_DEFINED_
typedef unsigned short wchar_t;
#define _NO_CRT_STDIO_INLINE
#include <strsafe.h>

_Check_return_
size_t __cdecl strlen(
    _In_z_ char const* _Str)
{
    const char* end;
    for (end = _Str; *end; end++);
    return end - _Str;
}

_Check_return_
char* __cdecl strchr(
    _In_z_ char const* _Str,
    _In_   int         _Val)
{
    const char* p;
    for (p = _Str; *p; p++) {
        if (*p == _Val) {
            return (char*)p;
        }
    }
    return NULL;
}

_Check_return_
int __cdecl strcmp(
    _In_z_ char const* a,
    _In_z_ char const* b)
{
    for (;;) {
        if (*a == *b) {
            if (*a == 0) {
                return 0;
            }
            a++;
            b++;
            continue;
        }
        return *a - *b;
    }
}

_Check_return_
int __cdecl strcasecmp(
    _In_z_ char const* a,
    _In_z_ char const* b)
{
    return _stricmp(a, b);
}

_Check_return_
int __cdecl strncasecmp(
    _In_z_ char const* a,
    _In_z_ char const* b,
    _In_ size_t n)
{
    return _strnicmp(a, b, n);
}

int oe_snprintf(
    char *buffer,
    _In_ size_t count,
    _In_z_ const char *format,
    ...)
{
    int result;
    va_list vargs;
    va_start(vargs, format);
    result = vsnprintf(buffer, count, format, vargs);
    va_end(vargs);
    return result;
}

#undef printf
int oe_printf(
    _In_z_ const char *format,
    ...)
{
    int result;
    va_list vargs;
    va_start(vargs, format);
    result = vprintf(format, vargs);
    va_end(vargs);
    return result;
}

/*
 * Include some tracing code from OP-TEE.
 */

#define TRACE_LEVEL 1
#define MAX_PRINT_SIZE      256
const char trace_ext_prefix[] = "TA";
#define CFG_MSG_LONG_PREFIX_MASK 0x1a
int trace_level = TRACE_LEVEL;

typedef long long intmax_t;
typedef unsigned long long uintmax_t;
#include <openenclave/enclave.h>
#define __ILP32__ 1
#include "../../../3rdparty/optee_os/lib/libutils/ext/trace.c"
#pragma warning( disable : 4146 )
#include "../../../3rdparty/optee_os/lib/libutils/ext/snprintk.c"

int trace_ext_get_thread_id(void)
{
    return -1;
}

#undef printf
void trace_ext_puts(_In_z_ const char *str)
{
    printf("%s", str);
}

void utee_log(_In_ const void *buf, _In_ size_t len)
{
}
