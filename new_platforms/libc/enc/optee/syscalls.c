// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// #include <openenclave/enclave.h>
// #include <openenclave/internal/syscall.h>
#include <stdarg.h>

/* Intercept __syscalls() from MUSL */
long __syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    (void)(n);
    (void)(x1);
    (void)(x2);
    (void)(x3);
    (void)(x4);
    (void)(x5);
    (void)(x6);
    return 0;
}

/* Intercept __syscalls_cp() from MUSL */
long __syscall_cp(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    return __syscall(n, x1, x2, x3, x4, x5, x6);
}

long syscall(long number, ...)
{
    va_list ap;

    va_start(ap, number);
    long x1 = va_arg(ap, long);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    long ret = __syscall(number, x1, x2, x3, x4, x5, x6);
    va_end(ap);

    return ret;
}
