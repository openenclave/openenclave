/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <string.h>
#include "tcps_t.h"
#include <TcpsCalls_t.h>

#define FALSE 0

static int vprintf(const char *format, __va_list argptr)
{
    int s;
    buffer1024 buf;

    memset(buf.buffer, 0, sizeof(buf.buffer));
    s = vsnprintf(buf.buffer, BUFSIZ, format, argptr);
    if (s < 0) {
        return s;
    }

    Tcps_StatusCode result;
    sgx_status_t status = ocall_puts(&result, buf, FALSE);
    if (status != SGX_SUCCESS) {
        return -1;
    }
    return Tcps_IsBad(result) ? -1 : s;
}

int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int result = vprintf(fmt, ap);
    va_end(ap);
    return result;
}
