/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openenclave/enclave.h>
#include "oeinternal_t.h"

#define FALSE 0

static int vprintf(const char *format, __va_list argptr)
{
    int s;
    char* buf = NULL;

    s = vsnprintf(NULL, 0, format, argptr);
    if (s < 0) {
        return s;
    }
    buf = (char*)malloc(s);
    if (buf == NULL) {
        return -1;
    }
    s = vsnprintf(buf, s, format, argptr);
    if (s < 0) {
        free(buf);
        return s;
    }

    oe_result_t host_result;
    oe_result_t result = ocall_puts(&host_result, buf, FALSE);
    free(buf);
    if (result != OE_OK) {
        return -1;
    }
    return (host_result != OE_OK) ? -1 : s;
}

int printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int result = vprintf(fmt, ap);
    va_end(ap);
    return result;
}
