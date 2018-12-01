/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <stddef.h>

#ifdef LINUX
#include "sal_unsup.h"
#endif

#include <openenclave/host.h>
#include "oeinternal_u.h"

/* I/O related APIs */

oe_result_t ocall_puts(_In_z_ char* str, int bNewline)
{
    uint32_t error;

    if (bNewline) {
        error = (puts(str) >= 0);
    } else {
        error = (fputs(str, stdout) >= 0);
    }

    if (error) {
        return OE_FAILURE;
    }

    return OE_OK;
}
