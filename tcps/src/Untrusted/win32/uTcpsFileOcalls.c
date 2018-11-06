/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <string.h>
#include <direct.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include "oehost.h"
#include "../oeoverintelsgx_u.h"

stat64i32_Result
SGX_CDECL
ocall_stat64i32(
    oe_buffer256 path)
{
    stat64i32_Result result;
    Tcps_StatusCode uStatus = Tcps_Good;
    if (_stat64i32(path.buffer, (struct _stat64i32*)&result.buffer) != 0) {
        result.status = Tcps_Bad;
    }
    result.status = uStatus;
    return result;
}
