/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>
#include "oeoverintelsgx_u.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "sal_unsup.h"
#include <openenclave/host.h>

stat64i32_Result
SGX_CDECL
ocall_stat64i32(
    oe_buffer256 path)
{
    stat64i32_Result result = { 0 };

    struct stat buf;
    if (stat(path.buffer, &buf) != 0) {
        result.status = OE_FAILURE;
        return result;
    }

    result.buffer._st_dev = buf.st_dev;
    result.buffer._st_ino = buf.st_ino;
    result.buffer._st_mode = buf.st_mode;
    result.buffer._st_nlink = buf.st_nlink;
    result.buffer._st_uid = buf.st_uid;
    result.buffer._st_gid = buf.st_gid;
    result.buffer._st_rdev = buf.st_rdev;
    result.buffer._st_size = buf.st_size;
    result.buffer._st_atime = buf.st_atime;
    result.buffer._st_mtime = buf.st_mtime;
    result.buffer._st_ctime = buf.st_ctime;

    result.status = OE_OK;
    return result;
}
