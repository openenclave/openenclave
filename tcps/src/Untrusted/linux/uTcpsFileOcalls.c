/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <openenclave/host.h>
#include "stdio_u.h"

int
ocall_stat64i32(
    const char* path,
    struct ocall_struct_stat64i32* buf64)
{
    struct stat buf;
    int result = stat(path, &buf);
    if (result != 0) {
        return result;
    }

    buf64->_st_dev = buf.st_dev;
    buf64->_st_ino = buf.st_ino;
    buf64->_st_mode = buf.st_mode;
    buf64->_st_nlink = buf.st_nlink;
    buf64->_st_uid = buf.st_uid;
    buf64->_st_gid = buf.st_gid;
    buf64->_st_rdev = buf.st_rdev;
    buf64->_st_size = buf.st_size;
    buf64->_st_atime = buf.st_atime;
    buf64->_st_mtime = buf.st_mtime;
    buf64->_st_ctime = buf.st_ctime;

    return result;
}
