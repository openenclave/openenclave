/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdio.h>
#include <string.h>
#include <direct.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <openenclave/host.h>
#include "stdio_u.h"

int
ocall_stat64i32(
    const char* path,
    struct ocall_struct_stat64i32* buf)
{
    return _stat64i32(path, (struct _stat64i32*)buf);
}
