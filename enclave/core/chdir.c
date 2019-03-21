// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/bits/devids.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/corelibc/unistd.h>

char __oe_cwd[OE_PATH_MAX] = "/";

int oe_chdir(const char* path)
{
    char real_path[OE_PATH_MAX];
    struct oe_stat st;

    if (!oe_realpath(path, real_path))
        return -1;

    if (oe_stat(real_path, &st) != 0 || !OE_S_ISDIR(st.st_mode))
        return -1;

    oe_strlcpy(__oe_cwd, real_path, OE_PATH_MAX);
    return 0;
}
