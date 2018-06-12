// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "fopen.h"
#include <errno.h>
#include <stdio.h>

int OE_Fopen(FILE** fp, const char* path, const char* mode)
{
#if defined(__linux__)

    if (!fp)
        return -1;

    if ((*fp = fopen(path, mode)) == NULL)
        return -1;

    return 0;

#elif defined(_MSC_VER)

    if (fopen_s(fp, path, mode) != 0)
        return -1;

    return 0;

#endif
}
