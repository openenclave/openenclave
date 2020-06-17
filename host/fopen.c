// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "fopen.h"
#include <errno.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>

int oe_fopen(FILE** fp, const char* path, const char* mode)
{
#if defined(__linux__)

    if (!fp)
        return -1;

    if ((*fp = fopen(path, mode)) == NULL)
    {
        OE_TRACE_ERROR("oe_fopen failed path=%s mode=%s\n", path, mode);
        return -1;
    }

    return 0;

#elif defined(_MSC_VER)

    if (fopen_s(fp, path, mode) != 0)
        return -1;

    return 0;

#endif
}
