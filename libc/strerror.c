// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>

char* strerror(int errnum)
{
    return oe_strerror(errnum);
}

int strerror_r(int errnum, char* buf, size_t buflen)
{
    return oe_strerror_r(errnum, buf, buflen);
}
