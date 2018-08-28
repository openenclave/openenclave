// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* Temporarily rename strerror() to __musl_strerror() */
#define strerror __musl_strerror
#include "../3rdparty/musl/musl/src/errno/strerror.c"
#undef strerror

/* Produce "Unknown error" which is expected by libcxx tests */
char* strerror(int errnum)
{
    char* msg = __musl_strerror(errnum);

    if (strcmp(msg, "No error information") == 0)
        return "Unknown error";

    return msg;
}
