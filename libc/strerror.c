// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/enclave.h>

typedef struct _error_info
{
    int errnum;
    const char* message;
} error_info_t;

static error_info_t _errors[] = {
#define E(errno, message) {errno, message},
#include "../3rdparty/musl/musl/src/errno/__strerror.h"
};

static size_t _num_errors = sizeof(_errors) / sizeof(_errors[0]);

char* strerror_l(int errnum, locale_t loc)
{
    OE_UNUSED(loc);
    for (size_t i = 0; i < _num_errors; i++)
    {
        if (errnum == _errors[i].errnum)
            return (char*)_errors[i].message;
    }

    return (char*)"Unknown error";
}

char* strerror(int errnum)
{
    return strerror_l(errnum, 0);
}
