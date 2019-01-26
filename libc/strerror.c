// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/elibc/string.h>
#include <openenclave/enclave.h>
#include "locale_impl.h"

char* strerror_l(int errnum, locale_t loc)
{
    OE_UNUSED(loc);
    oe_assert(loc == C_LOCALE);
    return oe_strerror(errnum);
}

char* strerror(int errnum)
{
    return oe_strerror(errnum);
}
