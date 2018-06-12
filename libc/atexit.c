// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/atexit.h>
#include <stdlib.h>

/*
**==============================================================================
**
** atexit()
**
**     Enclave implementation of the libc atexit function.
**
**==============================================================================
*/

int atexit(void (*function)(void))
{
    return OE_AtExit(function);
}
