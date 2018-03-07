// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_MALLOC_H
#define _OE_MALLOC_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

typedef void (*OE_AllocationFailureCallback)(
    const char* file,
    size_t line,
    const char* func,
    size_t size);

void OE_SetAllocationFailureCallback(OE_AllocationFailureCallback function);

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
