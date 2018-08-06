// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DLMALLOC_ERRNO_H
#define _OE_DLMALLOC_ERRNO_H

#include <openenclave/enclave.h>
#include <openenclave/internal/sgxtypes.h>

#define EINVAL 22
#define ENOMEM 12

#define errno *__errno_location()

OE_INLINE int* __errno_location(void)
{
    TD* td = (TD*)oe_get_thread_data();
    oe_assert(td);
    return &td->linux_errno;
}

#endif /* _OE_DLMALLOC_ERRNO_H */
