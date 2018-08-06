// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DLMALLOC_ERRNO_H
#define _OE_DLMALLOC_ERRNO_H

#define EINVAL 22
#define ENOMEM 12

int* __oe_errno_location(void);

#define errno *__oe_errno_location()

#endif /* _OE_DLMALLOC_ERRNO_H */
