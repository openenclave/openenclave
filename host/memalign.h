// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_MEMALIGN_H
#define _OE_HOST_MEMALIGN_H

#include <stddef.h>

void* oe_memalign(size_t alignment, size_t size);

void oe_memalign_free(void* ptr);

#endif /* _OE_HOST_MEMALIGN_H */
