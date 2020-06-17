// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_MEMALIGN_H
#define _OE_HOST_MEMALIGN_H

#include <stddef.h>

void* oe_memalign(size_t alignment, size_t size);

void oe_memalign_free(void* ptr);

#endif /* _OE_HOST_MEMALIGN_H */
