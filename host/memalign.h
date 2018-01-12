#ifndef _OE_HOST_MEMALIGN_H
#define _OE_HOST_MEMALIGN_H

#include <stddef.h>

void *Memalign(size_t alignment, size_t size);

void MemalignFree(void* ptr);

#endif /* _OE_HOST_MEMALIGN_H */
