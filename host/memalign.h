#ifndef _OE_HOST_MEMALIGN_H
#define _OE_HOST_MEMALIGN_H

#include <stddef.h>

void* OE_Memalign(size_t alignment, size_t size);

void OE_MemalignFree(void* ptr);

#endif /* _OE_HOST_MEMALIGN_H */
