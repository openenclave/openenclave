#ifndef _OE_MALLOC_H
#define _OE_MALLOC_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_MallocStats
{
    oe_size_t heapSize;
    oe_size_t heapUsed;
    oe_size_t heapAvailable;
    double heapUsage;
    oe_size_t freeListSize;
    oe_size_t numMallocs;
    oe_size_t numFrees;
}
OE_MallocStats;

void OE_GetMallocStats(OE_MallocStats* stats);

int OE_InitMalloc(void* base, oe_size_t size);

void* OE_Malloc(oe_size_t size);

void* OE_Memalign(oe_size_t size, oe_size_t alignment);

void* OE_Realloc(void* ptr, oe_size_t size);

void* OE_Calloc(oe_size_t nmemb, oe_size_t size);

void OE_Free(void* ptr);

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
