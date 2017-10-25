#ifndef _OE_MALLOC_H
#define _OE_MALLOC_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

typedef struct _OE_MallocStats
{
    size_t heapSize;
    size_t heapUsed;
    size_t heapAvailable;
    double heapUsage;
    size_t freeListSize;
    size_t numMallocs;
    size_t numFrees;
}
OE_MallocStats;

void OE_GetMallocStats(OE_MallocStats* stats);

int OE_InitMalloc(void* base, size_t size);

void* OE_Malloc(size_t size);

void* OE_Memalign(size_t size, size_t alignment);

void* OE_Realloc(void* ptr, size_t size);

void* OE_Calloc(size_t nmemb, size_t size);

void OE_Free(void* ptr);

typedef void (*OE_AllocationFailureCallback)(
    const char* file, 
    size_t line, 
    const char* func, 
    size_t size);

void OE_SetAllocationFailureCallback(
    OE_AllocationFailureCallback function);

OE_EXTERNC_END

#endif /* _OE_MALLOC_H */
