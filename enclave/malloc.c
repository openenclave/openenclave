#include <openenclave.h>
#include <oeinternal/globals.h>
#include <oeinternal/fault.h>

#define HAVE_MMAP 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_TYPES_H
#define LACKS_TIME_H
#define NO_MALLOC_STATS 1
#define MALLOC_FAILURE_ACTION
#define MORECORE sbrk
#define ABORT OE_Abort()
#define USE_DL_PREFIX
#define LACKS_STDLIB_H
#define LACKS_STRING_H
#define LACKS_ERRNO_H
#define size_t oe_size_t
#define ptrdiff_t oe_ptrdiff_t
#define memset OE_Memset
#define memcpy OE_Memcpy
#define sbrk OE_Sbrk
#define EINVAL 28
#define ENOMEM 49

void* OE_Sbrk(oe_ptrdiff_t increment);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#include "../3rdparty/dlmalloc/malloc.c"

OE_WEAK_ALIAS(dlmalloc, OE_Malloc);
OE_WEAK_ALIAS(dlcalloc, OE_Calloc);
OE_WEAK_ALIAS(dlrealloc, OE_Realloc);
OE_WEAK_ALIAS(dlfree, OE_Free);
OE_WEAK_ALIAS(dlmemalign, OE_Memalign);

#if 0
void *OE_Malloc(oe_size_t size)
{
    return dlmalloc(size);
}

void OE_Free(void *ptr)
{
    return dlfree(ptr);
}

void *OE_Calloc(oe_size_t nmemb, oe_size_t size)
{
    return dlcalloc(nmemb, size);
}

void *OE_Realloc(void *ptr, oe_size_t size)
{
    return dlrealloc(ptr, size);
}

void *OE_Memalign(oe_size_t alignment, oe_size_t size)
{
    return dlmemalign(alignment, size);
}
#endif
