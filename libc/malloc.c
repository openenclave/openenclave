#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/fault.h>

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
#define size_t size_t
#define ptrdiff_t ptrdiff_t
#define memset OE_Memset
#define memcpy OE_Memcpy
#define sbrk OE_Sbrk
#define EINVAL 28
#define ENOMEM 49

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#include "../3rdparty/dlmalloc/malloc.c"

OE_WEAK_ALIAS(dlmalloc, malloc);
OE_WEAK_ALIAS(dlcalloc, calloc);
OE_WEAK_ALIAS(dlrealloc, realloc);
OE_WEAK_ALIAS(dlfree, free);
OE_WEAK_ALIAS(dlmemalign, memalign);
OE_WEAK_ALIAS(dlposix_memalign, posix_memalign);
