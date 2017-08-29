#define USE_OE_MALLOC
//#define USE_DLMALLOC

/*
**==============================================================================
**
** ENC-Malloc:
**
**==============================================================================
*/

#ifdef USE_OE_MALLOC
# define OE_MEMALIGN memalign
# define OE_MALLOC malloc
# define OE_CALLOC calloc
# define OE_REALLOC realloc
# define OE_FREE free
# include "../common/malloc.c"
#endif

/*
**==============================================================================
**
** dlmalloc:
**
**==============================================================================
*/

#ifdef USE_DLMALLOC

#include <enc/enclave.h>
#include <enc/internal/globals.h>
#include <enc/internal/fault.h>

#define HAVE_MMAP 0
#define LACKS_UNISTD_H
#define LACKS_SYS_PARAM_H
#define LACKS_SYS_TYPES_H
#define LACKS_TIME_H
#define LACKS_STDLIB_H
#define LACKS_STRING_H
#define LACKS_ERRNO_H
#define NO_MALLOC_STATS 1
#define MALLOC_FAILURE_ACTION
#define MORECORE sbrk
#define ABORT abort()
#define ENOMEM 12
#define EINVAL 22

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#include "../3rdparty/dlmalloc/malloc.c"

#endif /* USE_DLMALLOC */
