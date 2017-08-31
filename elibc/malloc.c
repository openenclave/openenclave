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
#define ABORT abort()

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#include "../3rdparty/dlmalloc/malloc.c"
