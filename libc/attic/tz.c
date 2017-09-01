#include <stdio.h>
#include <stdarg.h>
#include <locale.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#define index __index__

static void do_tzset(void);

void __tzset(void);

const char *__tm_to_tzname(const struct tm *tm);

static char* getenv(const char* str)
{
    /* ATTN: fix this! */
    if (strcmp(str, "TZ") == 0)
        return "America/Los_Angeles";

    return NULL;
}

static int __munmap(void* ptr, size_t size)
{
    return 0;
}

static const unsigned char* __map_file(const char* path, size_t* size)
{
    assert("__map_file() called!" == NULL);
    return NULL;
}

static pthread_mutex_t _lock = PTHREAD_MUTEX_INITIALIZER;

#include "../3rdparty/musl/musl/src/internal/libc.h"

#undef LOCK
#define LOCK(IGNORE) pthread_mutex_lock(&_lock)

#undef UNLOCK
#define UNLOCK(IGNORE) pthread_mutex_unlock(&_lock)

#include "../3rdparty/musl/musl/src/time/__tz.c"
