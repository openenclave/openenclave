// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)
{
    if (len > destlen)
        oe_abort();
    return memcpy(dest, src, len);
}

void* __memset_chk(void* dest, int c, size_t len, size_t destlen)
{
    if (len > destlen)
        oe_abort();
    return memset(dest, c, len);
}

unsigned long getauxval(unsigned long type)
{
    OE_UNUSED(type);
    return 0;
}

char* secure_getenv(const char* name)
{
    OE_UNUSED(name);
    return NULL;
}

int shmget(long key, size_t size, int flag)
{
    OE_UNUSED(key);
    OE_UNUSED(size);
    OE_UNUSED(flag);
    return -1;
}

struct stat;
int __fxstat(int vers, int fd, struct stat* buf)
{
    // TODO: Just use MUSL's implementation which forwards to fstat
    OE_UNUSED(vers);
    OE_UNUSED(fd);
    OE_UNUSED(buf);
    return -1;
}

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

uint64_t oe_get_time(void);

OE_DEFINE_SYSCALL2(SYS_clock_gettime)
{
    clockid_t clock_id = (clockid_t)arg1;
    struct timespec* tp = (struct timespec*)arg2;
    int ret = -1;
    uint64_t msec;

    if (!tp)
        goto done;

    if (clock_id != CLOCK_REALTIME)
    {
        /* Only supporting CLOCK_REALTIME */
        // oe_assert("clock_gettime(): panic" == NULL);
        // goto done;
    }

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tp->tv_sec = msec / _SEC_TO_MSEC;
    tp->tv_nsec = (msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC;

    ret = 0;

done:

    return ret;
}

long syscall(
    long n,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6)
{
    OE_UNUSED(arg3);
    OE_UNUSED(arg4);
    OE_UNUSED(arg5);
    OE_UNUSED(arg6);

    switch (n)
    {
        case 318: // syscall_random
        {
            oe_random((void*)arg1, arg2);
            return 0;
        }
        break;
    }
    oe_abort();
    return -1;
}
