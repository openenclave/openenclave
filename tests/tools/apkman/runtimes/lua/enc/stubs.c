// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <wchar.h>

int pthread_condattr_init(void* ca)
{
    OE_UNUSED(ca);
    return -1;
}

int pthread_condattr_setclock(void* ca, long clk)
{
    OE_UNUSED(ca);
    OE_UNUSED(clk);
    return -1;
}

int sem_init(void* lock, int a, int b)
{
    OE_UNUSED(lock);
    OE_UNUSED(a);
    OE_UNUSED(b);
    return 0;
}

int readlink(void* path, void* cbuf, size_t len)
{
    return -1;
    OE_UNUSED(len);
    return swprintf(cbuf, len, L"%s", path);
}

int getrandom(void* buf, size_t buflen, unsigned int flags)
{
    OE_UNUSED(flags);
    oe_random(buf, buflen);
    return -1; // tell python that getrandom doesn't work
}

int sem_wait(void* sem)
{
    OE_UNUSED(sem);
    return 0;
}

int sem_post(void* sem)
{
    OE_UNUSED(sem);
    return 0;
}
