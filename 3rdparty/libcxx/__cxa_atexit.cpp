#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

extern "C" int __cxa_atexit(void (*func)(void *), void *arg, void *d)
{
    /* ATTN: handle global constructors here! */
}
