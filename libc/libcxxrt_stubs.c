#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <dlfcn.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

int __libcxxrt_dladdr(void *addr, Dl_info *info)
{
    assert("__libcxxrt_dladdr(): panic" == NULL);
    return -1;
}

int __libcxxrt_sched_yield(void)
{
    assert("__libcxxrt_sched_yield(): panic" == NULL);
    return -1;
}
