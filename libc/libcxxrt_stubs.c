#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <dlfcn.h>

/* Stubs needed to compile the libcxxrt library */

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
