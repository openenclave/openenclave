#include <pthread.h>
#include <assert.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/*
**==============================================================================
**
** dlfcn.h
**
**==============================================================================
*/

int __libcxxrt_dladdr(void *addr, Dl_info *info)
{
    assert("__libcxxrt_dladdr(): panic" == NULL);
    return -1;
}

/*
**==============================================================================
**
** sched.h
**
**==============================================================================
*/

int __libcxxrt_sched_yield(void)
{
    assert("__libcxxrt_sched_yield(): panic" == NULL);
    return -1;
}
