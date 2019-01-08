// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <sched.h>
#include <stdio.h>

int sched_yield(void)
{
    /* Since this is called by __cxa_guard_acquire() from
       3rdparty/libcxxrt/libcxxrt/src/guard.cc and
       std::this_thread::yield(), this routine needs to be supported for
       std::thread multi-threading to work. Adding a pause before
       returning 0 as a pause instruction is a hint to the CPU to improve
       power and performance of spin-wait loops.
     */
    __asm__ __volatile__("pause");
    return 0;
}
