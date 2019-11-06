// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

int oe_sched_yield(void)
{
    /* Since this is called by __cxa_guard_acquire() from
       3rdparty/libcxxrt/libcxxrt/src/guard.cc and
       std::this_thread::yield(), this routine needs to be supported for
       std::thread multi-threading to work. Adding a pause before
       returning 0 as a pause instruction is a hint to the CPU to improve
       power and performance of spin-wait loops.
     */

    asm volatile("pause");
    return 0;
}
