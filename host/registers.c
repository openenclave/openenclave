#if defined(__linux__)
# include <unistd.h>
# include <sys/syscall.h>
# include <asm/prctl.h>
#elif defined(_WIN32)
# include <Windows.h>
#endif

#include <stdio.h>

#include <openenclave/bits/registers.h>

int OE_SetGSRegisterBase(const void *ptr)
{
#if defined(__linux__)
    return syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
#elif defined(_WIN32)
    /* On Windows use the FS register instead of GS */
    _writefsbase_u64((uint64_t)ptr);
    return 0;
#endif
}

int OE_GetGSRegisterBase(const void **ptr)
{
#if defined(__linux__)
    return syscall(__NR_arch_prctl, ARCH_GET_GS, ptr);
#elif defined(_WIN32)
    /* On Windows use the FS register instead of GS */
    *ptr = (void*)_readfsbase_u64();
    return 0;
#endif
}
