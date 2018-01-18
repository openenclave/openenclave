#if defined(__linux__)
# include <unistd.h>
# include <sys/syscall.h>
# include <asm/prctl.h>
#elif defined(_WIN32)
# include <Windows.h>
#endif

#include <stdio.h>
#include <assert.h>

#include <openenclave/bits/registers.h>

void OE_SetGSRegisterBase(const void *ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
#elif defined(_WIN32)
    /* On Windows use the FS register instead of GS */
    _writefsbase_u64((uint64_t)ptr);
#endif
}

void* OE_GetGSRegisterBase()
{
#if defined(__linux__)
    void* ptr = NULL;
    syscall(__NR_arch_prctl, ARCH_GET_GS, &ptr);
    return ptr;
#elif defined(_WIN32)
    /* On Windows use the FS register instead of GS */
    return (void*)_readfsbase_u64();
#endif
}
