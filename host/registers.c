#if defined(__linux__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <openenclave/bits/registers.h>

void OE_SetGSRegisterBase(const void* ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
#elif defined(_WIN32)
    _writegsbase_u64((uint64_t)ptr);
#endif
}

void* OE_GetGSRegisterBase()
{
#if defined(__linux__)
    void* ptr = NULL;
    syscall(__NR_arch_prctl, ARCH_GET_GS, &ptr);
    return ptr;
#elif defined(_WIN32)
    return (void*)_readgsbase_u64();
#endif
}
