// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(__linux__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#include <immintrin.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <openenclave/internal/registers.h>

void oe_set_gs_register_base(const void* ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
#elif defined(_WIN32)
    _writegsbase_u64((uint64_t)ptr);
#endif
}

void* oe_get_gs_register_base()
{
#if defined(__linux__)
    void* ptr = NULL;
    syscall(__NR_arch_prctl, ARCH_GET_GS, &ptr);
    return ptr;
#elif defined(_WIN32)
    return (void*)_readgsbase_u64();
#endif
}

void oe_set_fs_register_base(const void* ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_FS, ptr);
#elif defined(_WIN32)
    _writefsbase_u64((uint64_t)ptr);
#endif
}

void* oe_get_fs_register_base()
{
#if defined(__linux__)
    void* ptr = NULL;
    syscall(__NR_arch_prctl, ARCH_GET_FS, &ptr);
    return ptr;
#elif defined(_WIN32)
    return (void*)_readfsbase_u64();
#endif
}
