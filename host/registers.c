// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__linux__)
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <assert.h>
#include <stdio.h>

#include <openenclave/internal/registers.h>

void oe_set_gs_register_base(const void* ptr)
{
#if defined(__linux__)
    syscall(__NR_arch_prctl, ARCH_SET_GS, ptr);
#elif defined(_WIN32)
   # if defined(_MSVC_VER)
      _writegsbase_u64((uint64_t)ptr);
   #else
     // __builtin_ia32_wrgsbase64((uint64_t)ptr);  // Need to figure out the needed feature to access fs/gs registers.
   #endif
#endif
}

void* oe_get_gs_register_base()
{
#if defined(__linux__)
    void* ptr = NULL;
    syscall(__NR_arch_prctl, ARCH_GET_GS, &ptr);
    return ptr;
#elif defined(_WIN32)
   # if defined(_MSVC_VER)
    return __builtin_ia32_rdgsbase64();
   #else
 //   return (void*)_readgsbase_u64();
   #endif
#endif
}
