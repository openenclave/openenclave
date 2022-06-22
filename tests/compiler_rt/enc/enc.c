// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <math.h>
#include "compiler_rt_t.h"

#if __aarch64__

/* Workaround: sqrtl is not implemented by MUSL for AARCH64. */
long double sqrtl(long double v)
{
    return sqrt((double)v);
}

/* Workaround: 3rdparty/optee/optee_os/lib/libutee/tee_api_operations.c
   defines rand. This causes multiple definition error since oelibc includes
   3rdparty/musl/musl/src/prng/rand.c.
   As a workaround, define a WEAK implementation of rand here which will be
   picked up by the linker over oelibc implementation, and later overridden
   by libutee implementation.
 */
OE_WEAK int rand(void)
{
    return 0;
}

#endif

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */

#define TA_UUID                                            \
    { /* d0a1a92a-cfc5-4563-b9d4-57cf526a839d */           \
        0xd0a1a92a, 0xcfc5, 0x4563,                        \
        {                                                  \
            0xb9, 0xd4, 0x57, 0xcf, 0x52, 0x6a, 0x83, 0x9d \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "compiler-rt test")
