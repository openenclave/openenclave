// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/pthread.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <pthread.h>
#include "data_types_t.h"

void ecall_test()
{
    OE_TEST(sizeof(oe_pthread_attr_t) == sizeof(pthread_attr_t));
    OE_TEST(sizeof(oe_pthread_mutexattr_t) == sizeof(pthread_mutexattr_t));
    OE_TEST(sizeof(oe_pthread_mutex_t) == sizeof(pthread_mutex_t));
    OE_TEST(sizeof(oe_pthread_condattr_t) == sizeof(pthread_condattr_t));
    OE_TEST(sizeof(oe_pthread_cond_t) == sizeof(pthread_cond_t));
    OE_TEST(sizeof(oe_pthread_rwlockattr_t) == sizeof(pthread_rwlockattr_t));
    OE_TEST(sizeof(oe_pthread_rwlock_t) == sizeof(pthread_rwlock_t));
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */

#define TA_UUID                                            \
    { /* 338a3b09-60dd-4808-8e51-afe019a11f99 */           \
        0x338a3b09, 0x60dd, 0x4808,                        \
        {                                                  \
            0x8e, 0x51, 0xaf, 0xe0, 0x19, 0xa1, 0x1f, 0x99 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "Data types test")
