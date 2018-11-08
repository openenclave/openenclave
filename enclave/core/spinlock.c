// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#else
#include <openenclave/host.h>
#endif
#include <openenclave/internal/utils.h>

oe_result_t oe_spin_init(oe_spinlock_t* spinlock)
{
    *spinlock = OE_SPINLOCK_INITIALIZER;
    return OE_OK;
}

oe_result_t oe_spin_lock(oe_spinlock_t* spinlock)
{
    while (oe_exchange_acquire((uint32_t*)spinlock, 1) != 0)
    {
        /* Spin while waiting for spinlock to be released (become 0) */
        while (*spinlock)
        {
            /* Yield to CPU */
            oe_pause();
        }
    }

    return OE_OK;
}

oe_result_t oe_spin_unlock(oe_spinlock_t* spinlock)
{
    oe_write_release((uint32_t*)spinlock, OE_SPINLOCK_INITIALIZER);
    return OE_OK;
}

oe_result_t oe_spin_destroy(oe_spinlock_t* spinlock)
{
    return OE_OK;
}
