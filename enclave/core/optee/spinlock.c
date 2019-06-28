// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// TODO: This file is a stub!

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#include <openenclave/internal/thread.h>
#else
#include <openenclave/host.h>
#endif

oe_result_t oe_spin_init(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    *spinlock = OE_SPINLOCK_INITIALIZER;

    return OE_OK;
}

oe_result_t oe_spin_lock(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_spin_unlock(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}

oe_result_t oe_spin_destroy(oe_spinlock_t* spinlock)
{
    if (!spinlock)
        return OE_INVALID_PARAMETER;

    return OE_OK;
}
