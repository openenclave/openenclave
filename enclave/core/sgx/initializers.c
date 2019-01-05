// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "initializers.h"
#include <openenclave/bits/initializers.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/thread.h>

#ifdef __linux__

/**
 * These two variables will be set by the linker to lie on the start and
 * end of the _oeinitializers section.
 */
extern uint8_t __start__oeinitializers[];
extern uint8_t __stop__oeinitializers[];

static oe_once_t _once = OE_ONCE_INIT;

void _call_enclave_initializers_impl()
{
    oe_enclave_initializer_t* initializers =
        (oe_enclave_initializer_t*)&__start__oeinitializers;
    oe_enclave_initializer_t* initializers_end =
        (oe_enclave_initializer_t*)&__stop__oeinitializers;

    // Sort the initializers according to their groups.
    const uint64_t n = (uint64_t)(initializers_end - initializers);
    for (uint64_t i = 0; i < n; ++i)
    {
        for (uint64_t j = i + 1; j < n; ++j)
        {
            if (oe_strcmp(
                    initializers[i].group_name, initializers[j].group_name) > 0)
            {
                oe_enclave_initializer_t tmp = initializers[i];
                initializers[i] = initializers[j];
                initializers[j] = tmp;
            }
        }
    }

    // Call the initializers.
    for (uint64_t i = 0; i < n; ++i)
    {
        if (!initializers[i].executed)
        {
            initializers[i].executed = true;
            initializers[i].initializer();
        }
    }
}

oe_result_t oe_call_enclave_initializers()
{
    oe_once(&_once, _call_enclave_initializers_impl);
    return OE_OK;
}

void oe_call_initializer_group(const char* group_name)
{
    oe_enclave_initializer_t* initializers =
        (oe_enclave_initializer_t*)&__start__oeinitializers;
    oe_enclave_initializer_t* initializers_end =
        (oe_enclave_initializer_t*)&__stop__oeinitializers;

    const uint64_t n = (uint64_t)(initializers_end - initializers);
    for (uint64_t i = 0; i < n; ++i)
    {
        if (!initializers[i].executed &&
            oe_strcmp(initializers[i].group_name, group_name) == 0)
        {
            initializers[i].executed = true;
            initializers[i].initializer();
        }
    }
}

/* Create default initializer to make sure the einitializers sections is not
 * empty */
static void _default_init()
{
}

OE_REGISTER_ENCLAVE_INITIALIZER("default", _default_init);

#endif
