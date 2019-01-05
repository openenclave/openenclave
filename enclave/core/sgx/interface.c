// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/enclave_interface.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

#define INTERFACE_MAGIC 0xb52e0a93a8ce97a6

typedef struct oe_interface_impl
{
    uint64_t magic;
    const char* name;
    oe_interface_ecall_handler_t handler;
    void* host_interface_handle;
    struct oe_interface_impl* next;
} oe_interface_impl_t;

OE_STATIC_ASSERT(sizeof(oe_interface_impl_t) <= sizeof(oe_interface_t));

static oe_interface_impl_t* _interfaces = NULL;

oe_result_t oe_register_interface(
    oe_interface_t* interface,
    const char* identifier,
    oe_interface_ecall_handler_t handler)
{
    oe_result_t result = OE_FAILURE;
    oe_interface_impl_t* impl = (oe_interface_impl_t*)interface;
    oe_interface_impl_t* impl_itr = _interfaces;

    if (impl == NULL || impl->magic)
        OE_RAISE(OE_INVALID_PARAMETER);

    while (impl_itr)
    {
        if (oe_strcmp(identifier, impl_itr->name) == 0)
            OE_RAISE(OE_FAILURE);

        impl_itr = impl_itr->next;
    }

    impl->magic = INTERFACE_MAGIC;
    impl->name = identifier;
    impl->handler = handler;
    impl->host_interface_handle = NULL;
    impl->next = _interfaces;

    _interfaces = impl;

done:
    return result;
}
