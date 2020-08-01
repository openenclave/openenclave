// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXLOAD_H
#define _OE_SGXLOAD_H

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/sgxcreate.h>

#define OE_SGX_NUM_CONTROL_PAGES 4

OE_EXTERNC_BEGIN

#define OE_SGX_NO_DEVICE_HANDLE -1

OE_INLINE bool oe_sgx_is_simulation_load_context(
    const oe_sgx_load_context_t* context)
{
    return (context && (context->attributes.flags & OE_ENCLAVE_FLAG_SIMULATE));
}

OE_INLINE bool oe_sgx_is_debug_load_context(
    const oe_sgx_load_context_t* context)
{
    return (context && (context->attributes.flags & OE_ENCLAVE_FLAG_DEBUG));
}

oe_result_t oe_sgx_create_enclave(
    oe_sgx_load_context_t* context,
    size_t enclave_size,
    size_t enclave_commit_size,
    uint64_t* enclave_addr);

oe_result_t oe_sgx_load_enclave_data(
    oe_sgx_load_context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

oe_result_t oe_sgx_initialize_enclave(
    oe_sgx_load_context_t* context,
    uint64_t addr,
    const oe_sgx_enclave_properties_t* properties,
    OE_SHA256* mrenclave);

oe_result_t oe_sgx_delete_enclave(oe_enclave_t* enclave);

OE_EXTERNC_END

#endif /* _OE_SGXLOAD_H */
