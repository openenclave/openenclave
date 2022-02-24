// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_EXTRADATA_H
#define _OE_INTERNAL_SGX_EXTRADATA_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/sgxcreate.h>

OE_EXTERNC_BEGIN

#define OE_LOAD_EXTRA_ENCLAVE_DATA_HOOK_ARG_MAGIC 0x793d33e0efb446d0

typedef struct oe_load_extra_enclave_data_hook_arg
{
    uint64_t magic;
    oe_sgx_load_context_t* sgx_load_context;
    uint64_t enclave_base;
    uint64_t enclave_start;
    uint64_t base_vaddr; /* address relative to the enclave start */
    uint64_t vaddr;      /* address relative to the extra data start */
} oe_load_extra_enclave_data_hook_arg_t;

/**
 * May be registered by the host application via
 * oe_register_load_extra_enclave_data_hook to add additional enclave data pages
 * immediately before the enclave heap. The hook will be invoked by the loader
 * twice: In the first time, the loader constructs a dummy **arg** and passes
 * **baseaddr** as zero, expecting the hook to invoke oe_load_extra_enclave_data
 * and returns the total size of extra data (will be stored as part of **arg**).
 * In the second time, the loader constructs the **arg** with necessary
 * parameters and passes the **baseaddr** as the starting address to which the
 * extra data will be loaded, expecting the hook to invoke
 * oe_load_extra_enclave_data to load each extra data page.
 */
typedef oe_result_t (*oe_load_extra_enclave_data_hook_t)(
    oe_load_extra_enclave_data_hook_arg_t* arg,
    uint64_t baseaddr);

void oe_register_load_extra_enclave_data_hook(
    oe_load_extra_enclave_data_hook_t hook);

/**
 * Called by the host application (from oe_load_extra_enclave_data_hook) to add
 * one page of enclave data. The **vaddr** is relative to the starting address
 * of the extra data (use 0 for adding the first page).
 */
oe_result_t oe_load_extra_enclave_data(
    oe_load_extra_enclave_data_hook_arg_t* arg,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_SGX_EXTRADATA_H */
