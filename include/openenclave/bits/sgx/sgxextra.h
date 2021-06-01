// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXEXTRA_H
#define _OE_SGXEXTRA_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * May be overriden by the host application to add additional enclave data pages
 * immediately before the enclave heap.
 */
oe_result_t oe_load_extra_enclave_data_hook(void* arg, uint64_t baseaddr);

/**
 * Called by the host application (from oe_load_extra_enclave_data_hook) to add
 * one page of enclave data.
 */
oe_result_t oe_load_extra_enclave_data(
    void* arg,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend);

OE_EXTERNC_END

#endif /* _OE_SGXEXTRA_H */
