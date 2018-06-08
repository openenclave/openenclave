// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SGXMEASURE_H
#define _OE_SGXMEASURE_H

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/sha.h>

OE_EXTERNC_BEGIN

oe_result_t oe_sgx__measure_create_enclave(oe_sha256__context_t* context, SGX_Secs* secs);

oe_result_t oe_sgx__measure_load_enclave_data(
    oe_sha256__context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

oe_result_t oe_sgx__measure_initialize_enclave(
    oe_sha256__context_t* context,
    OE_SHA256* mrenclave);

OE_EXTERNC_END

#endif /* _OE_SGXMEASURE_H */
