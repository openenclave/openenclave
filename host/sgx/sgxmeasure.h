// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXMEASURE_H
#define _OE_SGXMEASURE_H

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/crypto/sha.h>

OE_EXTERNC_BEGIN

oe_result_t oe_sgx_measure_create_enclave(
    oe_sha256_context_t* context,
    sgx_secs_t* secs);

oe_result_t oe_sgx_measure_load_enclave_data(
    oe_sha256_context_t* context,
    uint64_t base,
    uint64_t addr,
    uint64_t src,
    uint64_t flags,
    bool extend);

oe_result_t oe_sgx_measure_initialize_enclave(
    oe_sha256_context_t* context,
    OE_SHA256* mrenclave);

OE_EXTERNC_END

#endif /* _OE_SGXMEASURE_H */
