// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_KEYS_H
#define _OE_KEYS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * Get a secret SGX key.
 *
 * Call this function to get a secret SGX key from processor.
 *
 * @param sgx_key_request The parameter points to the KEYREQUEST structure that
 * describes which key and how it should be derived. This parameter must point
 * to a readable memory block inside enclave.
 * @param sgx_key The parameter points to sgx_key_t structure where the key will
 * be
 * returned. This parameter must point to a writable memory block inside
 * enclave. It will not be changed if this function fails.
 *
 * @retval OE_OK Request succeeded and the key is written to **sgx_key**.
 *  **sgx_key** is not modified if the return value is not OE_OK.
 * @retval OE_INVALID_CPUSVN **sgx_key_request** contains an invalid CPUSVN.
 * @retval OE_INVALID_ISVSVN **sgx_key_request** contains an invalid ISVSVN.
 * @retval OE_INVALID_KEYNAME **sgx_key_request** contains an invalid KEYNAME.
 * @retval OE_INVALID_PARAMETER Any other invalid parameter was specified.
 * @retval OE_UNEXPECTED An unexpected error occurred.
 *
 */
oe_result_t oe_get_key(
    const sgx_key_request_t* sgx_key_request,
    sgx_key_t* sgx_key);

OE_EXTERNC_END

#endif /* _OE_KEYS_H */
