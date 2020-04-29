// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SIGNSGX_H
#define _OE_SIGNSGX_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include "crypto/sha.h"

OE_EXTERNC_BEGIN

/**
 * Digitally sign the enclave with the given hash
 *
 * This function digitally signs the enclave whose hash is given by the
 * **mrenclave** parameter. The signing key is given by the **pem_data**
 * parameter. If successful, the function writes the signature into the
 * **sigstruct** parameter (an SGX signature structure).
 *
 * @param mrenclave[in] hash of the enclave being signed
 * @param pem_data[in] PEM buffer containing the signing key
 * @param pem_size[in] size of the PEM buffer
 * @param sigstruct[out] the SGX signature
 *
 * @return OE_OK success
 */
oe_result_t oe_sgx_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const uint8_t* pem_data,
    size_t pem_size,
    sgx_sigstruct_t* sigstruct);

/**
 * Digitally sign the enclave with the given hash using an openssl engine
 *
 * This function digitally signs the enclave whose hash is given by the
 * **mrenclave** parameter. The signing key is given by the **engine_id** and
 * related **key_id** parameter. If successful, the function writes the
 * signature into the
 * **sigstruct** parameter (an SGX signature structure).
 *
 * @param mrenclave[in] hash of the enclave being signed
 * @param engine_id[in] text name of the engine to use
 * @param key_id[in] integer handle for the key to use.
 * @param sigstruct[out] the SGX signature
 *
 * @return OE_OK success
 */
oe_result_t oe_sgx_sign_enclave_from_engine(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id,
    sgx_sigstruct_t* sigstruct);

OE_EXTERNC_END

#endif /* _OE_SIGNSGX_H */
