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
 * @param attributes[in] ATTRIBUTES flag values for the SGX sigstruct
 * @param product_id[in] ISVPRODID value for the SGX sigstruct
 * @param security_version[in] ISVSVN value for the SGX sigstruct
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
 * signature into the **sigstruct** parameter (an SGX signature structure).
 *
 * @param mrenclave[in] hash of the enclave being signed
 * @param attributes[in] ATTRIBUTES flag values for the SGX sigstruct
 * @param product_id[in] ISVPRODID value for the SGX sigstruct
 * @param security_version[in] ISVSVN value for the SGX sigstruct
 * @param engine_id[in] text name of the engine to use
 * @param engine_load_path[in] file path to the openssl engine to use
 * @param key_id[in] integer handle for the key to use
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

/**
 * Get the digest of an unsigned sigstruct given the expected MRENCLAVE,
 * ATTRIBUTES, ISVPRODID, and ISVSVN values.
 *
 * @param mrenclave[in] hash of the enclave to be signed
 * @param attributes[in] ATTRIBUTES flag values for the SGX sigstruct
 * @param product_id[in] ISVPRODID value for the SGX sigstruct
 * @param security_version[in] ISVSVN value for the SGX sigstruct
 * @param digest[out] the digest of the sigstruct to be signed
 *
 * @return OE_OK success
 */
oe_result_t oe_sgx_get_sigstruct_digest(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    OE_SHA256* digest);

/**
 * Verify the provided signature for the enclave sigstruct digest and
 * construct a sigstruct with the digest signature.
 *
 * This function digitally signs the enclave whose hash is given by the
 * **mrenclave** parameter with the provided **digest_signature**.
 * The **digest_signature** is verified against the public signing
 * certificate specified by the **cert_pem_data** parameter.
 * If successful, the function writes the signature into the
 * **sigstruct** parameter (an SGX signature structure).
 *
 * @param mrenclave[in] hash of the enclave to be signed
 * @param attributes[in] ATTRIBUTES flag values for the SGX sigstruct
 * @param product_id[in] ISVPRODID value for the SGX sigstruct
 * @param security_version[in] ISVSVN value for the SGX sigstruct
 * @param cert_pem_data[in] PEM buffer containing the public signing cert
 * @param cert_pem_size[in] size of the PEM buffer
 * @param digest_signature[in] binary data of the sigstruct digest signature
 * @param digest_signature_size[in] size of the sigstruct digest signature
 * @param sigstruct[out] the SGX signature
 *
 * @return OE_OK success
 */
oe_result_t oe_sgx_digest_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t product_id,
    uint16_t security_version,
    const uint8_t* cert_pem_data,
    size_t cert_pem_size,
    const uint8_t* digest_signature,
    size_t digest_signature_size,
    sgx_sigstruct_t* sigstruct);

OE_EXTERNC_END

#endif /* _OE_SIGNSGX_H */
