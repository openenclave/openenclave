// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SIGNSGX_H
#define _OE_SIGNSGX_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include "sgxtypes.h"
#include "sha.h"

OE_EXTERNC_BEGIN

/**
* Digitally sign the enclave with the given hash
*
* This function digitally signs the enclave whose hash is given by the
* **mrenclave** parameter. The signing key is given by the **pemData**
* parameter. If successful, the function writes the signature into the
* **sigstruct** parameter (an SGX signature structure).
*
* @param mrenclave[in] hash of the enclave being signed
* @param pemData[in] PEM buffer containing the signing key
* @param pemSize[in] size of the PEM buffer
* @param sigstruct[out] the SGX signature
*
* @return OE_OK success
*/
oe_result_t oe_sgx_sign_enclave(
    const OE_SHA256* mrenclave,
    uint64_t attributes,
    uint16_t productID,
    uint16_t securityVersion,
    const uint8_t* pemData,
    size_t pemSize,
    sgx_sigstruct_t* sigstruct);

OE_EXTERNC_END

#endif /* _OE_SIGNSGX_H */
