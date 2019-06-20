// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string>
#include "../../common/utility.h"
#include "tls_client_enc_pubkey.h"

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;
    bool bret = false;

    printf(TLS_SERVER
           "Server:enclave_identity_verifier_callback is called with enclave "
           "identity information:\n");

    // the enclave's security version
    printf(
        TLS_SERVER "identity->security_version = %d\n",
        identity->security_version);

    // the unique ID for the enclave, for SGX enclaves, this is the MRENCLAVE
    // value
    printf(TLS_SERVER "identity->unique_id(MRENCLAVE) :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        printf(TLS_SERVER "0x%0x ", (uint8_t)identity->unique_id[i]);

    // Check enclave's signer id
    // for SGX enclaves, this is the MRSIGNER value
    printf(TLS_SERVER "\nidentity->signer_id(MRSIGNER) :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf(TLS_SERVER "0x%0x ", (uint8_t)identity->signer_id[i]);

    if (!verify_mrsigner(
            (char*)OTHER_ENCLAVE_PUBLIC_KEY,
            sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
            identity->signer_id,
            sizeof(identity->signer_id)))
    {
        printf(TLS_SERVER "failed:mrsigner not equal!\n");
        goto exit;
    }
    printf(TLS_SERVER "mrsigner id validation passed.\n");

    // The Product ID for the enclave,  for SGX enclaves, this is the ISVPRODID
    // value
    printf(TLS_SERVER "\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        printf(TLS_SERVER "0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;

exit:

    return result;
}
