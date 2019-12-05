// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string>

#include "../../common/tls_server_enc_mrenclave.h"
#include "../../common/tls_server_enc_pubkey.h"
#include "../../common/utility.h"

oe_result_t enclave_identity_verifier_callback(
    oe_identity_t* identity,
    void* arg)
{
    OE_UNUSED(arg);

    oe_result_t result = OE_VERIFY_FAILED;

    printf(TLS_CLIENT
           "Client:enclave_identity_verifier_callback is called with enclave "
           "identity information:\n");

    // enclave's security version
    printf(
        TLS_CLIENT "identity->security_version = %d\n",
        identity->security_version);

    // the unique ID for the enclave, for SGX enclaves, this is the MRENCLAVE
    // value
    printf(TLS_CLIENT "Validating identity->unique_id(MRENCLAVE) :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
    {
        printf("0x%0x ", (uint8_t)identity->unique_id[i]);
        if (SERVER_ENCLAVE_MRENCLAVE[i] != (uint8_t)identity->unique_id[i])
        {
            printf(
                TLS_CLIENT
                "identity->unique_id[%d] expected: 0x%0x  found: 0x%0x ",
                i,
                SERVER_ENCLAVE_MRENCLAVE[i],
                (uint8_t)identity->unique_id[i]);
            printf(TLS_CLIENT "failed:unique_id not equal!\n");
            goto exit;
        }
    }
    printf("\n" TLS_CLIENT "unique_id validation passed\n");

    // The signer ID for the enclave, for SGX enclaves, this is the MRSIGNER
    // value
    printf(TLS_CLIENT "\nidentity->signer_id(MRSIGNER) :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);

    if (!verify_mrsigner(
            (char*)OTHER_ENCLAVE_PUBLIC_KEY,
            sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
            identity->signer_id,
            sizeof(identity->signer_id)))
    {
        printf(TLS_CLIENT "failed:mrsigner not equal!\n");
        goto exit;
    }
    printf(TLS_CLIENT "mrsigner id validation passed.\n");

    // The Product ID for the enclave, for SGX enclaves, this is the ISVPRODID
    // value
    printf(TLS_CLIENT "\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        printf(TLS_CLIENT "0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
exit:
    return result;
}
