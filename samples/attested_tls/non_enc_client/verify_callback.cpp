// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#endif

#include <string.h>

#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include "../common/common.h"
#include "../common/tls_server_enc_mrenclave.h"
#include "../common/tls_server_enc_pubkey.h"

/**
 * Helper function used to make the claim-finding process more convenient. Given
 * the claim name, claim list, and its size, returns the claim with that claim
 * name in the list.
 */
const oe_claim_t* find_claim(
    const oe_claim_t* claims,
    size_t claims_size,
    const char* name)
{
    for (size_t i = 0; i < claims_size; i++)
    {
        if (strcmp(claims[i].name, name) == 0)
            return &(claims[i]);
    }
    return nullptr;
}

bool verify_signer_id(
    const char* pem_key_buffer,
    size_t pem_key_buffer_len,
    uint8_t* expected_signer,
    size_t expected_signer_size)
{
    printf("\n" TLS_CLIENT "verify connecting server's identity\n");

    uint8_t calculated_signer[OE_SIGNER_ID_SIZE];
    size_t calculated_signer_size = sizeof(calculated_signer);
    if (oe_sgx_get_signer_id_from_public_key(
            pem_key_buffer,
            pem_key_buffer_len,
            calculated_signer,
            &calculated_signer_size) != OE_OK)
    {
        printf("oe_sgx_get_signer_id_from_public_key failed\n");
        return false;
    }

    // validate against
    if (memcmp(calculated_signer, expected_signer, expected_signer_size) != 0)
    {
        printf("signer_id is not equal\n");
        for (size_t i = 0; i < expected_signer_size; i++)
        {
            printf(
                "0x%x - 0x%x\n",
                (uint8_t)expected_signer[i],
                (uint8_t)calculated_signer[i]);
        }
        return false;
    }
    printf("signer_id was successfully validated\n");
    return true;
}

// This is the evidence claims validation callback. A TLS connecting party
// (client or server) can verify the passed in "identity" information to decide
// whether to accept the connection request from a tls server running inside a
// specific enclave. In a real app, custom identity validation should be done
// inside this routine.
oe_result_t enclave_claims_verifier(
    oe_claim_t* claims,
    size_t claims_length,
    void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;
    const oe_claim_t* claim;

    (void)arg;
    printf(TLS_CLIENT "enclave_claims_verifier is called with the claims from "
                      "the evidence:\n");

    // Dump an identity information: unique ID, signer ID and Product ID
    // They are MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.

    // Enclave's security version
    if ((claim = find_claim(
             claims, claims_length, OE_CLAIM_SECURITY_VERSION)) == nullptr)
    {
        printf(TLS_SERVER "could not find OE_CLAIM_SECURITY_VERSION\n");
        goto done;
    }
    if (claim->value_size != sizeof(uint32_t))
    {
        printf(
            "security_version size(%lu) checking failed\n", claim->value_size);
        goto done;
    }
    printf(TLS_SERVER "\nsecurity_version = %d\n", *claim->value);

    // The unique ID for the enclave, for SGX enclaves, this is the MRENCLAVE
    // value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_UNIQUE_ID)) ==
        nullptr)
    {
        printf(TLS_CLIENT "could not find OE_CLAIM_UNIQUE_ID\n");
        goto done;
    }
    if (claim->value_size != OE_UNIQUE_ID_SIZE)
    {
        printf(
            TLS_CLIENT "unique_id size(%lu) checking failed\n",
            claim->value_size);
        goto done;
    }
    printf(TLS_CLIENT "\nverify unique_id:\n");
    for (size_t i = 0; i < claim->value_size; i++)
    {
        printf("0x%0x ", (uint8_t)claim->value[i]);
        if (SERVER_ENCLAVE_MRENCLAVE[i] != (uint8_t)claim->value[i])
        {
            printf(
                TLS_CLIENT "unique_id[%lu] expected: 0x%0x  found: 0x%0x ",
                i,
                SERVER_ENCLAVE_MRENCLAVE[i],
                (uint8_t)claim->value[i]);
            printf(TLS_CLIENT "failed: unique_id not equal\n");
            goto done;
        }
    }
    printf("\n" TLS_CLIENT "unique_id validation passed\n");

    // The Product ID for the enclave, for SGX enclaves, this is the ISVPRODID
    // value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_PRODUCT_ID)) ==
        nullptr)
    {
        printf(TLS_CLIENT "could not find OE_CLAIM_PRODUCT_ID\n");
        goto done;
    }
    if (claim->value_size != OE_PRODUCT_ID_SIZE)
    {
        printf(
            TLS_CLIENT "product_id size(%lu) checking failed\n",
            claim->value_size);
        goto done;
    }
    printf(TLS_CLIENT "\nproduct_id :\n");
    for (size_t i = 0; i < claim->value_size; i++)
        printf("0x%0x ", (uint8_t)claim->value[i]);
    printf("\n");

    // The signer ID for the enclave, for SGX enclaves, this is the MRSIGNER
    // value
    if ((claim = find_claim(claims, claims_length, OE_CLAIM_SIGNER_ID)) ==
        nullptr)
    {
        printf(TLS_CLIENT "could not find OE_CLAIM_SIGNER_ID\n");
        goto done;
    }
    if (claim->value_size != OE_SIGNER_ID_SIZE)
    {
        printf(
            TLS_CLIENT "signer_id size(%lu) checking failed\n",
            claim->value_size);
        goto done;
    }
    printf(TLS_CLIENT "\nverify signer_id:\n");
    for (size_t i = 0; i < claim->value_size; i++)
        printf("0x%0x ", (uint8_t)claim->value[i]);

    // In this sample, only signer_id validation is shown
    if (!verify_signer_id(
            (char*)OTHER_ENCLAVE_PUBLIC_KEY,
            sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
            claim->value,
            claim->value_size))
    {
        printf(TLS_CLIENT "failed: signer_id not equal\n");
        goto done;
    }
    printf(TLS_CLIENT "signer_id validation passed.\n");

    printf(TLS_CLIENT "enclave_claims_verifier returned success\n");
    result = OE_OK;
done:
    return result;
}

// The return value of verify_callback controls the strategy of the further
// verification process. If verify_callback returns 0, the verification process
// is immediately stopped with "verification failed" state and A verification
// failure alert is sent to the peer and the TLS/SSL handshake is terminated. If
// verify_callback returns 1, the verification process is continued.
int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    int ret = 0;
    int der_len = 0;
    unsigned char* der = nullptr;
    unsigned char* buff = nullptr;
    oe_result_t result = OE_FAILURE;
    X509* crt = nullptr;
    int err = X509_V_ERR_UNSPECIFIED;

    printf(
        TLS_CLIENT "verify_callback called with preverify_ok=%d\n",
        preverify_ok);
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == nullptr)
    {
        printf(TLS_CLIENT "failed to retrieve certificate\n");
        goto done;
    }

    if (preverify_ok == 0)
    {
        err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        {
            // A self-signed certificate is expected, return 1 to continue the
            // verification process
            printf(TLS_CLIENT "self-signed certificated detected\n");
            ret = 1;
            goto done;
        }
    }

    // convert a cert into a buffer in DER format
    der_len = i2d_X509(crt, nullptr);
    buff = (unsigned char*)malloc(der_len);
    if (buff == nullptr)
    {
        printf(TLS_CLIENT "malloc failed (der_len=%d)\n", der_len);
        goto done;
    }
    der = buff;
    der_len = i2d_X509(crt, &buff);
    if (der_len < 0)
    {
        printf(TLS_CLIENT "i2d_X509 failed(der_len=%d)\n", der_len);
        goto done;
    }

    // note: i2d_X509() updates the pointer to the buffer so that following the
    // call to i2d_X509(), buff is pointing to the "end" of the data buffer
    // pointed by buff That is, buff = buff + der_len;
    printf(
        TLS_CLIENT "der=%p buff=%p buff moved by %d offset der_len=%d\n",
        der,
        buff,
        (int)(buff - der),
        der_len);

#if 1 // for debugging purpose
    {
        // output the whole cer in DER format
        FILE* file = fopen("./cert.der", "wb");
        fwrite(der, 1, der_len, file);
        fclose(file);
    }
#endif

    // verify tls certificate
    oe_verifier_initialize();
    result = oe_verify_attestation_certificate_with_evidence(
        der, der_len, enclave_claims_verifier, nullptr);
    if (result != OE_OK)
    {
        printf(TLS_CLIENT "result=%s\n", oe_result_str(result));
        goto done;
    }
    ret = 1;
done:

    if (der)
        free(der);

    if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
    {
        printf(
            TLS_CLIENT "verifying SGX certificate extensions ... %s\n",
            ret ? "succeeded" : "failed");
    }
    oe_verifier_shutdown();
    return ret;
}
