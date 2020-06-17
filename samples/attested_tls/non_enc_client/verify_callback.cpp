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
#include <openenclave/host.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include "../common/common.h"
#include "../common/tls_server_enc_mrenclave.h"
#include "../common/tls_server_enc_pubkey.h"

bool verify_mrsigner(
    const char* pem_key_buffer,
    size_t pem_key_buffer_len,
    uint8_t* expected_signer,
    size_t expected_signer_size)
{
    printf(TLS_CLIENT "Verify connecting server's identity\n");

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
        printf("mrsigner is not equal!\n");
        for (int i = 0; i < expected_signer_size; i++)
        {
            printf(
                "0x%x - 0x%x\n",
                (uint8_t)expected_signer[i],
                (uint8_t)calculated_signer[i]);
        }
        return false;
    }
    printf("signer id (MRSIGNER) was successfully validated\n");
    return true;
}

// This is the identity validation callback. An TLS connecting party (client or
// server) can verify the passed in "identity" information to decide whether to
// accept the connection reqest from an tls server running inside a specific
// enclave In a real app, custom identity validation should be done inside this
// routine
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    printf(TLS_CLIENT
           "enclave_identity_verifier is called with parsed report:\n");

    // Dump an identity information: unique ID, signer ID and Product ID
    // They are MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves.
    printf(
        TLS_CLIENT "identity.security_version = %d\n",
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
            goto done;
        }
    }
    printf("\n" TLS_CLIENT "unique_id validation passed\n");

    printf("\n" TLS_CLIENT "identity->product_id : ");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->product_id[i]);
    printf("\n");

    printf(TLS_CLIENT "identity->signer_id : ");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        printf("0x%0x ", (uint8_t)identity->signer_id[i]);
    printf("\n");

    // In this sample, only signer_id validation is shown
    if (!verify_mrsigner(
            (char*)OTHER_ENCLAVE_PUBLIC_KEY,
            sizeof(OTHER_ENCLAVE_PUBLIC_KEY),
            identity->signer_id,
            sizeof(identity->signer_id)))
    {
        printf("failed:mrsigner not equal!\n");
        goto done;
    }

    printf(TLS_CLIENT "enclave_identity_verifier returned success\n");
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
    unsigned char* der = NULL;
    unsigned char* buff = NULL;
    oe_result_t result = OE_FAILURE;
    X509* crt = NULL;
    int err = X509_V_ERR_UNSPECIFIED;

    printf(
        TLS_CLIENT "verify_callback called with preverify_ok=%d\n",
        preverify_ok);
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == NULL)
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
    der_len = i2d_X509(crt, NULL);
    buff = (unsigned char*)malloc(der_len);
    if (buff == NULL)
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
    result = oe_verify_attestation_certificate(
        der, der_len, enclave_identity_verifier, NULL);
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
            TLS_CLIENT "Verifying SGX certificate extensions ... %s\n",
            ret ? "succeeded" : "failed");
    }
    return ret;
}
