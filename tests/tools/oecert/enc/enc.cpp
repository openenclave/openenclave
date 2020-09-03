// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oecert_t.h"

// This is the identity validation callback. A TLS connecting party (client or
// server) can verify the passed in identity information to decide whether to
// accept a connection request
oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg)
{
    oe_result_t result = OE_VERIFY_FAILED;

    (void)arg;
    OE_TRACE_INFO("enclave_identity_verifier is called with parsed report:\n");

    // Check the enclave's security version
    if (identity->security_version < 1)
    {
        OE_TRACE_ERROR(
            "identity->security_version checking failed (%d)\n",
            identity->security_version);
        goto done;
    }

    // Dump an enclave's unique ID, signer ID and Product ID. They are
    // MRENCLAVE, MRSIGNER and ISVPRODID for SGX enclaves. In a real scenario,
    // custom id checking should be done here

    OE_TRACE_INFO("identity->signer_id :\n");
    for (int i = 0; i < OE_UNIQUE_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nparsed_report->identity.signer_id :\n");
    for (int i = 0; i < OE_SIGNER_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->signer_id[i]);

    OE_TRACE_INFO("\nidentity->product_id :\n");
    for (int i = 0; i < OE_PRODUCT_ID_SIZE; i++)
        OE_TRACE_INFO("0x%0x ", (uint8_t)identity->product_id[i]);

    result = OE_OK;
done:
    return result;
}

oe_result_t get_tls_cert_signed_with_key(
    uint8_t* private_key,
    size_t private_key_size,
    uint8_t* public_key,
    size_t public_key_size,
    unsigned char** cert,
    size_t* cert_size)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* host_cert_buf = NULL;

    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;

    OE_TRACE_INFO("called into enclave\n");
    OE_TRACE_INFO("private key:[%s]\n", private_key);
    OE_TRACE_INFO("public key:[%s]\n", public_key);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key,
        private_key_size,
        public_key,
        public_key_size,
        &output_cert,
        &output_cert_size);
    if (result != OE_OK)
    {
        OE_TRACE_ERROR(" failed with %s\n", oe_result_str(result));
        goto done;
    }

    OE_TRACE_INFO("output_cert_size = 0x%x", output_cert_size);
    // validate cert inside the enclave
    result = oe_verify_attestation_certificate(
        output_cert, output_cert_size, enclave_identity_verifier, NULL);
    OE_TRACE_INFO(
        "\nFrom inside enclave: verifying the certificate... %s\n",
        result == OE_OK ? "Success" : "Fail");

    // copy cert to host memory
    host_cert_buf = (uint8_t*)oe_host_malloc(output_cert_size);
    if (host_cert_buf == NULL)
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    // copy to the host for host-side validation test
    memcpy(host_cert_buf, output_cert, output_cert_size);
    *cert_size = output_cert_size;
    *cert = host_cert_buf;
    OE_TRACE_INFO("*cert = %p", *cert);
    OE_TRACE_INFO("*cert_size = 0x%x", *cert_size);

done:

    oe_free_attestation_certificate(output_cert);

    return result;
}

oe_result_t get_plugin_evidence(
    uint8_t* evidence,
    size_t evidence_size,
    size_t* evidence_out_size,
    uint8_t* endorsements,
    size_t endorsements_size,
    size_t* endorsements_out_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* local_evidence = NULL;
    size_t local_evidence_size = 0;
    uint8_t* local_endorsements = NULL;
    size_t local_endorsements_size = 0;

    static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

    OE_CHECK(oe_attester_initialize());

    OE_CHECK(oe_get_evidence(
        &_ecdsa_uuid,
        OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
        NULL,
        0,
        NULL,
        0,
        &local_evidence,
        &local_evidence_size,
        &local_endorsements,
        &local_endorsements_size));

    if (local_evidence_size > evidence_size ||
        local_endorsements_size > endorsements_size)
        return OE_BUFFER_TOO_SMALL;

    *evidence_out_size = local_evidence_size;
    *endorsements_out_size = local_endorsements_size;

    memcpy(evidence, local_evidence, local_evidence_size);
    memcpy(endorsements, local_endorsements, local_endorsements_size);

    OE_CHECK(oe_attester_shutdown());

    result = OE_OK;

done:

    return result;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    128,  /* NumHeapPages */
    128,  /* NumStackPages */
    1);   /* NumTCS */
