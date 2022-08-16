// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/bits/report.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>

#include "dcap_quoteprov_log_t.h"

static const oe_uuid_t _ecdsa_uuid = {OE_FORMAT_UUID_SGX_ECDSA};

void generate_evidence()
{
    uint8_t* evidence = NULL;
    size_t evidence_size = 0;
    uint8_t* endorsements;
    size_t endorsements_size;
    oe_uuid_t selected_format;
    OE_TEST(oe_attester_initialize() == OE_OK);

    OE_TEST(
        oe_attester_select_format(&_ecdsa_uuid, 1, &selected_format) == OE_OK);

    OE_TEST(
        oe_get_evidence(
            &selected_format,
            OE_EVIDENCE_FLAGS_EMBED_FORMAT_ID,
            NULL,
            0,
            NULL,
            0,
            &evidence,
            &evidence_size,
            &endorsements,
            &endorsements_size) == OE_OK);

    OE_TEST(oe_free_evidence(evidence) == OE_OK);
    OE_TEST(oe_free_endorsements(endorsements) == OE_OK);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */

#define TA_UUID                                            \
    { /* c6d845e1-5fd6-4faf-9c73-d84e25d48fe0 */           \
        0xc6d845e1, 0x5fd6, 0x4faf,                        \
        {                                                  \
            0x9c, 0x73, 0xd8, 0x4e, 0x25, 0xd4, 0x8f, 0xe0 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "dcap_quoteprov_log test")
