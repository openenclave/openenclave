// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include <string.h>

#include <openenclave/bits/report.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>

#include "../../host/sgx/sgxmeasure.h"

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include "verify_eeid.h"

oe_result_t verify_eeid(
    const uint8_t* report,
    size_t report_size,
    oe_report_t* parsed_report,
    const oe_eeid_t* eeid)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!eeid)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Recompute extended mrenclave
    oe_sha256_context_t hctx;
    oe_sha256_restore(&hctx, eeid->hash_state_H, eeid->hash_state_N);

    size_t eeid_sz =
        oe_round_up_to_page_size(sizeof(oe_eeid_t) + eeid->data_size);
    size_t num_pages = eeid_sz / OE_PAGE_SIZE;
    oe_page_t* pages = (oe_page_t*)eeid;
    uint64_t enclave_base = 0x0ab0c0d0e0f;
    uint64_t addr = enclave_base + eeid->data_vaddr;

    for (size_t i = 0; i < num_pages; i++)
    {
        OE_CHECK(oe_sgx_measure_load_enclave_data(
            &hctx,
            (uint64_t)enclave_base,
            addr,
            (uint64_t)&pages[i],
            SGX_SECINFO_REG | SGX_SECINFO_R,
            true));

        addr += sizeof(oe_page_t);
    }

    OE_SHA256 cpt_mrenclave;
    oe_sha256_final(&hctx, &cpt_mrenclave);

    // Extract reported mrenclave
    oe_report_t* treport = parsed_report;
    OE_SHA256 reported_mrenclave;
    uint8_t reported_mrsigner[OE_SIGNER_ID_SIZE];

    if (parsed_report == NULL)
    {
        treport = calloc(1, sizeof(oe_report_t));
        OE_CHECK(oe_parse_report(report, report_size, treport));
    }

    memcpy(reported_mrenclave.buf, treport->identity.unique_id, OE_SHA256_SIZE);
    memcpy(reported_mrsigner, treport->identity.signer_id, OE_SIGNER_ID_SIZE);

    if (parsed_report == NULL)
        free(treport);

    // char str[OE_SHA256_SIZE * 2 + 1];
    // oe_hex_string(str, OE_SHA256_SIZE * 2 + 1, cpt_mrenclave.buf,
    // OE_SHA256_SIZE); OE_TRACE_INFO("*** CPT: %s\n", str); oe_hex_string(str,
    // OE_SHA256_SIZE * 2 + 1, reported_mrenclave.buf, OE_SHA256_SIZE);
    // OE_TRACE_INFO("*** REP: %s\n", str);

    // Check recomputed mrenclave against reported mrenclave
    if (memcmp(cpt_mrenclave.buf, reported_mrenclave.buf, OE_SHA256_SIZE) != 0)
        OE_RAISE(OE_VERIFY_FAILED);

    static const uint8_t debug_public_key[] = {
        0xca, 0x9a, 0xd7, 0x33, 0x14, 0x48, 0x98, 0x0a, 0xa2, 0x88, 0x90,
        0xce, 0x73, 0xe4, 0x33, 0x63, 0x83, 0x77, 0xf1, 0x79, 0xab, 0x44,
        0x56, 0xb2, 0xfe, 0x23, 0x71, 0x93, 0x19, 0x3a, 0x8d, 0xa};

    if (memcmp(debug_public_key, reported_mrsigner, OE_SIGNER_ID_SIZE) != 0)
        OE_RAISE(OE_VERIFY_FAILED);

    // Check old signature (new signature has been checked above)
    const sgx_sigstruct_t* ss = (const sgx_sigstruct_t*)&eeid->sigstruct;

    uint8_t zero[OE_KEY_SIZE];
    memset(zero, 0, OE_KEY_SIZE);

    if (memcmp(ss->signature, zero, OE_KEY_SIZE) == 0) // Unsigned image is ok?
        return OE_OK;
    else
    {
        // TODO: Need to find mrsigner of old image somehow in order to check
        // the signature.
        OE_RAISE(OE_VERIFY_FAILED);
    }

done:

    return result;
}
