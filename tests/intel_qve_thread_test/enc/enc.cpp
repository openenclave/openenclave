// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/tdx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/internal/raise.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "intel_qve_thread_test_t.h"

oe_result_t init_tdx_verifier()
{
    oe_verifier_initialize();
    oe_tdx_verifier_initialize();

    return OE_OK;
}

oe_result_t shutdown_tdx_verifier()
{
    oe_verifier_shutdown();
    oe_tdx_verifier_shutdown();

    return OE_OK;
}

static oe_result_t call_oe_verify_evidence(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size)
{
    oe_result_t result = OE_UNEXPECTED;

    OE_CHECK_MSG(
        oe_verify_evidence(
            format_id,
            evidence,
            evidence_size,
            nullptr,
            0,
            nullptr,
            0,
            nullptr,
            0),
        "Failed to verify evidence. result=%u (%s)\n",
        result,
        oe_result_str(result));

    result = OE_OK;

done:

    return result;
}

/**
 * This is the entry point for enclave code
 * It counts the number of oe_verify_evidence called, within a
 * given duration
 *
 * @param[in] duration: In seconds, the amount of time this thread should run
 * before exit
 * @param[out] count: Number of oe_verify_evidence called
 */
oe_result_t run_enclave_thread(
    const oe_uuid_t* format_id,
    uint8_t* evidence,
    size_t evidence_size,
    double duration,
    int* count)
{
    oe_result_t result = OE_UNEXPECTED;
    int count_local = 0;

    time_t start, now;
    time(&start);
    time(&now);

    while (difftime(now, start) < duration)
    {
        OE_CHECK(call_oe_verify_evidence(format_id, evidence, evidence_size));
        count_local += 1;
        time(&now);
    }

    result = OE_OK;

    if (count != NULL)
    {
        *count = count_local;
    }
done:
    return result;
}
