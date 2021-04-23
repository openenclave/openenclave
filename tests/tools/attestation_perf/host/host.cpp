// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__linux__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include "attestation_perf_u.h"

int local_cache_clear();

long get_tick()
{
    return clock() * 1000 / CLOCKS_PER_SEC;
}

int main(int argc, const char* argv[])
{
    int ret = 0;
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave = nullptr;
    const char* enclave_filename = argv[1];
    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;
    uint8_t evidence[8096] = {};
    size_t evidence_size = 0;
    long tick = 0;

    if (argc != 2)
    {
        fprintf(
            stderr, "Invalid parameter.\nSyntax: %s <enclave_file>\n", argv[0]);
        return -1;
    }

    // Clear local cache
    ret = local_cache_clear();
    if (ret != 0)
    {
        fprintf(stderr, "Failed to clear local collateral cache\n");
        return -2;
    }

    OE_CHECK_MSG(
        oe_create_attestation_perf_enclave(
            enclave_filename,
            OE_ENCLAVE_TYPE_AUTO,
            OE_ENCLAVE_FLAG_DEBUG,
            nullptr,
            0,
            &enclave),
        "Failed to create enclave. result=%u (%s)\n",
        oe_result_str(result));

    // Verify evidence with no collateral cache
    tick = get_tick();
    OE_CHECK_MSG(
        get_evidence(enclave, &result, nullptr, 0, nullptr, true),
        "Failed to create OE evidence. Error: %s\n",
        oe_result_str(result));
    printf(
        "1. Verifying evidence with no collateral cache (%ld msec)\n",
        get_tick() - tick);

    // Verifying evidence with collateral cache
    tick = get_tick();
    OE_CHECK_MSG(
        get_evidence(enclave, &result, nullptr, 0, nullptr, true),
        "Failed to create OE evidence. Error: %s\n",
        oe_result_str(result));
    printf(
        "2. Verifying evidence with collateral cache (%ld msec)\n",
        get_tick() - tick);

    // Generating evidence without verifying
    tick = get_tick();
    OE_CHECK_MSG(
        get_evidence(
            enclave,
            &result,
            evidence,
            sizeof(evidence),
            &evidence_size,
            false),
        "Failed to create OE evidence. Error: %s\n",
        oe_result_str(result));
    printf(
        "3. Generating evidence without verifying (%ld msec)\n",
        get_tick() - tick);

    // Verifying evidence in host
    OE_CHECK(oe_verifier_initialize());
    tick = get_tick();
    OE_CHECK_MSG(
        oe_verify_evidence(
            nullptr,
            evidence,
            evidence_size,
            nullptr,
            0,
            nullptr,
            0,
            &claims,
            &claims_length),
        "Failed to verify evidence. Error: %s\n",
        oe_result_str(result));
    printf("4. Verifying evidence in host (%ld msec)\n", get_tick() - tick);

    oe_free_claims(claims, claims_length);
    OE_CHECK(oe_verifier_shutdown());

    result = OE_OK;

done:
    if (enclave)
        oe_terminate_enclave(enclave);

    return ret;
}
