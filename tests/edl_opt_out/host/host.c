// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edl_opt_out_u.h"
#include "header_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_edl_opt_out_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = enc_edl_opt_out(enclave);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    /* logging.edl */
    OE_TEST(oe_log_init_ecall(NULL, NULL, 0) == OE_UNSUPPORTED);

#if __x86_64__ || _M_X64
#if defined(_WIN32)
    /*
     * On Windows, explicitly invoking the function so the attestation-related
     * ecalls are pulled in by the linker. On Linux, we currently do not build
     * the host with --gc-sections so this is not needed.
     */
    oe_verify_report(enclave, NULL, 0, NULL);
#endif

    /* attestation.edl */
    result = OE_OK;
    OE_TEST(oe_verify_report_ecall(NULL, &result, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(result == OE_UNSUPPORTED);

    /* sgx/attestation.edl */
    result = OE_OK;
    OE_TEST(
        oe_get_report_v2_ecall(NULL, &result, 0, NULL, 0, NULL, NULL) ==
        OE_UNSUPPORTED);
    OE_TEST(result == OE_UNSUPPORTED);
    result = OE_OK;
    OE_TEST(
        oe_verify_local_report_ecall(NULL, &result, NULL, 0, NULL) ==
        OE_UNSUPPORTED);
    OE_TEST(result == OE_UNSUPPORTED);

    /* sgx/switchless.edl */
    result = OE_OK;
    OE_TEST(
        oe_sgx_init_context_switchless_ecall(NULL, &result, NULL, 0) ==
        OE_UNSUPPORTED);
    OE_TEST(result == OE_UNSUPPORTED);
    OE_TEST(
        oe_sgx_switchless_enclave_worker_thread_ecall(NULL, NULL) ==
        OE_UNSUPPORTED);
#endif

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (edl_opt_out)\n");

    return 0;
}
