// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <ctime>
#include <vector>
#include "../../../common/sgx/tcbinfo.h"
#include "../../../host/sgx/quote.h"
#include "tests_u.h"

#define SKIP_RETURN_CODE 2

extern void run_parse_advisoryids_json_test();
extern void run_qe_identity_test_cases(oe_enclave_t* enclave);
extern void run_qe_identity_v2_test_cases(oe_enclave_t* enclave);
extern std::vector<uint8_t> FileToBytes(const char* path);

int main(int argc, const char* argv[])
{
    // sgx_target_info_t target_info;
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    /* Create the enclave */
    if ((result = oe_create_tests_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

#ifdef OE_HAS_SGX_DCAP_QL

    run_parse_advisoryids_json_test();
    run_qe_identity_test_cases(enclave);
    run_qe_identity_v2_test_cases(enclave);

#endif

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
