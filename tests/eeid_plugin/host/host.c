// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#if defined(_WIN32)
#include <ShlObj.h>
#include <Windows.h>
#endif

#include "../../../host/sgx/quote.h"
#include "../test_helpers.h"
#include "eeid_plugin_u.h"

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
#ifdef OE_LINK_SGX_DCAP_QL
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    // Skip test in simulation mode because of memory alignment issues, same as
    // tests/attestation_plugin).
    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
        return SKIP_RETURN_CODE;

    oe_enclave_setting_t setting;
    setting.setting_type = OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA;
    setting.u.eeid = mk_test_eeid();

    result = oe_create_eeid_plugin_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, &setting, 1, &enclave);
    OE_TEST(result == OE_OK);

    run_tests(enclave);

    free(setting.u.eeid);
    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    return 0;
#else
    // This test should not run on any platforms where HAS_QUOTE_PROVIDER is not
    // defined.
    OE_UNUSED(argc);
    OE_UNUSED(argv);
    printf("=== tests skipped when built with HAS_QUOTE_PROVIDER=OFF\n");
    return SKIP_RETURN_CODE;
#endif
}
