// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/tests.h>
#include "backtrace_u.h"
#include "openenclave/bits/result.h"

extern bool oe_sgx_is_vdso_enabled;

#ifdef _WIN32
static int _is_on_windows = 1;
#else
static int _is_on_windows = 0;
#endif

#define TEST_BASE 0
#define TEST_SEGFAULT 1
#define TEST_ABORT_AFTER_SEGFAULT 2
#define TEST_SEGFAULT_NO_PFGP 3

#define SKIP_RETURN_CODE 2

const char* arg0;

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();
    int test = TEST_BASE;
    int is_misc_region_supported = oe_sgx_is_misc_region_supported();

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    test = atoi(argv[2]);

    r = oe_create_backtrace_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) && (test != TEST_BASE))
    {
        printf("Skip the test in the simulation mode\n");
        return SKIP_RETURN_CODE;
    }

    if (test == TEST_BASE)
        OE_TEST(enc_test(enclave) == OE_ENCLAVE_ABORTING);
    else if (test == TEST_SEGFAULT)
    {
        if (_is_on_windows && !is_misc_region_supported)
        {
            /* On Windows, we do not support #PF simulation
             * in debug mode for CFL machines. Skip the test. */
            return SKIP_RETURN_CODE;
        }

        OE_TEST(enc_test_segfault(enclave) == OE_ENCLAVE_ABORTING);
    }
    else if (test == TEST_ABORT_AFTER_SEGFAULT)
    {
        if (_is_on_windows && !is_misc_region_supported)
        {
            /* On Windows, we do not support #PF simulation
             * in debug mode for CFL machines. Skip the test. */
            return SKIP_RETURN_CODE;
        }

        OE_TEST(enc_test_abort_after_segfault(enclave) == OE_ENCLAVE_ABORTING);
    }
    else if (test == TEST_SEGFAULT_NO_PFGP)
    {
        if (!oe_sgx_is_vdso_enabled)
        {
            /* If the vdso is not enabled, the segfault will be
             * raised. Skip the test in such cases. */
            return SKIP_RETURN_CODE;
        }

        OE_TEST(enc_test_segfault(enclave) == OE_FAILURE);
    }

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
