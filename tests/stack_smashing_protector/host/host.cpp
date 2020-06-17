// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "ssp_u.h"

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_ssp_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (OE_OK != result)
    {
        oe_put_err("oe_create_ocall_enclave(): result=%u", result);
    }

    /* Call enc_set_thread_variable */
    {
        int ret_val = -1;
        result =
            enc_set_thread_variable(enclave, &ret_val, _strdup("TSD-DATA"));
        OE_TEST(OE_OK == result);
        OE_TEST(0 == ret_val);
    }

    /* Call was_destructor_called */
    {
        bool ret_destroyed = false;
        result = was_destructor_called(enclave, &ret_destroyed);
        OE_TEST(OE_OK == result);
        OE_TEST(ret_destroyed);
    }

    /* Call enc_get_thread_specific_data */
    {
        void* ret_value = NULL;
        result = enc_get_thread_specific_data(enclave, &ret_value);
        OE_TEST(OE_OK == result);
        OE_TEST(NULL == ret_value);
    }

    /* Call ssp_test */
    {
        void* ret_value = NULL;
        result = ssp_test(enclave, &ret_value);
        OE_TEST(OE_ENCLAVE_ABORTING == result);
        OE_TEST(NULL == ret_value);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
