// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "ocall_u.h"

uint64_t host_my_ocall(uint64_t val)
{
    return val * MY_OCALL_MULTIPLIER;
}

static bool g_func2_ok = false;

void host_func2(const unsigned char*)
{
    g_func2_ok = true;
}

static oe_enclave_t* g_enclave = NULL;
static bool g_reentrancy_tested = false;
void host_test_reentrancy()
{
    oe_result_t result = enc_test_reentrancy(g_enclave);
    printf("result ==== %s\n", oe_result_str(result));
    OE_TEST(result == OE_REENTRANT_ECALL);
    g_reentrancy_tested = true;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_ocall_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (OE_OK != result)
    {
        oe_put_err("oe_create_ocall_enclave(): result=%u", result);
    }

    /* Call enc_test2 */
    {
        const uint64_t TEST2_VAL = 123456789;
        uint64_t ret_val = 0;
        result = enc_test2(enclave, &ret_val, TEST2_VAL);
        OE_TEST(OE_OK == result);
        OE_TEST(TEST2_VAL == ret_val);
    }

    /* Call enc_test4 */
    {
        result = enc_test4(enclave);
        OE_TEST(OE_OK == result);
        OE_TEST(g_func2_ok);
    }

    /* Call was_destructor_called */
    {
        bool ret_destroyed = true;
        result = was_destructor_called(enclave, &ret_destroyed);
        OE_TEST(OE_OK == result);
        OE_TEST(false == ret_destroyed);
    }

    /* Call enc_set_tsd */
    {
        int ret_val = -1;
        result = enc_set_tsd(enclave, &ret_val, _strdup("TSD-DATA"));
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

    /* Call enc_get_tsd */
    {
        void* ret_value = NULL;
        result = enc_get_tsd(enclave, &ret_value);
        OE_TEST(OE_OK == result);
        /*returning from enc_set_tsd() cleared this TSD slot */
        OE_TEST(NULL == ret_value);
    }

    /* Call enc_test_my_ocall */
    {
        uint64_t ret_val = 0;
        result = enc_test_my_ocall(enclave, &ret_val);
        OE_TEST(OE_OK == result);
        OE_TEST(MY_OCALL_SEED * MY_OCALL_MULTIPLIER == ret_val);
    }

    /* Call enc_test_reentrancy */
    {
        g_enclave = enclave;
        result = enc_test_reentrancy(enclave);

        OE_TEST(OE_OK == result);
        OE_TEST(g_reentrancy_tested);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
