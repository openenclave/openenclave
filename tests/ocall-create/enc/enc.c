// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/tests.h>
#include "ocall_create_t.h"

int enc_double(int val)
{
    oe_host_printf("==== enc_double\n");
    return val * 2;
}

int enc_double_ocall(int val)
{
    oe_host_printf("==== enc_double_ocall\n");
    int rval = 0;
    OE_TEST(OE_OK == host_double(&rval, val));
    return rval;
}

oe_result_t enc_create_enclave(
    char const* path,
    oe_enclave_type_t type,
    uint32_t flags,
    oe_enclave_t** enclave_out)
{
    oe_host_printf("==== enc_create_enclave\n");
    oe_result_t ret_result = OE_OK;
    oe_result_t result =
        host_create_enclave(&ret_result, path, type, flags, enclave_out);
    return (OE_OK == result) ? ret_result : result;
}

static oe_enclave_t* _create_enclave(const char* path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t ret_result = 1;
    oe_result_t result = host_create_enclave(
        &ret_result, path, OE_ENCLAVE_TYPE_SGX, flags, &enclave);
    OE_TEST(OE_OK == result);
    OE_TEST(OE_OK == ret_result);
    OE_TEST(NULL != enclave);
    return enclave;
}

int enc_test_ocall_enclave(const char* path, uint32_t flags)
{
    oe_host_printf("==== enc_test_ocall_enclave\n");

    int seed = 123;

    /* Create Enclave via OCALL. */
    oe_enclave_t* enclave = _create_enclave(path, flags);
    OE_TEST(enclave != NULL);

    /* Test ECALL on this enclave. */
    oe_result_t ret_result;
    int ret_val = 0;
    oe_result_t result =
        host_call_enc_double(&ret_result, enclave, &ret_val, seed);
    seed *= 2;

    OE_TEST(OE_OK == result);
    OE_TEST(OE_OK == ret_result);
    OE_TEST(seed == ret_val);

    /* Test OCALL on this enclave. */
    ret_val = 0;
    result = host_call_enc_double_ocall(&ret_result, enclave, &ret_val, seed);
    seed *= 2;

    OE_TEST(OE_OK == result);
    OE_TEST(OE_OK == ret_result);
    OE_TEST(seed == ret_val);

    /* Test terminating the enclave. */
    result = host_terminate_enclave(&ret_result, enclave);
    OE_TEST(OE_OK == result);
    OE_TEST(OE_OK == ret_result);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    256,  /* NumHeapPages */
    128,  /* NumStackPages */
    2);   /* NumTCS */
