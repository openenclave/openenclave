// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "ocall_create_u.h"

oe_result_t host_create_enclave(
    char const* path,
    oe_enclave_type_t type,
    uint32_t flags,
    oe_enclave_t** enclave_out)
{
    printf("==== host_create_enclave\n");
    return oe_create_ocall_create_enclave(
        path, type, flags, NULL, 0, enclave_out);
}

oe_result_t host_call_enc_double(oe_enclave_t* enclave, int* ret_val, int val)
{
    printf("==== host_call_enc_double\n");
    return enc_double(enclave, ret_val, val);
}

oe_result_t host_call_enc_double_ocall(
    oe_enclave_t* enclave,
    int* ret_val,
    int val)
{
    printf("==== host_call_enc_double_ocall\n");
    return enc_double_ocall(enclave, ret_val, val);
}

oe_result_t host_terminate_enclave(oe_enclave_t* enclave)
{
    printf("==== host_terminate_enclave\n");
    return oe_terminate_enclave(enclave);
}

int host_double(int val)
{
    printf("==== host_double\n");
    return val * 2;
}

static void _test_ecall_ocall(oe_enclave_t* enclave)
{
    int seed = 512;
    int ret_val = 0;
    oe_result_t result = enc_double(enclave, &ret_val, seed);
    seed *= 2;
    if (OE_OK != result)
    {
        oe_put_err("enc_double: result=%u", result);
    }
    OE_TEST(ret_val == seed);

    ret_val = 0;
    result = enc_double_ocall(enclave, &ret_val, seed);
    seed *= 2;
    if (OE_OK != result)
    {
        oe_put_err("enc_double_ocall: result=%u", result);
    }
    OE_TEST(ret_val == seed);
}

static void _test_create_enclave_ocall_for_host(
    const char* path,
    uint32_t flags)
{
    printf("\n_test_create_enclave_ocall_for_host\n");

    oe_enclave_t* enclave = NULL;
    oe_result_t result = oe_create_ocall_create_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        oe_put_err("oe_create_ocall_create_enclave(): result=%u", result);
    }

    /* Create enclave via OCALL. */
    oe_result_t ret_result;
    oe_enclave_t* ret_enclave = NULL;
    result = enc_create_enclave(
        enclave, &ret_result, path, OE_ENCLAVE_TYPE_SGX, flags, &ret_enclave);

    if (OE_OK != result)
    {
        oe_put_err("enc_create_enclave(): result=%u", result);
    }

    if (OE_OK != ret_result)
    {
        oe_put_err("enc_create_enclave(): ret_result=%u", ret_result);
    }

    OE_TEST(ret_enclave != NULL);

    /* Test if basic ECALLs and OCALLs work for the new enclave. */
    _test_ecall_ocall(ret_enclave);

    /* Test if the old enclave still works. */
    _test_ecall_ocall(enclave);

    /* Terminate the enclave. */
    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    result = oe_terminate_enclave(ret_enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }
}

static void _test_create_enclave_ocall_for_enclave(
    const char* path,
    uint32_t flags)
{
    printf("\n_test_create_enclave_ocall_for_enclave\n");

    oe_enclave_t* enclave;
    oe_result_t result = oe_create_ocall_create_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
    {
        oe_put_err("oe_create_ocall_create_enclave(): result=%u", result);
    }

    int ret_val = 1;
    result = enc_test_ocall_enclave(enclave, &ret_val, path, flags);
    if (result != OE_OK)
    {
        oe_put_err("enc_test_ocall_enclave(): result=%u", result);
    }

    if (0 != ret_val)
    {
        oe_put_err("enc_test_ocall_enclave ret_val=%u", ret_val);
    }

    result = oe_terminate_enclave(enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    /* Test if an enclave created via an OCALL can be used by the host. */
    _test_create_enclave_ocall_for_host(argv[1], flags);

    /* Test if an OCALL created enclave can be used by the enclave. */
    _test_create_enclave_ocall_for_enclave(argv[1], flags);

    return 0;
}
